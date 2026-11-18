/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.mls.group

import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentData
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Extension
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The policy hooks that see what a commit produces and who signed a Welcome,
 * and the rule that a leaf's application data the engine does not know is
 * carried, never judged.
 */
class ApplicationRuleHooksTest {
    private fun keyPackage(
        name: String,
        leafExtensions: List<Extension> = emptyList(),
        capabilities: Capabilities = Capabilities(),
        keyPackageExtensions: List<Extension> = emptyList(),
    ): KeyPackageBundle =
        MlsGroup.createKeyPackage(
            identity = name.encodeToByteArray(),
            leafExtensions = leafExtensions,
            capabilities = capabilities,
            keyPackageExtensions = keyPackageExtensions,
        )

    /** Refuses any resulting state with more than [max] occupied leaves. */
    private class LeafCap(
        val max: Int,
    ) : MlsGroupPolicy {
        override fun validateResultingState(
            parentExtensions: List<Extension>,
            proposals: List<PendingProposal>,
            resulting: GroupView,
        ) {
            val occupied = (0 until resulting.leafCount).count { resulting.leafNode(it) != null }
            check(occupied <= max) { "$occupied leaves, at most $max" }
        }
    }

    @Test
    fun anInboundCommitWhoseResultBreaksARuleIsRefusedAndChangesNothing() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = keyPackage("bob")
        val bob = MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b, policy = LeafCap(2))

        val addCarol = alice.addMember(keyPackage("carol").keyPackage.toTlsBytes())
        assertFailsWith<IllegalStateException> { bob.processFramedCommit(addCarol.framedCommitBytes) }
        assertEquals(1L, bob.epoch)
        assertEquals(2, bob.memberCount)
    }

    @Test
    fun aLocalCommitWhoseResultBreaksARuleIsNeverBuilt() {
        val alice = MlsGroup.create("alice".encodeToByteArray(), policy = LeafCap(2))
        alice.addMember(keyPackage("bob").keyPackage.toTlsBytes())
        assertFailsWith<IllegalStateException> { alice.addMember(keyPackage("carol").keyPackage.toTlsBytes()) }
        assertEquals(1L, alice.epoch)
        assertEquals(2, alice.memberCount)
    }

    @Test
    fun theResultingStateHookSeesBothSidesOfTheCommit() {
        var parent: List<Extension>? = null
        var leaves = -1
        var proposalCount = -1
        val watching =
            object : MlsGroupPolicy {
                override fun validateResultingState(
                    parentExtensions: List<Extension>,
                    proposals: List<PendingProposal>,
                    resulting: GroupView,
                ) {
                    parent = parentExtensions
                    leaves = (0 until resulting.leafCount).count { resulting.leafNode(it) != null }
                    proposalCount = proposals.size
                }
            }
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = keyPackage("bob")
        val bob = MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b, policy = watching)
        val before = bob.extensions

        bob.processFramedCommit(alice.addMember(keyPackage("carol").keyPackage.toTlsBytes()).framedCommitBytes)
        assertEquals(before, parent)
        assertEquals(3, leaves)
        assertEquals(1, proposalCount)
    }

    @Test
    fun validateJoinSeesWhoSignedTheGroupInfo() {
        var signer = -1
        var identity: String? = null
        val watching =
            object : MlsGroupPolicy {
                override fun validateJoin(
                    group: GroupView,
                    groupInfoSigner: Int,
                    groupInfoExtensions: List<Extension>,
                ) {
                    signer = groupInfoSigner
                    identity = group.memberIdentityHex(groupInfoSigner)
                }
            }
        val alice = MlsGroup.create("alice".encodeToByteArray())
        alice.addMember(keyPackage("bob").keyPackage.toTlsBytes())
        val c = keyPackage("carol")
        MlsGroup.processWelcome(alice.addMember(c.keyPackage.toTlsBytes()).welcomeBytes!!, c, policy = watching)
        assertEquals(0, signer)
        assertEquals("alice".encodeToByteArray().toHex(), identity)
    }

    @Test
    fun theOlderValidateJoinStillRunsByDefault() {
        val refusing =
            object : MlsGroupPolicy {
                override fun validateJoin(group: GroupView): Unit = throw IllegalStateException("no")
            }
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = keyPackage("bob")
        val welcome = alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!
        assertFailsWith<IllegalStateException> { MlsGroup.processWelcome(welcome, b, policy = refusing) }
    }

    /**
     * A leaf, and a KeyPackage, may carry dictionary entries for components
     * nobody in the group knows — Marmot's `0x800f` device tag is one that
     * linked devices put in every leaf. The engine carries them: an Add, a
     * join and later commits all go through.
     */
    @Test
    fun unknownDictionaryEntriesInALeafAndAKeyPackageAreCarriedNotJudged() {
        val deviceTag = 0x800f
        val caps = Capabilities(extensions = listOf(AppDataDictionary.EXTENSION_TYPE))
        val leafDictionary =
            AppDataDictionary(
                listOf(
                    ComponentData(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(listOf(ComponentsList.APP_COMPONENTS_ID))),
                    ComponentData(deviceTag, byteArrayOf(1, 2, 3, 4)),
                ),
            ).toExtension()
        val keyPackageDictionary = AppDataDictionary(listOf(ComponentData(deviceTag, byteArrayOf(9)))).toExtension()

        val alice = MlsGroup.create("alice".encodeToByteArray(), capabilities = caps)
        val b = keyPackage("bob", listOf(leafDictionary), caps, listOf(keyPackageDictionary))
        val bob = MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b)

        // Bob's leaf kept its entry, as alice and bob both see it.
        listOf(alice, bob).forEach { member ->
            val leaf = assertNotNull(member.view().leafNode(1))
            assertTrue(AppDataDictionary.fromExtensionsOrEmpty(leaf.extensions).contains(deviceTag))
        }

        // Bob commits with it, and a third member joins a tree that holds it.
        alice.processFramedCommit(bob.commit().framedCommitBytes)
        val c = keyPackage("carol", listOf(leafDictionary), caps)
        val add = alice.addMember(c.keyPackage.toTlsBytes())
        bob.processFramedCommit(add.framedCommitBytes)
        val carol = MlsGroup.processWelcome(add.welcomeBytes!!, c)
        assertEquals(3L, carol.epoch)
        assertEquals("ok", bob.decrypt(carol.encrypt("ok".encodeToByteArray())).content.decodeToString())
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
