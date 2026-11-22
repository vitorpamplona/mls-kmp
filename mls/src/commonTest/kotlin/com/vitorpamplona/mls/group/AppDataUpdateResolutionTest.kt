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
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Extension
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * [MlsGroupPolicy.resolveAppDataUpdate]: an AppDataUpdate's payload means what its component says
 * it means (draft-ietf-mls-extensions; OpenMLS hands such commits back as `UnresolvedAppDataCommit`
 * for the application to resolve against the parent's bytes). The default keeps the payload as the
 * new value; a binding with a diff component resolves it, on the committer and every receiver alike.
 */
class AppDataUpdateResolutionTest {
    private val component = 0x8abc
    private val caps = Capabilities(extensions = listOf(AppDataDictionary.EXTENSION_TYPE), proposals = listOf(MlsGroup.APP_DATA_UPDATE_PROPOSAL_TYPE))

    /** A component whose update is appended to the parent's value: a stand-in for a diff format. */
    private object Appending : MlsGroupPolicy {
        override fun resolveAppDataUpdate(
            parentExtensions: List<Extension>,
            componentId: Int,
            parentData: ByteArray?,
            update: ByteArray,
        ): ByteArray = if (componentId == 0x8abc) (parentData ?: ByteArray(0)) + update else update
    }

    /** Refuses every update of the component, as a binding refuses an update its diff cannot apply to. */
    private object Refusing : MlsGroupPolicy {
        override fun resolveAppDataUpdate(
            parentExtensions: List<Extension>,
            componentId: Int,
            parentData: ByteArray?,
            update: ByteArray,
        ): ByteArray = throw IllegalArgumentException("cannot apply")
    }

    private fun keyPackage(name: String): KeyPackageBundle = MlsGroup.createKeyPackage(identity = name.encodeToByteArray(), capabilities = caps)

    private fun pair(
        alicePolicy: MlsGroupPolicy,
        bobPolicy: MlsGroupPolicy,
    ): Pair<MlsGroup, MlsGroup> {
        val alice = MlsGroup.create("alice".encodeToByteArray(), capabilities = caps, policy = alicePolicy)
        val b = keyPackage("bob")
        val bob = MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b, policy = bobPolicy)
        return alice to bob
    }

    @Test
    fun theDefaultKeepsThePayloadAsTheNewValue() {
        val (alice, bob) = pair(MlsGroupPolicy.Permissive, MlsGroupPolicy.Permissive)
        alice.proposeAppDataUpdate(component, byteArrayOf(1, 2))
        bob.processFramedCommit(alice.commit().framedCommitBytes)
        alice.proposeAppDataUpdate(component, byteArrayOf(3))
        bob.processFramedCommit(alice.commit().framedCommitBytes)
        for (m in listOf(alice, bob)) assertContentEquals(byteArrayOf(3), m.appDataDictionary()[component])
        assertEquals("ok", bob.decrypt(alice.encrypt("ok".encodeToByteArray())).content.decodeToString())
    }

    @Test
    fun aResolvingPolicyAppliesTheUpdateToTheParentOnBothSides() {
        val (alice, bob) = pair(Appending, Appending)
        alice.proposeAppDataUpdate(component, byteArrayOf(1, 2))
        bob.processFramedCommit(alice.commit().framedCommitBytes)
        alice.proposeAppDataUpdate(component, byteArrayOf(3))
        bob.processFramedCommit(alice.commit().framedCommitBytes)
        for (m in listOf(alice, bob)) assertContentEquals(byteArrayOf(1, 2, 3), m.appDataDictionary()[component])
        // Same GroupContext, so the same key schedule: they still talk.
        assertEquals("ok", bob.decrypt(alice.encrypt("ok".encodeToByteArray())).content.decodeToString())
        assertEquals("back", alice.decrypt(bob.encrypt("back".encodeToByteArray())).content.decodeToString())
    }

    @Test
    fun membersThatResolveDifferentlyForkWhichIsWhyTheBindingMustAgree() {
        val (alice, bob) = pair(Appending, MlsGroupPolicy.Permissive)
        alice.proposeAppDataUpdate(component, byteArrayOf(1))
        bob.processFramedCommit(alice.commit().framedCommitBytes)
        alice.proposeAppDataUpdate(component, byteArrayOf(2))
        // Alice's GroupContext is [1, 2], bob's would be [2]: the confirmation tag does not verify.
        assertFailsWith<Exception> { bob.processFramedCommit(alice.commit().framedCommitBytes) }
    }

    @Test
    fun aPolicyThatThrowsRefusesTheCommitAndChangesNothing() {
        val (alice, bob) = pair(MlsGroupPolicy.Permissive, Refusing)
        val epoch = bob.epoch
        alice.proposeAppDataUpdate(component, byteArrayOf(1))
        assertFailsWith<IllegalArgumentException> { bob.processFramedCommit(alice.commit().framedCommitBytes) }
        assertEquals(epoch, bob.epoch)
        assertNull(bob.appDataDictionary()[component])

        // A committer whose own policy refuses never builds the commit.
        val (carol, _) = pair(Refusing, MlsGroupPolicy.Permissive)
        val before = carol.epoch
        carol.proposeAppDataUpdate(component, byteArrayOf(1))
        assertFailsWith<IllegalArgumentException> { carol.commit() }
        assertEquals(before, carol.epoch)
        assertNull(carol.appDataDictionary()[component])
    }

    @Test
    fun aRemovalNeverReachesTheResolver() {
        val (alice, bob) = pair(Appending, Refusing)
        alice.proposeAppDataRemoval(component)
        bob.processFramedCommit(alice.commit().framedCommitBytes)
        assertNull(bob.appDataDictionary()[component])
    }
}
