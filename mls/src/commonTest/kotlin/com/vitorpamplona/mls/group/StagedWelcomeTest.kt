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

import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.tree.Credential
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/** [MlsGroup.stageWelcome]: look at a group before joining it. */
class StagedWelcomeTest {
    private fun bundle(name: String) = MlsGroup.create(name.encodeToByteArray()).createKeyPackage(name.encodeToByteArray(), ByteArray(0))

    private fun identities(members: List<Pair<Int, com.vitorpamplona.mls.tree.LeafNode>>) = members.map { (it.second.credential as Credential.Basic).identity.decodeToString() }

    @Test
    fun aStagedWelcomeShowsTheGroupThenJoinsIt() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val bob = bundle("bob")
        val carol = bundle("carol")
        val add = alice.addMembers(listOf(bob.keyPackage.toTlsBytes(), carol.keyPackage.toTlsBytes()))

        val staged = MlsGroup.stageWelcome(add.welcomeBytes!!, carol)
        assertContentEquals(alice.groupId, staged.groupId)
        assertEquals(alice.epoch, staged.epoch)
        assertEquals(listOf("alice", "bob", "carol"), identities(staged.members()))
        assertEquals(0, staged.welcomerLeafIndex)
        assertEquals("alice", (staged.welcomer.credential as Credential.Basic).identity.decodeToString())
        assertEquals(2, staged.leafIndex)
        assertEquals(alice.extensions, staged.extensions)
        assertEquals(emptyList(), staged.psks)

        val group = staged.join()
        assertContentEquals(alice.epochAuthenticator, group.epochAuthenticator)
        assertEquals("hi carol", group.decrypt(alice.encrypt("hi carol".encodeToByteArray())).content.decodeToString())
        assertFailsWith<IllegalStateException> { staged.join() }
    }

    @Test
    fun stagingRunsEveryCheckJoiningDoes() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val bob = bundle("bob")
        val add = alice.addMember(bob.keyPackage.toTlsBytes())
        assertFailsWith<IllegalArgumentException>("someone else's bundle") { MlsGroup.stageWelcome(add.welcomeBytes!!, bundle("mallory")) }

        val refuse =
            object : MlsGroupPolicy {
                override fun validateJoin(group: GroupView) = throw IllegalStateException("not this group")
            }
        assertFailsWith<IllegalStateException> { MlsGroup.stageWelcome(add.welcomeBytes!!, bob, refuse) }
    }

    @Test
    fun aStagedWelcomeNamesItsPsks() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val id = "shared".encodeToByteArray()
        val psk = ByteArray(32) { 7 }
        alice.registerPsk(id, psk)
        val bob = bundle("bob")
        alice.proposePsk(id)
        alice.proposeAdd(bob.keyPackage.toTlsBytes())
        val commit = alice.commit()

        val staged = MlsGroup.stageWelcome(commit.welcomeBytes!!, bob, psks = { if (it is PreSharedKeyId.External && it.pskId.contentEquals(id)) psk else null })
        val named = assertIs<PreSharedKeyId.External>(staged.psks.single())
        assertContentEquals(id, named.pskId)
        assertContentEquals(alice.epochAuthenticator, staged.join().epochAuthenticator)
    }
}
