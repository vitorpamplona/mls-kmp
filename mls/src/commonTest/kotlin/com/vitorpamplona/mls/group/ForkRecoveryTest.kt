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

import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.LeafNode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** [MlsGroup.recoverForkByReadding] and [MlsGroup.reboot] on a group that really forked. */
class ForkRecoveryTest {
    private fun bundle(name: String) = MlsGroup.create(name.encodeToByteArray()).createKeyPackage(name.encodeToByteArray(), ByteArray(0))

    private fun names(members: List<Pair<Int, LeafNode>>) = members.map { (it.second.credential as Credential.Basic).identity.decodeToString() }

    private fun assertTalk(
        from: MlsGroup,
        to: MlsGroup,
    ) {
        val text = "from ${from.leafIndex} to ${to.leafIndex}"
        assertEquals(text, to.decrypt(from.encrypt(text.encodeToByteArray())).content.decodeToString())
    }

    private class Fork(
        val alice: MlsGroup,
        val bob: MlsGroup,
        val charlie: MlsGroup,
    )

    /**
     * alice adds bob; then alice and bob each commit an Add of charlie and
     * merge their own. Both reach epoch 2, with different keys. charlie
     * joined from alice's Welcome, so he is on alice's side.
     */
    private fun fork(): Fork {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val bobBundle = bundle("bob")
        val bob = MlsGroup.processWelcome(alice.addMember(bobBundle.keyPackage.toTlsBytes()).welcomeBytes!!, bobBundle)
        val charlieForAlice = bundle("charlie")
        val aliceAdd = alice.addMember(charlieForAlice.keyPackage.toTlsBytes())
        bob.addMember(bundle("charlie").keyPackage.toTlsBytes())
        val charlie = MlsGroup.processWelcome(aliceAdd.welcomeBytes!!, charlieForAlice)
        assertEquals(alice.epoch, bob.epoch)
        assertFalse(alice.epochAuthenticator.contentEquals(bob.epochAuthenticator), "the group forked")
        assertFails("bob cannot read alice's side any more") { bob.decrypt(alice.encrypt("lost".encodeToByteArray())) }
        return Fork(alice, bob, charlie)
    }

    @Test
    fun readdingTheOtherSideRepairsTheFork() {
        val f = fork()
        val complement = f.alice.forkComplement(listOf(f.alice.leafIndex, f.charlie.leafIndex))
        assertEquals(listOf("bob"), names(complement))

        val freshBob = bundle("bob")
        val commit = f.alice.recoverForkByReadding(listOf(f.alice.leafIndex, f.charlie.leafIndex), listOf(freshBob.keyPackage.toTlsBytes()))
        f.charlie.processMessage(commit.framedCommitBytes)
        val bob = MlsGroup.processWelcome(commit.welcomeBytes!!, freshBob)

        assertContentEquals(f.alice.epochAuthenticator, bob.epochAuthenticator)
        assertContentEquals(f.alice.epochAuthenticator, f.charlie.epochAuthenticator)
        assertEquals(listOf("alice", "bob", "charlie"), names(bob.members()))
        assertTalk(bob, f.alice)
        assertTalk(f.charlie, bob)
    }

    @Test
    fun rebootingStartsANewGroupWithEveryone() {
        val f = fork()
        assertEquals(listOf("bob", "charlie"), names(f.alice.rebootMembers()))
        val bob = bundle("bob")
        val charlie = bundle("charlie")
        val rebooted = f.alice.reboot(listOf(bob.keyPackage.toTlsBytes(), charlie.keyPackage.toTlsBytes()))

        val newBob = MlsGroup.processWelcome(rebooted.commit.welcomeBytes!!, bob)
        val newCharlie = MlsGroup.processWelcome(rebooted.commit.welcomeBytes!!, charlie)
        assertFalse(rebooted.group.groupId.contentEquals(f.alice.groupId), "a reboot is a new group")
        assertEquals(f.alice.extensions, rebooted.group.extensions)
        assertEquals(1L, rebooted.group.epoch)
        assertContentEquals(rebooted.group.epochAuthenticator, newBob.epochAuthenticator)
        assertContentEquals(rebooted.group.epochAuthenticator, newCharlie.epochAuthenticator)
        assertTalk(newBob, rebooted.group)
        assertTalk(newCharlie, newBob)
        assertTrue(f.alice.isLocalMember(), "the old group carries on until it is left")
    }

    @Test
    fun thePartitionMustHoldUsAndOnlyMembers() {
        val f = fork()
        assertFailsWith<IllegalArgumentException> { f.alice.forkComplement(listOf(f.charlie.leafIndex)) }
        assertFailsWith<IllegalArgumentException> { f.alice.forkComplement(listOf(f.alice.leafIndex, 7)) }
    }

    @Test
    fun aFailedReaddLeavesTheGroupAsItWas() {
        val f = fork()
        val before = f.alice.epochAuthenticator
        assertFails { f.alice.recoverForkByReadding(listOf(f.alice.leafIndex, f.charlie.leafIndex), listOf(byteArrayOf(1, 2, 3))) }
        assertContentEquals(before, f.alice.epochAuthenticator)
        assertFalse(f.alice.hasPendingProposals(), "the Remove proposed on the way is gone too")
    }
}
