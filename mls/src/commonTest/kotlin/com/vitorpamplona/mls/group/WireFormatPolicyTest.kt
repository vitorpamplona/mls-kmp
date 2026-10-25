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

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.WireFormat
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/** [WireFormatPolicy]: which wire format members' proposals and commits travel in (RFC 9420 §6). */
class WireFormatPolicyTest {
    private fun policy(wire: WireFormatPolicy) =
        object : MlsGroupPolicy {
            override val wireFormatPolicy = wire
        }

    private fun wireFormatOf(bytes: ByteArray) = MlsMessage.decodeTls(TlsReader(bytes)).wireFormat

    /** alice and bob, both under [wire]. */
    private fun pair(wire: WireFormatPolicy): Pair<MlsGroup, MlsGroup> {
        val alice = MlsGroup.create("alice".encodeToByteArray(), policy = policy(wire))
        val bundle = MlsGroup.create("bob".encodeToByteArray()).createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
        val add = alice.addMember(bundle.keyPackage.toTlsBytes())
        return alice to MlsGroup.processWelcome(add.welcomeBytes!!, bundle, policy(wire))
    }

    @Test
    fun theDefaultSendsPublicMessagesAndAcceptsBoth() {
        val (alice, bob) = pair(MlsGroupPolicy.Permissive.wireFormatPolicy)
        assertEquals(WireFormatPolicy.MIXED_PLAINTEXT, MlsGroupPolicy.Permissive.wireFormatPolicy)
        val public = alice.commit()
        assertEquals(WireFormat.PUBLIC_MESSAGE, wireFormatOf(public.framedCommitBytes))
        bob.processMessage(public.framedCommitBytes)
        val private = alice.commit(wireFormat = WireFormat.PRIVATE_MESSAGE)
        assertEquals(WireFormat.PRIVATE_MESSAGE, wireFormatOf(private.framedCommitBytes))
        bob.processMessage(private.framedCommitBytes)
        assertContentEquals(alice.epochAuthenticator, bob.epochAuthenticator)
    }

    @Test
    fun pureCiphertextSendsEveryHandshakeAsAPrivateMessage() {
        val (alice, bob) = pair(WireFormatPolicy.PURE_CIPHERTEXT)
        val proposal = bob.proposalMessage(bob.proposeSigningKeyRotation())
        assertEquals(WireFormat.PRIVATE_MESSAGE, wireFormatOf(proposal))
        assertIs<ProcessedMessage.StagedProposal>(alice.processMessage(proposal))
        val commit = alice.commit()
        assertEquals(WireFormat.PRIVATE_MESSAGE, wireFormatOf(commit.framedCommitBytes))
        assertIs<ProcessedMessage.AppliedCommit>(bob.processMessage(commit.framedCommitBytes))
        assertContentEquals(alice.epochAuthenticator, bob.epochAuthenticator)
    }

    @Test
    fun pureCiphertextRejectsAPublicCommitAndStaysPut() {
        val (alice, bob) = pair(WireFormatPolicy.MIXED_PLAINTEXT)
        // carol joins alice's group, but runs it as PURE_CIPHERTEXT.
        val bundle = MlsGroup.create("carol".encodeToByteArray()).createKeyPackage("carol".encodeToByteArray(), ByteArray(0))
        val add = alice.addMember(bundle.keyPackage.toTlsBytes())
        bob.processMessage(add.framedCommitBytes)
        val carol = MlsGroup.processWelcome(add.welcomeBytes!!, bundle, policy(WireFormatPolicy.PURE_CIPHERTEXT))
        val before = carol.epochAuthenticator

        val public = alice.commit()
        assertFailsWith<IllegalArgumentException> { carol.processMessage(public.framedCommitBytes) }
        assertContentEquals(before, carol.epochAuthenticator, "a refused commit leaves the group where it was")

        val proposal = bob.proposalMessage(bob.proposeSigningKeyRotation(), WireFormat.PUBLIC_MESSAGE)
        assertFailsWith<IllegalArgumentException> { carol.processMessage(proposal) }
    }

    @Test
    fun purePlaintextRejectsAPrivateProposal() {
        val (alice, bob) = pair(WireFormatPolicy.MIXED_CIPHERTEXT)
        val strict = MlsGroup.restore(bob.saveState(), policy(WireFormatPolicy.PURE_PLAINTEXT))
        val proposal = alice.proposalMessage(alice.proposeSigningKeyRotation())
        assertEquals(WireFormat.PRIVATE_MESSAGE, wireFormatOf(proposal), "MIXED_CIPHERTEXT sends PrivateMessages")
        assertFailsWith<IllegalArgumentException> { strict.processMessage(proposal) }
        assertIs<ProcessedMessage.StagedProposal>(bob.processMessage(proposal), "MIXED accepts it")
    }

    @Test
    fun anExplicitWireFormatThePolicyRefusesIsNotSent() {
        val (alice, _) = pair(WireFormatPolicy.PURE_CIPHERTEXT)
        assertFailsWith<IllegalArgumentException> { alice.commit(wireFormat = WireFormat.PUBLIC_MESSAGE) }
        assertFailsWith<IllegalArgumentException> { alice.proposalMessage(alice.proposeSigningKeyRotation(), WireFormat.PUBLIC_MESSAGE) }
        assertEquals(1L, alice.epoch, "the refused commit did not move the group")
    }

    @Test
    fun externalCommitsArePublicWhateverThePolicy() {
        val (alice, bob) = pair(WireFormatPolicy.PURE_CIPHERTEXT)
        val join = MlsGroup.externalJoin(alice.groupInfoMessage(), "zara".encodeToByteArray())
        assertEquals(WireFormat.PUBLIC_MESSAGE, wireFormatOf(join.framedCommitBytes))
        alice.processMessage(join.framedCommitBytes)
        bob.processMessage(join.framedCommitBytes)
        assertContentEquals(alice.epochAuthenticator, join.group.epochAuthenticator)
        assertContentEquals(bob.epochAuthenticator, join.group.epochAuthenticator)
    }

    @Test
    fun aPolicyMustAcceptWhatItSends() {
        assertFailsWith<IllegalArgumentException> { WireFormatPolicy(WireFormat.PUBLIC_MESSAGE, WireFormatPolicy.Incoming.PRIVATE_ONLY) }
        assertFailsWith<IllegalArgumentException> { WireFormatPolicy(WireFormat.WELCOME, WireFormatPolicy.Incoming.MIXED) }
    }
}
