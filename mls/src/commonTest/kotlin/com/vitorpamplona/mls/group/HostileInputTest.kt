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
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.FramedContent
import com.vitorpamplona.mls.framing.Framing
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.Sender
import com.vitorpamplona.mls.framing.SenderType
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.messages.Commit
import com.vitorpamplona.mls.messages.GroupInfo
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.messages.ProposalOrRef
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Inputs built to cost the receiver: huge counts, huge trees, oversized
 * messages, indices off the end of every structure. Each must be refused
 * with an IllegalArgumentException within a time budget, leaving the group
 * as it was.
 */
class HostileInputTest {
    private val budget = 30.seconds

    private fun bundle(name: String) = MlsGroup.createKeyPackage(name.encodeToByteArray())

    private fun pair(policy: MlsGroupPolicy = MlsGroupPolicy.Permissive): Pair<MlsGroup, MlsGroup> {
        val alice = MlsGroup.create("alice".encodeToByteArray(), policy = policy)
        val b = MlsGroup.createKeyPackage("bob".encodeToByteArray(), policy)
        return alice to MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b, policy)
    }

    /** A commit from [sender] with [proposals], signed and MACed, with a placeholder confirmation tag. */
    private fun forge(
        sender: MlsGroup,
        proposals: List<ProposalOrRef>,
    ): ByteArray {
        val state = sender.saveState()
        val ctx = state.groupContext.toTlsBytes()
        val content = FramedContent(sender.groupId, sender.epoch, Sender(SenderType.MEMBER, sender.leafIndex), ByteArray(0), ContentType.COMMIT, Commit(proposals, null).toTlsBytes())
        val signature = Framing.sign(state.signingPrivateKey, WireFormat.PUBLIC_MESSAGE, content, ctx)
        val tag = ByteArray(32)
        val membershipTag = Framing.membershipTag(state.epochSecrets.membershipKey, content, ctx, signature, tag)
        return MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, tag, membershipTag)).toTlsBytes()
    }

    private fun refusedQuickly(
        what: String,
        block: () -> Unit,
    ) {
        val start = TimeSource.Monotonic.markNow()
        assertFailsWith<IllegalArgumentException>(what) { block() }
        val took: Duration = start.elapsedNow()
        assertTrue(took < budget, "$what took $took")
    }

    @Test
    fun aCommitWithTenThousandProposals() {
        val (alice, bob) = pair()
        val before = bob.epochAuthenticator
        val commit = forge(alice, List(10_000) { ProposalOrRef.Inline(Proposal.Remove(1)) })
        refusedQuickly("10,000 proposals") { bob.processMessage(commit) }
        assertContentEquals(before, bob.epochAuthenticator)
    }

    @Test
    fun aCommitWithAMillionReferences() {
        val (alice, bob) = pair()
        val commit = forge(alice, List(1_000_000) { ProposalOrRef.Reference(ByteArray(0)) })
        refusedQuickly("a million references") { bob.processMessage(commit) }
        refusedQuickly("a million references, to a view") { PublicGroup.fromGroupInfo(alice.groupInfoMessage()).processMessage(commit) }
    }

    @Test
    fun aRatchetTreePaddedWithBlankLeaves() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val dave = bundle("dave")
        alice.proposeAdd(dave.keyPackage.toTlsBytes())
        val welcome = alice.commit(includeRatchetTreeInWelcome = false).welcomeBytes!!
        val inner = TlsReader(alice.exportTreeBytes()).readOpaqueVarInt()
        val padded = TlsWriter().apply { putOpaqueVarInt(inner + ByteArray(1 shl 17)) }.toByteArray()
        refusedQuickly("a tree padded with 65,536 blank leaves") { MlsGroup.processWelcome(welcome, dave, ratchetTree = padded) }
    }

    @Test
    fun maxMessageSizeIsCheckedBeforeDecoding() {
        val small =
            object : MlsGroupPolicy {
                override val maxMessageSize = 64
            }
        val (alice, bob) = pair()
        val strict = MlsGroup.restore(bob.saveState(), small)
        refusedQuickly("an oversized message") { strict.processMessage(alice.encrypt("x".encodeToByteArray())) }
        refusedQuickly("an oversized GroupInfo") { MlsGroup.externalJoin(alice.groupInfoMessage(), "z".encodeToByteArray(), policy = small) }
        refusedQuickly("an oversized GroupInfo, to a view") { PublicGroup.fromGroupInfo(alice.groupInfoMessage(), small) }
        val dave = bundle("dave")
        val welcome = alice.addMember(dave.keyPackage.toTlsBytes()).welcomeBytes!!
        refusedQuickly("an oversized Welcome") { MlsGroup.processWelcome(welcome, dave, small) }
    }

    // --- Found by MessageFuzzTest ---

    @Test
    fun aGroupInfoSignerOffTheEndOfTheTree() {
        val (alice, _) = pair()
        val info = GroupInfo.decodeTls(TlsReader(MlsMessage.decodeTls(TlsReader(alice.groupInfoMessage())).payload))
        for (signer in listOf(0x7FFFFFFF, 0x12345678)) {
            val forged = info.copy(signer = signer).toTlsBytes()
            refusedQuickly("signer $signer") { MlsGroup.externalJoin(forged, "z".encodeToByteArray()) }
            refusedQuickly("signer $signer, to a view") { PublicGroup.fromGroupInfo(forged) }
        }
        // A uint32 past Int.MAX_VALUE once read as a negative index.
        val marker = info.copy(signer = 0x0BADF00D).toTlsBytes()
        val at = (0..marker.size - 4).first { marker[it] == 0x0B.toByte() && marker[it + 1] == 0xAD.toByte() && marker[it + 2] == 0xF0.toByte() && marker[it + 3] == 0x0D.toByte() }
        val negative = marker.copyOf().also { for (k in 0 until 4) it[at + k] = 0xFF.toByte() }
        refusedQuickly("signer 0xFFFFFFFF") { MlsGroup.externalJoin(negative, "z".encodeToByteArray()) }
    }

    @Test
    fun countsAndIndicesTheBytesCannotBack() {
        refusedQuickly("a count of 2^31") { TlsReader(byteArrayOf(0x7F, -1, -1, -1)).readCount() }
        refusedQuickly("an index past Int.MAX_VALUE") { TlsReader(byteArrayOf(-1, -1, -1, -1)).readIndex() }
        // Every count and index in a saved state is a uint32: inflate each
        // position in turn. Each damaged state decodes or is refused, nothing
        // else, and none of them costs more than the budget.
        val state = pair().second.saveState().encodeTls()
        val start = TimeSource.Monotonic.markNow()
        for (i in 2 until state.size - 4) {
            val damaged =
                state.copyOf().also {
                    it[i] = 0x7F
                    it[i + 1] = -1
                    it[i + 2] = -1
                    it[i + 3] = -1
                }
            try {
                MlsGroup.restore(MlsGroupState.decodeTls(damaged))
            } catch (_: IllegalArgumentException) {
            } catch (_: IllegalStateException) {
            }
        }
        assertTrue(start.elapsedNow() < budget, "decoding ${state.size} damaged states took ${start.elapsedNow()}")
    }
}
