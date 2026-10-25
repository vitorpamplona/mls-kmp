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

import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.FramedContent
import com.vitorpamplona.mls.framing.Framing
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.Sender
import com.vitorpamplona.mls.framing.SenderType
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.messages.Commit
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.messages.ProposalOrRef
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** [PublicGroup]: following a group from outside, through its PublicMessages. */
class PublicGroupTest {
    private fun bundle(name: String) = MlsGroup.create(name.encodeToByteArray()).createKeyPackage(name.encodeToByteArray(), ByteArray(0))

    private fun names(members: List<Pair<Int, LeafNode>>) = members.map { (it.second.credential as Credential.Basic).identity.decodeToString() }

    private class Trio(
        val alice: MlsGroup,
        val bob: MlsGroup,
        val carol: MlsGroup,
    )

    private fun trio(policy: MlsGroupPolicy = MlsGroupPolicy.Permissive): Trio {
        val alice = MlsGroup.create("alice".encodeToByteArray(), policy = policy)
        val b = bundle("bob")
        val c = bundle("carol")
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        return Trio(alice, MlsGroup.processWelcome(add.welcomeBytes!!, b, policy), MlsGroup.processWelcome(add.welcomeBytes!!, c, policy))
    }

    /** The view agrees with [member] on everything public: epoch, tree, GroupContext and transcript. */
    private fun assertInSync(
        view: PublicGroup,
        member: MlsGroup,
    ) {
        assertEquals(member.epoch, view.epoch)
        assertContentEquals(member.exportTreeBytes(), view.exportTreeBytes())
        val ours = view.saveState()
        val theirs = member.saveState()
        assertContentEquals(theirs.groupContext.toTlsBytes(), ours.groupContext.toTlsBytes())
        assertContentEquals(theirs.interimTranscriptHash, ours.interimTranscriptHash)
    }

    /** Hand [message] to the view and to every member. */
    private fun deliver(
        message: ByteArray,
        view: PublicGroup,
        vararg members: MlsGroup,
    ) {
        view.processMessage(message)
        members.forEach { it.processMessage(message) }
    }

    @Test
    fun followsTheGroupThroughEveryPublicChange() {
        val t = trio()
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage())
        assertInSync(view, t.alice)
        assertEquals(listOf("alice", "bob", "carol"), names(view.members()))

        // A commit adding a member.
        val dave = bundle("dave")
        val add = t.alice.addMember(dave.keyPackage.toTlsBytes())
        deliver(add.framedCommitBytes, view, t.bob, t.carol)
        val daveGroup = MlsGroup.processWelcome(add.welcomeBytes!!, dave)
        assertInSync(view, t.alice)

        // A proposal by reference, then another member's commit of it.
        val update = t.bob.proposalMessage(t.bob.proposeSigningKeyRotation())
        deliver(update, view, t.alice, t.carol, daveGroup)
        assertEquals(1, view.pendingProposals().size)
        val byRef = t.carol.commit()
        deliver(byRef.framedCommitBytes, view, t.alice, t.bob, daveGroup)
        assertTrue(view.pendingProposals().isEmpty())
        assertInSync(view, t.carol)

        // An external join, then a removal.
        val zara = MlsGroup.externalJoin(t.alice.groupInfoMessage(), "zara".encodeToByteArray())
        deliver(zara.framedCommitBytes, view, t.alice, t.bob, t.carol, daveGroup)
        assertInSync(view, zara.group)
        val remove = zara.group.removeMember(t.bob.leafIndex)
        deliver(remove.framedCommitBytes, view, t.alice, t.carol, daveGroup)
        assertInSync(view, t.alice)
        assertEquals(listOf("alice", "carol", "dave", "zara"), names(view.members()))
    }

    @Test
    fun followsCommitsWithPsksAndNewExtensions() {
        val t = trio()
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage())
        val id = "shared".encodeToByteArray()
        for (g in listOf(t.alice, t.bob, t.carol)) g.registerPsk(id, ByteArray(32) { 3 })
        t.alice.proposePsk(id)
        t.alice.proposeResumptionPsk(t.alice.epoch)
        deliver(t.alice.commit().framedCommitBytes, view, t.bob, t.carol)
        assertInSync(view, t.alice)

        // required_capabilities naming BasicCredential: an extension every member satisfies.
        val required =
            TlsWriter().apply {
                putOpaqueVarInt(ByteArray(0))
                putOpaqueVarInt(ByteArray(0))
                putOpaqueVarInt(byteArrayOf(0, 1))
            }
        val extensions = listOf(Extension(MlsGroup.REQUIRED_CAPABILITIES_EXTENSION_TYPE, required.toByteArray()))
        t.bob.proposeGroupContextExtensions(extensions)
        deliver(t.bob.commit().framedCommitBytes, view, t.alice, t.carol)
        assertInSync(view, t.bob)
        assertEquals(extensions, view.extensions)
    }

    @Test
    fun aGroupInfoWithoutTheTreeTakesItOutOfBand() {
        val t = trio()
        assertFailsWith<IllegalArgumentException> { PublicGroup.fromGroupInfo(t.alice.groupInfoMessage(includeRatchetTree = false)) }
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage(includeRatchetTree = false), ratchetTree = t.alice.exportTreeBytes())
        assertInSync(view, t.alice)
    }

    /** A commit by [sender] carrying [proposals] inline and no path: correctly signed, with a placeholder confirmation tag. */
    private fun forge(
        sender: MlsGroup,
        proposals: List<Proposal>,
    ): ByteArray {
        val state = sender.saveState()
        val ctx = state.groupContext.toTlsBytes()
        val body = Commit(proposals.map { ProposalOrRef.Inline(it) }, null).toTlsBytes()
        val content = FramedContent(sender.groupId, sender.epoch, Sender(SenderType.MEMBER, sender.leafIndex), ByteArray(0), ContentType.COMMIT, body)
        val signature = Framing.sign(state.signingPrivateKey, WireFormat.PUBLIC_MESSAGE, content, ctx)
        val tag = ByteArray(32)
        val membershipTag = Framing.membershipTag(state.epochSecrets.membershipKey, content, ctx, signature, tag)
        return MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, tag, membershipTag)).toTlsBytes()
    }

    @Test
    fun aCommitBreakingTheProposalRulesIsRejectedAndTheViewStaysPut() {
        val t = trio()
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage())
        for (proposals in listOf(listOf(Proposal.Remove(2)), listOf(Proposal.Remove(t.alice.leafIndex)))) {
            assertFailsWith<IllegalArgumentException> { view.processMessage(forge(t.alice, proposals)) }
            assertInSync(view, t.alice)
        }
    }

    @Test
    fun aCommitFromTheWrongEpochOrGroupIsRejected() {
        val t = trio()
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage())
        val first = t.alice.commit()
        view.processMessage(first.framedCommitBytes)
        assertFailsWith<IllegalArgumentException>("a replay") { view.processMessage(first.framedCommitBytes) }
        val other = trio()
        assertFailsWith<IllegalArgumentException>("another group") { view.processMessage(other.alice.commit().framedCommitBytes) }
        assertEquals(t.alice.epoch, view.epoch)
    }

    @Test
    fun privateMessagesCannotBeFollowed() {
        val t = trio()
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage())
        val commit = t.alice.commit(wireFormat = WireFormat.PRIVATE_MESSAGE)
        assertFailsWith<IllegalArgumentException> { view.processMessage(commit.framedCommitBytes) }
        assertFailsWith<IllegalArgumentException> { view.processMessage(t.alice.encrypt("hi".encodeToByteArray())) }
    }

    @Test
    fun theViewEnforcesTheGroupsPolicy() {
        val onlyAlice =
            object : MlsGroupPolicy {
                override fun authorizeCommit(
                    group: GroupView,
                    proposals: List<PendingProposal>,
                    committerLeafIndex: Int,
                ) = require(committerLeafIndex == 0) { "only alice commits" }
            }
        val t = trio()
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage(), onlyAlice)
        val bobs = t.bob.commit()
        val error = assertFailsWith<IllegalArgumentException> { view.processMessage(bobs.framedCommitBytes) }
        assertEquals("only alice commits", error.message)
        assertIs<ProcessedMessage.AppliedCommit>(PublicGroup.fromGroupInfo(t.alice.groupInfoMessage()).processMessage(bobs.framedCommitBytes))
    }

    @Test
    fun theViewSurvivesARestart() {
        val t = trio()
        val view = PublicGroup.restore(PublicGroup.fromGroupInfo(t.alice.groupInfoMessage()).saveState())
        val update = t.carol.proposalMessage(t.carol.proposeSigningKeyRotation())
        deliver(update, view, t.alice, t.bob)
        val restored = PublicGroup.restore(view.saveState())
        assertEquals(1, restored.pendingProposals().size)
        val commit = t.alice.commit()
        deliver(commit.framedCommitBytes, restored, t.bob, t.carol)
        assertInSync(restored, t.alice)
    }

    /**
     * The limit of a view without secrets: the confirmation tag binds the
     * commit to the new epoch's keys, and only members can check it. A
     * tampered tag passes the view; the members' membership tag catches it.
     */
    @Test
    fun aTamperedConfirmationTagIsOnlyCaughtByMembers() {
        val t = trio()
        val view = PublicGroup.fromGroupInfo(t.alice.groupInfoMessage())
        val commit =
            t.alice
                .commit()
                .framedCommitBytes
                .copyOf()
        // A PublicMessage commit ends confirmation_tag<V> || membership_tag<V>, 32 bytes each.
        commit[commit.size - 40] = (commit[commit.size - 40].toInt() xor 1).toByte()
        val bobBefore = t.bob.epochAuthenticator
        assertFailsWith<IllegalArgumentException> { t.bob.processMessage(commit) }
        assertContentEquals(bobBefore, t.bob.epochAuthenticator)
        assertIs<ProcessedMessage.AppliedCommit>(view.processMessage(commit))
        assertFalse(view.saveState().interimTranscriptHash.contentEquals(t.alice.saveState().interimTranscriptHash), "the view now trails a commit the members refused")
    }
}
