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

import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.FramedContent
import com.vitorpamplona.mls.framing.Framing
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.Sender
import com.vitorpamplona.mls.framing.SenderType
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.messages.Commit
import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.messages.ProposalOrRef
import com.vitorpamplona.mls.schedule.KeySchedule
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.Grease
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * End-to-end coverage of the RFC 9420 flows beyond add/remove/application
 * messages: proposals by reference from every kind of sender, external
 * commits (join and resync), out-of-band trees, PrivateMessage commits,
 * staged commits, PSKs in Welcomes and atomic failure.
 */
class RfcFlowsTest {
    private class Trio(
        val alice: MlsGroup,
        val bob: MlsGroup,
        val carol: MlsGroup,
    )

    private fun keyPackage(name: String) = MlsGroup.create(name.encodeToByteArray()).createKeyPackage(name.encodeToByteArray(), ByteArray(0))

    private fun trio(): Trio {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = keyPackage("bob")
        val c = keyPackage("carol")
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        return Trio(alice, MlsGroup.processWelcome(add.welcomeBytes!!, b), MlsGroup.processWelcome(add.welcomeBytes!!, c))
    }

    /** A well-formed GroupContext extension every member satisfies: required_capabilities naming BasicCredential. */
    private fun requiredBasicCredentials(): Extension {
        val w = TlsWriter()
        w.putOpaqueVarInt(ByteArray(0))
        w.putOpaqueVarInt(ByteArray(0))
        w.putOpaqueVarInt(byteArrayOf(0, 1))
        return Extension(MlsGroup.REQUIRED_CAPABILITIES_EXTENSION_TYPE, w.toByteArray())
    }

    private fun assertSameEpoch(vararg groups: MlsGroup) {
        val first = groups.first()
        for (g in groups) {
            assertEquals(first.epoch, g.epoch)
            assertContentEquals(first.epochAuthenticator, g.epochAuthenticator, "epoch authenticators diverged")
        }
    }

    private fun assertTalk(
        from: MlsGroup,
        to: MlsGroup,
    ) {
        val text = "from ${from.leafIndex} to ${to.leafIndex} at ${from.epoch}"
        assertEquals(text, to.decrypt(from.encrypt(text.encodeToByteArray())).content.decodeToString())
    }

    @Test
    fun externalJoinAfterTheGroupHasMovedOn() {
        val t = trio()
        t.alice.commit().also {
            t.bob.processFramedCommit(it.framedCommitBytes)
            t.carol.processFramedCommit(it.framedCommitBytes)
        }
        val join = MlsGroup.externalJoin(t.bob.groupInfoMessage(), "zara".encodeToByteArray())
        for (g in listOf(t.alice, t.bob, t.carol)) g.processFramedCommit(join.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob, t.carol, join.group)
        assertTalk(join.group, t.carol)
        assertTalk(t.alice, join.group)
    }

    @Test
    fun externalJoinIntoATreeWithABlankSubtree() {
        val t = trio()
        t.alice.removeMember(t.bob.leafIndex).also { t.carol.processFramedCommit(it.framedCommitBytes) }
        val join = MlsGroup.externalJoin(t.alice.groupInfo().toTlsBytes(), "zara".encodeToByteArray())
        t.alice.processFramedCommit(join.framedCommitBytes)
        t.carol.processFramedCommit(join.framedCommitBytes)
        assertSameEpoch(t.alice, t.carol, join.group)
        assertEquals(t.bob.leafIndex, join.group.leafIndex, "the joiner takes the leftmost blank leaf")
        assertTalk(t.carol, join.group)
    }

    @Test
    fun externalResyncReplacesTheMembersOldLeaf() {
        val t = trio()
        val members = t.alice.memberCount
        val join =
            MlsGroup.externalJoin(t.alice.groupInfo().toTlsBytes(), "bob".encodeToByteArray(), resyncLeafIndex = t.bob.leafIndex)
        t.alice.processFramedCommit(join.framedCommitBytes)
        t.carol.processFramedCommit(join.framedCommitBytes)
        assertEquals(members, t.alice.memberCount)
        assertSameEpoch(t.alice, t.carol, join.group)
        assertTalk(join.group, t.alice)
    }

    @Test
    fun externalResyncMustKeepTheCredential() {
        val t = trio()
        assertFailsWith<IllegalArgumentException> {
            MlsGroup.externalJoin(t.alice.groupInfo().toTlsBytes(), "mallory".encodeToByteArray(), resyncLeafIndex = t.bob.leafIndex)
        }
    }

    @Test
    fun outOfBandRatchetTree() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = keyPackage("bob")
        val add =
            alice.commit().let {
                alice.proposeAdd(b.keyPackage.toTlsBytes())
                alice.commit(includeRatchetTreeInWelcome = false)
            }
        assertFailsWith<IllegalArgumentException> { MlsGroup.processWelcome(add.welcomeBytes!!, b) }
        val bob = MlsGroup.processWelcome(add.welcomeBytes!!, b, ratchetTree = alice.exportTreeBytes())
        assertSameEpoch(alice, bob)

        val join = MlsGroup.externalJoin(alice.groupInfoMessage(includeRatchetTree = false), "zara".encodeToByteArray(), ratchetTree = alice.exportTreeBytes())
        alice.processFramedCommit(join.framedCommitBytes)
        bob.processFramedCommit(join.framedCommitBytes)
        assertSameEpoch(alice, bob, join.group)
    }

    @Test
    fun updateByReferenceRotatesTheProposersKeys() {
        val t = trio()
        val signatureKeyBefore =
            t.alice
                .members()
                .first { it.first == t.bob.leafIndex }
                .second.signatureKey
        val message = t.bob.proposalMessage(t.bob.proposeSigningKeyRotation(), WireFormat.PRIVATE_MESSAGE)
        assertIs<ProcessedMessage.StagedProposal>(t.alice.processMessage(message))
        t.carol.processMessage(message)
        // The delivery service echoes Bob's own message back to him.
        assertIs<ProcessedMessage.StagedProposal>(t.bob.processMessage(message))

        val commit = t.alice.commit()
        val body = Commit.decodeTls(TlsReader(commit.commitBytes))
        assertIs<ProposalOrRef.Reference>(body.proposals.single(), "someone else's proposal goes in by reference")
        t.bob.processFramedCommit(commit.framedCommitBytes)
        t.carol.processFramedCommit(commit.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob, t.carol)

        val signatureKeyAfter =
            t.alice
                .members()
                .first { it.first == t.bob.leafIndex }
                .second.signatureKey
        assertFalse(signatureKeyBefore.contentEquals(signatureKeyAfter))
        assertTalk(t.bob, t.alice)
        // Bob's leaf now holds the Update's encryption key: a commit that
        // encrypts to it directly must still reach him.
        t.carol.commit().also {
            t.alice.processFramedCommit(it.framedCommitBytes)
            t.bob.processFramedCommit(it.framedCommitBytes)
        }
        assertSameEpoch(t.alice, t.bob, t.carol)
    }

    @Test
    fun ownUpdateIsFoldedIntoTheUpdatePath() {
        val t = trio()
        t.alice.proposeSigningKeyRotation()
        val commit = t.alice.commit()
        assertTrue(Commit.decodeTls(TlsReader(commit.commitBytes)).proposals.isEmpty(), "a committer must not commit its own Update")
        t.bob.processFramedCommit(commit.framedCommitBytes)
        t.carol.processFramedCommit(commit.framedCommitBytes)
        assertTalk(t.alice, t.bob)
    }

    @Test
    fun addRemoveAndExtensionsByReference() {
        val t = trio()
        val dave = keyPackage("dave")
        val add = t.bob.proposalMessage(Proposal.Add(dave.keyPackage))
        val gce = t.carol.proposalMessage(Proposal.GroupContextExtensions(listOf(requiredBasicCredentials())))
        t.alice.processMessage(add)
        t.carol.processMessage(add)
        t.alice.processMessage(gce)
        t.bob.processMessage(gce)
        val commit = t.alice.commit()
        t.bob.processFramedCommit(commit.framedCommitBytes)
        t.carol.processFramedCommit(commit.framedCommitBytes)
        val joined = MlsGroup.processWelcome(commit.welcomeBytes!!, dave)
        assertSameEpoch(t.alice, t.bob, t.carol, joined)
        assertEquals(listOf(1), MlsGroup.findRequiredCapabilities(joined.extensions)!!.credentials)

        val remove = t.bob.proposalMessage(Proposal.Remove(t.carol.leafIndex))
        t.alice.processMessage(remove)
        t.carol.processMessage(remove)
        joined.processMessage(remove)
        val removal = t.alice.commit()
        t.bob.processFramedCommit(removal.framedCommitBytes)
        joined.processFramedCommit(removal.framedCommitBytes)
        t.carol.processFramedCommit(removal.framedCommitBytes)
        assertFalse(t.carol.isLocalMember())
        assertSameEpoch(t.alice, t.bob, joined)
    }

    @Test
    fun externalSenderCanProposeARemoval() {
        val t = trio()
        val service = Ed25519.generateKeyPair()
        val senders = TlsWriter()
        val entry = TlsWriter()
        entry.putOpaqueVarInt(service.publicKey)
        Credential.Basic("service".encodeToByteArray()).encodeTls(entry)
        senders.putOpaqueVarInt(entry.toByteArray())
        t.alice.proposeGroupContextExtensions(listOf(Extension(0x0005, senders.toByteArray())))
        t.alice.commit().also {
            t.bob.processFramedCommit(it.framedCommitBytes)
            t.carol.processFramedCommit(it.framedCommitBytes)
        }

        val content = FramedContent(t.alice.groupId, t.alice.epoch, Sender(SenderType.EXTERNAL, 0), ByteArray(0), ContentType.PROPOSAL, Proposal.Remove(t.carol.leafIndex).toTlsBytes())
        val signature = Framing.sign(service.privateKey, WireFormat.PUBLIC_MESSAGE, content, null)
        val message = MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, null, null)).toTlsBytes()
        val staged = assertIs<ProcessedMessage.StagedProposal>(t.alice.processMessage(message))
        assertEquals(SenderType.EXTERNAL, staged.sender.senderType)
        t.bob.processMessage(message)

        val commit = t.alice.commit()
        t.bob.processFramedCommit(commit.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob)
        assertEquals(2, t.alice.memberCount)

        // A forged external proposal is refused.
        val forged = MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature.copyOf().also { it[0] = (it[0] + 1).toByte() }, null, null)).toTlsBytes()
        assertFailsWith<IllegalArgumentException> { t.alice.processMessage(forged) }
    }

    @Test
    fun newMemberCanProposeItsOwnAdd() {
        val t = trio()
        val dave = keyPackage("dave")
        val content = FramedContent(t.alice.groupId, t.alice.epoch, Sender(SenderType.NEW_MEMBER_PROPOSAL), ByteArray(0), ContentType.PROPOSAL, Proposal.Add(dave.keyPackage).toTlsBytes())
        val signature = Framing.sign(dave.signaturePrivateKey, WireFormat.PUBLIC_MESSAGE, content, null)
        val message = MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, null, null)).toTlsBytes()
        for (g in listOf(t.alice, t.bob, t.carol)) g.processMessage(message)
        val commit = t.alice.commit()
        t.bob.processFramedCommit(commit.framedCommitBytes)
        t.carol.processFramedCommit(commit.framedCommitBytes)
        val joined = MlsGroup.processWelcome(commit.welcomeBytes!!, dave)
        assertSameEpoch(t.alice, t.bob, t.carol, joined)
    }

    @Test
    fun commitAsPrivateMessageWithAuthenticatedDataAndPadding() {
        val t = trio()
        val commit = t.alice.commit(authenticatedData = "aad".encodeToByteArray(), wireFormat = WireFormat.PRIVATE_MESSAGE, paddingLength = 32)
        assertEquals(WireFormat.PRIVATE_MESSAGE, MlsMessage.decodeTls(TlsReader(commit.framedCommitBytes)).wireFormat)
        assertEquals(
            "aad",
            t.bob
                .decrypt(commit.framedCommitBytes)
                .authenticatedData
                .decodeToString(),
        )
        assertIs<ProcessedMessage.AppliedCommit>(t.carol.processMessage(commit.framedCommitBytes))
        assertSameEpoch(t.alice, t.bob, t.carol)

        val publicWithAad = t.bob.commit(authenticatedData = "public aad".encodeToByteArray())
        t.alice.processFramedCommit(publicWithAad.framedCommitBytes)
        t.carol.processFramedCommit(publicWithAad.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob, t.carol)

        val padded = t.alice.encrypt("hi".encodeToByteArray(), paddingLength = 100)
        assertEquals(
            "hi",
            t.carol
                .decrypt(padded)
                .content
                .decodeToString(),
        )
    }

    @Test
    fun stagedCommitWaitsForTheDeliveryService() {
        val t = trio()
        val epoch = t.alice.epoch
        val staged = t.alice.stageCommit()
        assertTrue(t.alice.hasPendingCommit)
        assertEquals(epoch, t.alice.epoch, "staging does not move the group")
        assertTalk(t.bob, t.alice)

        // Bob's commit wins the epoch: Alice processes it and her staged one is dropped.
        val winner = t.bob.commit()
        t.alice.processFramedCommit(winner.framedCommitBytes)
        t.carol.processFramedCommit(winner.framedCommitBytes)
        assertFalse(t.alice.hasPendingCommit)
        assertSameEpoch(t.alice, t.bob, t.carol)
        assertFailsWith<IllegalArgumentException> { t.bob.processFramedCommit(staged.framedCommitBytes) }

        // Next time Alice's commit goes through: its echo merges it.
        val mine = t.alice.stageCommit()
        t.bob.processFramedCommit(mine.framedCommitBytes)
        t.carol.processFramedCommit(mine.framedCommitBytes)
        t.alice.processFramedCommit(mine.framedCommitBytes)
        assertFalse(t.alice.hasPendingCommit)
        assertSameEpoch(t.alice, t.bob, t.carol)

        t.alice.stageCommit()
        t.alice.clearPendingCommit()
        assertFalse(t.alice.hasPendingCommit)
        assertEquals(t.bob.epoch, t.alice.epoch)
    }

    @Test
    fun aFailedCommitChangesNothing() {
        val t = trio()
        val epoch = t.alice.epoch
        val tree = t.alice.exportTreeBytes()
        // An extension no member supports makes the commit invalid, but only
        // once the proposals have been applied.
        t.alice.proposeRemove(t.carol.leafIndex)
        t.alice.proposeGroupContextExtensions(listOf(Extension(0x7777, ByteArray(1))))
        assertFailsWith<IllegalArgumentException> { t.alice.commit() }
        assertEquals(epoch, t.alice.epoch)
        assertContentEquals(tree, t.alice.exportTreeBytes())
        assertTrue(t.alice.hasPendingProposals())
        assertTalk(t.alice, t.carol)
    }

    @Test
    fun pskProposalsReachTheWelcome() {
        val t = trio()
        val id = "shared".encodeToByteArray()
        val psk = ByteArray(32) { 9 }
        for (g in listOf(t.alice, t.bob, t.carol)) g.registerPsk(id, psk)
        val dave = keyPackage("dave")
        t.alice.proposePsk(id)
        t.alice.proposeResumptionPsk(t.alice.epoch)
        t.alice.proposeAdd(dave.keyPackage.toTlsBytes())
        val commit = t.alice.commit()
        t.bob.processFramedCommit(commit.framedCommitBytes)
        t.carol.processFramedCommit(commit.framedCommitBytes)

        assertFailsWith<IllegalStateException> { MlsGroup.processWelcome(commit.welcomeBytes!!, dave) }
        val resumption =
            t.bob
                .saveState()
                .resumptionPsks
                .getValue(t.bob.epoch - 1)
        val joined =
            MlsGroup.processWelcome(commit.welcomeBytes!!, dave) { pskId ->
                when (pskId) {
                    is PreSharedKeyId.External -> psk
                    is PreSharedKeyId.Resumption -> resumption
                }
            }
        assertSameEpoch(t.alice, t.bob, t.carol, joined)
    }

    @Test
    fun aRestoredGroupKeepsResumptionPsksAndStagedProposals() {
        val t = trio()
        t.alice.commit().also {
            t.bob.processFramedCommit(it.framedCommitBytes)
            t.carol.processFramedCommit(it.framedCommitBytes)
        }
        t.bob.processMessage(t.carol.proposalMessage(Proposal.Remove(t.alice.leafIndex)))
        val restored = MlsGroup.restore(MlsGroupState.decodeTls(t.bob.saveState().encodeTls()))
        restored.proposeResumptionPsk(restored.epoch - 1)
        val commit = restored.commit()
        t.carol.processFramedCommit(commit.framedCommitBytes)
        assertSameEpoch(restored, t.carol)
        assertEquals(2, restored.memberCount)
    }

    @Test
    fun aStagedCommitSurvivesARestart() {
        val t = trio()
        val staged = t.alice.stageCommit()
        val restored = MlsGroup.restore(MlsGroupState.decodeTls(t.alice.saveState().encodeTls()))
        assertTrue(restored.hasPendingCommit)
        assertEquals(t.alice.epoch, restored.epoch)
        t.bob.processFramedCommit(staged.framedCommitBytes)
        // The delivery service's echo merges the restored staged commit.
        restored.processFramedCommit(staged.framedCommitBytes)
        assertSameEpoch(restored, t.bob)
        assertTalk(restored, t.bob)
    }

    @Test
    fun aRemovedMemberStaysRemovedWhenItsLeafIsReused() {
        val t = trio()
        val dave = keyPackage("dave")
        // One commit removes Carol and adds Dave, who takes Carol's leaf.
        t.alice.proposeRemove(t.carol.leafIndex)
        t.alice.proposeAdd(dave.keyPackage.toTlsBytes())
        val commit = t.alice.commit()
        t.carol.processFramedCommit(commit.framedCommitBytes)
        t.bob.processFramedCommit(commit.framedCommitBytes)
        val joined = MlsGroup.processWelcome(commit.welcomeBytes!!, dave)
        assertEquals(t.carol.leafIndex, joined.leafIndex)
        assertFalse(t.carol.isLocalMember())
        assertFalse(MlsGroup.restore(MlsGroupState.decodeTls(t.carol.saveState().encodeTls())).isLocalMember())
        assertSameEpoch(t.alice, t.bob, joined)
    }

    @Test
    fun aNewGroupsInterimTranscriptHashFollowsFromItsConfirmationTag() {
        // RFC 9420 §11: a new group's interim transcript hash is computed from a
        // confirmation tag over the empty confirmed transcript hash (§8.2), the
        // tag its GroupInfo carries. An external joiner of epoch 0 derives it so.
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val groupInfo = alice.groupInfo()
        assertEquals(0, groupInfo.groupContext.confirmedTranscriptHash.size)
        val input = TlsWriter().apply { putOpaqueVarInt(groupInfo.confirmationTag) }.toByteArray()
        assertContentEquals(MlsCryptoProvider.hash(input), alice.saveState().interimTranscriptHash)
    }

    @Test
    fun aNewGroupsEpochSecretIsNotDerivedFromItsGroupContext() {
        // RFC 9420 §11: the first epoch secret is fresh randomness, not a
        // function of the (non-secret) GroupContext.
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val zero = ByteArray(MlsCryptoProvider.HASH_OUTPUT_LENGTH)
        val fromContext = KeySchedule(alice.groupInfo().groupContext.toTlsBytes()).deriveEpochSecrets(zero, zero)
        assertFalse(fromContext.epochSecret.contentEquals(alice.saveState().epochSecrets.epochSecret))
    }

    @Test
    fun anExternalJoinerOfANewGroupAgreesOnItsTranscript() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val restored = MlsGroup.restore(alice.saveState())
        val join = MlsGroup.externalJoin(alice.groupInfo().toTlsBytes(), "bob".encodeToByteArray())
        restored.processFramedCommit(join.framedCommitBytes)
        assertSameEpoch(restored, join.group)
        assertTalk(restored, join.group)
    }

    @Test
    fun anExternalJoinCanCarryAResumptionPskOfTheGroup() {
        // A former member rejoining by external commit proves it held an earlier epoch.
        val t = trio()
        val epoch = t.alice.epoch
        val psk = t.alice.resumptionPsk
        t.alice.commit().also {
            t.bob.processFramedCommit(it.framedCommitBytes)
            t.carol.processFramedCommit(it.framedCommitBytes)
        }
        val id = PreSharedKeyId.Resumption(PreSharedKeyId.USAGE_APPLICATION, t.alice.groupId, epoch, ByteArray(32) { 9 })
        val join = MlsGroup.externalJoin(t.alice.groupInfo().toTlsBytes(), "zara".encodeToByteArray(), psks = listOf(id to psk))
        t.alice.processFramedCommit(join.framedCommitBytes)
        assertSameEpoch(t.alice, join.group)
        assertTalk(t.alice, join.group)
    }

    @Test
    fun aPolicyCanRefuseExternalJoins() {
        val closed =
            object : MlsGroupPolicy {
                override fun authorizeExternalCommit(
                    group: GroupView,
                    joiner: com.vitorpamplona.mls.tree.LeafNode,
                    resynced: com.vitorpamplona.mls.tree.LeafNode?,
                ): Unit = throw IllegalStateException("no external joins")
            }
        val alice = MlsGroup.create("alice".encodeToByteArray(), policy = closed)
        val join = MlsGroup.externalJoin(alice.groupInfo().toTlsBytes(), "zara".encodeToByteArray())
        assertFailsWith<IllegalStateException> { alice.processFramedCommit(join.framedCommitBytes) }
        assertEquals(0L, alice.epoch)
    }

    @Test
    fun reinitMovesEveryMemberToTheSuccessorGroup() {
        val t = trio()
        val newId = ByteArray(32) { 42 }
        t.alice.proposeReInit(newGroupId = newId, newExtensions = listOf(requiredBasicCredentials()))
        t.alice.commit().also {
            t.bob.processFramedCommit(it.framedCommitBytes)
            t.carol.processFramedCommit(it.framedCommitBytes)
        }
        assertFailsWith<IllegalStateException> { t.alice.encrypt("old group".encodeToByteArray()) }

        val bobKp = t.bob.createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
        val carolKp = t.carol.createKeyPackage("carol".encodeToByteArray(), ByteArray(0))
        val successor = t.alice.reinit(listOf(bobKp.keyPackage.toTlsBytes(), carolKp.keyPackage.toTlsBytes()))
        val bob = MlsGroup.joinSuccessor(successor.commit.welcomeBytes!!, bobKp, predecessor = t.bob)
        val carol = MlsGroup.joinSuccessor(successor.commit.welcomeBytes!!, carolKp, predecessor = t.carol)

        assertContentEquals(newId, bob.groupId)
        assertEquals(1L, bob.epoch)
        assertSameEpoch(successor.group, bob, carol)
        assertTalk(bob, carol)
        assertTalk(successor.group, bob)
    }

    @Test
    fun aReinitCanKeepTheGroupId() {
        // The mlswg interop runner's reinit/change_extensions script: same group_id, empty required_capabilities and external_senders.
        val t = trio()
        val extensions = listOf(Extension(3, byteArrayOf(0, 0, 0)), Extension(5, byteArrayOf(0)))
        t.alice.proposeReInit(newGroupId = t.alice.groupId, newExtensions = extensions)
        t.alice.commit().also {
            t.bob.processFramedCommit(it.framedCommitBytes)
            t.carol.processFramedCommit(it.framedCommitBytes)
        }

        val aliceKp = t.alice.createKeyPackage("alice".encodeToByteArray(), ByteArray(0))
        val bobKp = t.bob.createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
        val successor = t.carol.reinit(listOf(aliceKp.keyPackage.toTlsBytes(), bobKp.keyPackage.toTlsBytes()))
        val alice = MlsGroup.joinSuccessor(successor.commit.welcomeBytes!!, aliceKp, predecessor = t.alice)
        val bob = MlsGroup.joinSuccessor(successor.commit.welcomeBytes!!, bobKp, predecessor = t.bob)
        assertSameEpoch(successor.group, alice, bob)
        assertTalk(alice, bob)
    }

    @Test
    fun aSuccessorMustMatchItsPredecessor() {
        val t = trio()
        // No ReInit was committed, so a "reinit" Welcome has nothing to resume.
        val bobKp = t.bob.createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
        val branch = t.alice.branch(listOf(bobKp.keyPackage.toTlsBytes()))
        // A branch joined as a member of an unrelated group is refused.
        val stranger = MlsGroup.create("bob".encodeToByteArray())
        assertFailsWith<Exception> { MlsGroup.joinSuccessor(branch.commit.welcomeBytes!!, bobKp, predecessor = stranger) }

        // A branch that adds someone who was never a member is refused by members.
        val dave = keyPackage("dave")
        val bobKp2 = t.bob.createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
        val widened = t.alice.branch(listOf(bobKp2.keyPackage.toTlsBytes(), dave.keyPackage.toTlsBytes()))
        val error = assertFailsWith<IllegalArgumentException> { MlsGroup.joinSuccessor(widened.commit.welcomeBytes!!, bobKp2, predecessor = t.bob) }
        assertTrue(error.message!!.contains("only hold members"))
    }

    @Test
    fun aBranchLeavesItsPredecessorRunning() {
        val t = trio()
        val bobKp = t.bob.createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
        val branch = t.alice.branch(listOf(bobKp.keyPackage.toTlsBytes()))
        val bob = MlsGroup.joinSuccessor(branch.commit.welcomeBytes!!, bobKp, predecessor = t.bob)
        assertSameEpoch(branch.group, bob)
        assertEquals(2, bob.memberCount)
        assertTalk(bob, branch.group)
        // The original group is untouched.
        assertTalk(t.carol, t.alice)
    }

    @Test
    fun theRatchetForwardDistanceIsAPolicySetting() {
        val strict =
            object : MlsGroupPolicy {
                override val maxForwardRatchetDistance: Int get() = 2
            }
        val alice = MlsGroup.create("alice".encodeToByteArray(), policy = strict)
        val b = keyPackage("bob")
        val bob = MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b)
        val messages = (0 until 5).map { bob.encrypt("m$it".encodeToByteArray()) }
        // Generation 4 is four steps ahead: further than this policy allows.
        assertFailsWith<IllegalArgumentException> { alice.decrypt(messages[4]) }
        assertEquals("m1", alice.decrypt(messages[1]).content.decodeToString())
    }

    @Test
    fun customProposalsTravelInlineAndByReference() {
        val custom = 0xF0F0
        val caps = Capabilities(proposals = listOf(custom))
        val alice = MlsGroup.create("alice".encodeToByteArray(), capabilities = caps)
        val factory = MlsGroup.create("factory".encodeToByteArray())
        val b = factory.createKeyPackage("bob".encodeToByteArray(), ByteArray(0), capabilities = caps)
        val bob = MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b)

        // Inline, from the committer.
        alice.proposeCustom(custom, "inline".encodeToByteArray())
        val inline = assertIs<ProcessedMessage.AppliedCommit>(bob.processMessage(alice.commit().framedCommitBytes))
        assertEquals("inline", (inline.proposals.single().proposal as Proposal.Custom).data.decodeToString())

        // By reference, from another member.
        alice.processMessage(bob.proposalMessage(Proposal.Custom(custom, "by ref".encodeToByteArray())))
        val byRef = alice.commit()
        val applied = assertIs<ProcessedMessage.AppliedCommit>(bob.processMessage(byRef.framedCommitBytes))
        assertEquals("by ref", (applied.proposals.single().proposal as Proposal.Custom).data.decodeToString())
        assertSameEpoch(alice, bob)
    }

    @Test
    fun aCustomProposalNotEveryMemberSupportsIsRefused() {
        val t = trio()
        t.alice.proposeCustom(0xF0F0, ByteArray(1))
        assertFailsWith<IllegalArgumentException> { t.alice.commit() }
    }

    @Test
    fun leavesAdvertiseGrease() {
        val kp = keyPackage("dave").keyPackage
        val caps = kp.leafNode.capabilities
        for (list in listOf(caps.ciphersuites, caps.extensions, caps.proposals, caps.credentials)) {
            assertTrue(list.any { Grease.isGrease(it) }, "no GREASE value in $list")
        }
        // A GREASE value is only ever advertised, never sent as a proposal.
        assertFailsWith<IllegalArgumentException> {
            val alice = MlsGroup.create("alice".encodeToByteArray())
            alice.proposeCustom(Grease.VALUES.first(), ByteArray(0))
            alice.commit()
        }
    }

    @Test
    fun unknownCredentialAndProposalTypesRoundTrip() {
        val credential = Credential.Custom(0xF00D, "opaque".encodeToByteArray())
        val decoded = Credential.decodeTls(TlsReader(credential.toTlsBytes()))
        assertEquals(credential, decoded)
        val proposal = Proposal.Custom(0xF0F0, byteArrayOf(1, 2, 3))
        assertEquals(proposal, Proposal.decodeTls(TlsReader(proposal.toTlsBytes())))
    }
}
