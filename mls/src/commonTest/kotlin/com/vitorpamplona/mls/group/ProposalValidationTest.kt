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

import com.vitorpamplona.crypto.curve25519.Ed25519KeyPair
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
import com.vitorpamplona.mls.messages.UpdatePath
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Extension
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Commits that break an RFC 9420 §12.2 / §12.4.2 rule, signed and MACed by a
 * real member so only the rule itself can reject them. Every receiver must
 * refuse each one and stay exactly where it was.
 */
class ProposalValidationTest {
    private class Pair2(
        val alice: MlsGroup,
        val bob: MlsGroup,
    )

    private fun keyPackage(name: String) = MlsGroup.create(name.encodeToByteArray()).createKeyPackage(name.encodeToByteArray(), ByteArray(0))

    private fun pair(): Pair2 {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = keyPackage("bob")
        val c = keyPackage("carol")
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        return Pair2(alice, MlsGroup.processWelcome(add.welcomeBytes!!, b))
    }

    /** A commit from [sender] carrying [proposals] inline, authentic except for its confirmation tag. */
    private fun forge(
        sender: MlsGroup,
        proposals: List<Proposal>,
        path: UpdatePath? = null,
    ): ByteArray {
        val state = sender.saveState()
        val ctx = state.groupContext.toTlsBytes()
        val body = Commit(proposals.map { ProposalOrRef.Inline(it) }, path).toTlsBytes()
        val content = FramedContent(sender.groupId, sender.epoch, Sender(SenderType.MEMBER, sender.leafIndex), ByteArray(0), ContentType.COMMIT, body)
        val signature = Framing.sign(state.signingPrivateKey, WireFormat.PUBLIC_MESSAGE, content, ctx)
        val tag = ByteArray(32)
        val membershipTag = Framing.membershipTag(state.epochSecrets.membershipKey, content, ctx, signature, tag)
        return MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, tag, membershipTag)).toTlsBytes()
    }

    private fun assertRejected(
        receiver: MlsGroup,
        commit: ByteArray,
        reason: String,
    ) {
        val epoch = receiver.epoch
        val tree = receiver.exportTreeBytes()
        val error = assertFailsWith<Exception> { receiver.processFramedCommit(commit) }
        assertTrue(error.message.orEmpty().contains(reason), "expected '$reason', got '${error.message}'")
        assertEquals(epoch, receiver.epoch)
        assertContentEquals(tree, receiver.exportTreeBytes())
    }

    @Test
    fun aRemoveWithoutAPathIsRejected() {
        val p = pair()
        assertRejected(p.bob, forge(p.alice, listOf(Proposal.Remove(2))), "required UpdatePath")
    }

    @Test
    fun anEmptyCommitWithoutAPathIsRejected() {
        val p = pair()
        assertRejected(p.bob, forge(p.alice, emptyList()), "required UpdatePath")
    }

    @Test
    fun twoGroupContextExtensionsAreRejected() {
        val p = pair()
        val gce = Proposal.GroupContextExtensions(emptyList())
        assertRejected(p.bob, forge(p.alice, listOf(gce, gce)), "Multiple GroupContextExtensions")
    }

    @Test
    fun removingTheCommitterIsRejected() {
        val p = pair()
        assertRejected(p.bob, forge(p.alice, listOf(Proposal.Remove(p.alice.leafIndex))), "must not remove its committer")
    }

    @Test
    fun twoRemovalsOfOneLeafAreRejected() {
        val p = pair()
        assertRejected(p.bob, forge(p.alice, listOf(Proposal.Remove(2), Proposal.Remove(2))), "Multiple Update/Remove")
    }

    @Test
    fun theCommittersOwnUpdateIsRejected() {
        val p = pair()
        val update = p.alice.proposeSigningKeyRotation()
        assertRejected(p.bob, forge(p.alice, listOf(update)), "committer's own Update")
    }

    @Test
    fun aReInitWithOtherProposalsIsRejected() {
        val p = pair()
        val reInit = Proposal.ReInit(ByteArray(32), 1, 1, emptyList())
        assertRejected(p.bob, forge(p.alice, listOf(reInit, Proposal.Remove(2))), "ReInit proposal must be committed alone")
    }

    @Test
    fun anExternalInitInAMemberCommitIsRejected() {
        val p = pair()
        assertRejected(p.bob, forge(p.alice, listOf(Proposal.ExternalInit(ByteArray(32)))), "Only an external commit")
    }

    @Test
    fun aProposalTypeSomeMemberDoesNotSupportIsRejected() {
        val p = pair()
        assertRejected(p.bob, forge(p.alice, listOf(Proposal.AppDataUpdate.update(0x8001, ByteArray(1)))), "does not support proposal type")
    }

    @Test
    fun anAddWithAForgedKeyPackageIsRejected() {
        val p = pair()
        val kp = keyPackage("dave").keyPackage
        val forged = kp.copy(signature = kp.signature.copyOf().also { it[0] = (it[0] + 1).toByte() })
        assertRejected(p.bob, forge(p.alice, listOf(Proposal.Add(forged))), "Invalid KeyPackage signature")
    }

    @Test
    fun anAddOfAMemberAlreadyInTheGroupIsRejected() {
        val p = pair()
        // A valid KeyPackage, but for a client already in the group: it shares Bob's signature key.
        val bobsKey =
            Ed25519KeyPair(
                p.bob.saveState().signingPrivateKey,
                p.alice
                    .members()
                    .first { it.first == p.bob.leafIndex }
                    .second.signatureKey,
            )
        val clone = MlsGroup.create("x".encodeToByteArray()).createKeyPackage("bob".encodeToByteArray(), ByteArray(0), leafSignatureKeyPair = bobsKey)
        assertRejected(p.bob, forge(p.alice, listOf(Proposal.Add(clone.keyPackage))), "Duplicate signature key")
    }

    @Test
    fun keyPackagesThatBreakLeafRulesAreRefusedLocally() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val unlisted =
            alice.createKeyPackage(
                "dave".encodeToByteArray(),
                ByteArray(0),
                leafExtensions = listOf(Extension(0x7777, ByteArray(1))),
            )
        assertFailsWith<IllegalArgumentException> { alice.proposeAdd(unlisted.keyPackage.toTlsBytes()) }

        val noBasic =
            alice.createKeyPackage(
                "erin".encodeToByteArray(),
                ByteArray(0),
                capabilities = Capabilities(credentials = emptyList()),
            )
        assertFailsWith<IllegalArgumentException> { alice.proposeAdd(noBasic.keyPackage.toTlsBytes()) }
    }

    @Test
    fun aTamperedUpdatePathIsRejected() {
        val p = pair()
        val honest = p.alice.stageCommit()
        p.alice.clearPendingCommit()
        val commit =
            Commit.decodeTls(
                com.vitorpamplona.mls.codec
                    .TlsReader(honest.commitBytes),
            )
        val path = commit.updatePath!!
        // Swap the first path node's key: the parent-hash chain no longer matches the signed leaf.
        val nodes = path.nodes.toMutableList().also { it[0] = it[0].copy(encryptionKey = ByteArray(32) { 5 }) }
        assertRejected(p.bob, forge(p.alice, emptyList(), path.copy(nodes = nodes)), "Parent hash verification failed")
    }
}
