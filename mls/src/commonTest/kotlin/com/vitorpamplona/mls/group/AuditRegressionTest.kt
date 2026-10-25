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

import com.vitorpamplona.mls.InternalMlsApi
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
import com.vitorpamplona.mls.platform.TimeUtils
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Lifetime
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Regressions for the bugs an audit of the changes since 1.2.0 found. */
@OptIn(InternalMlsApi::class)
class AuditRegressionTest {
    private val now = TimeUtils.now()
    private val aWeek = 7 * 24 * 3600L

    private fun bundle(
        name: String,
        lifetime: Lifetime? = null,
    ) = MlsGroup.createKeyPackage(name.encodeToByteArray(), lifetime = lifetime)

    /** A KeyPackage valid now that expires tomorrow. */
    private fun shortLived(name: String) = bundle(name, Lifetime(now - 60, now + 24 * 3600))

    private class Trio(
        val alice: MlsGroup,
        val bob: MlsGroup,
        val carol: MlsGroup,
    )

    private fun trio(): Trio {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = bundle("bob")
        val c = bundle("carol")
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        return Trio(alice, MlsGroup.processWelcome(add.welcomeBytes!!, b), MlsGroup.processWelcome(add.welcomeBytes!!, c))
    }

    private fun assertSameEpoch(vararg groups: MlsGroup) {
        for (g in groups) assertContentEquals(groups.first().epochAuthenticator, g.epochAuthenticator, "epoch authenticators diverged")
    }

    // --- A KeyPackage lifetime is the committer's to judge ---

    @Test
    fun aMemberPastAKeyPackagesLifetimeStillAppliesTheCommitThatAddedIt() {
        val t = trio()
        t.bob.clock = { now + aWeek } // bob is reading a week-old backlog
        val add = t.alice.addMember(shortLived("dave").keyPackage.toTlsBytes())
        t.bob.processMessage(add.framedCommitBytes)
        t.carol.processMessage(add.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob, t.carol)
    }

    @Test
    fun aLateStandaloneAddIsStillStagedSoTheCommitReferencingItResolves() {
        val t = trio()
        t.bob.clock = { now + aWeek }
        val proposal = t.alice.proposalMessage(t.alice.proposeAdd(shortLived("dave").keyPackage.toTlsBytes()))
        assertIs<ProcessedMessage.StagedProposal>(t.bob.processMessage(proposal))
        t.carol.processMessage(proposal)
        val commit = t.carol.commit() // carol's clock is fine: the Add goes in by reference
        t.alice.processMessage(commit.framedCommitBytes)
        t.bob.processMessage(commit.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob, t.carol)
        assertEquals(4, t.bob.members().size)
    }

    // --- A committer leaves out what it cannot commit ---

    @Test
    fun aCommitLeavesOutAPskTheCommitterWasNeverGiven() {
        val t = trio()
        val id = "only bob has this".encodeToByteArray()
        t.bob.registerPsk(id, ByteArray(32) { 1 })
        val psk = t.bob.proposalMessage(t.bob.proposePsk(id))
        t.alice.processMessage(psk)
        t.carol.processMessage(psk)
        val commit = t.alice.commit() // used to fail with "PSK not available" for the rest of the epoch
        t.bob.processMessage(commit.framedCommitBytes)
        t.carol.processMessage(commit.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob, t.carol)
    }

    @Test
    fun aCommitLeavesOutAnAddWhoseKeyPackageExpiredInThePool() {
        val t = trio()
        val proposal = t.alice.proposalMessage(t.alice.proposeAdd(shortLived("dave").keyPackage.toTlsBytes()))
        t.bob.processMessage(proposal)
        t.carol.processMessage(proposal)
        t.bob.clock = { now + aWeek } // bob commits after the KeyPackage expired
        val commit = t.bob.commit()
        t.alice.processMessage(commit.framedCommitBytes)
        t.carol.processMessage(commit.framedCommitBytes)
        assertSameEpoch(t.alice, t.bob, t.carol)
        assertEquals(3, t.bob.members().size, "the expired Add was left out")
    }

    // --- A reference only names a proposal that travelled ---

    @Test
    fun aCommitCannotReferenceAProposalWeStagedButNeverSent() {
        val t = trio()
        t.carol.proposeRemove(t.bob.leafIndex) // staged, never sent: nobody else holds it
        val guessedRef = Framing.proposalRef(Proposal.Remove(t.bob.leafIndex).toTlsBytes())

        val state = t.alice.saveState()
        val ctx = state.groupContext.toTlsBytes()
        val body = Commit(listOf(ProposalOrRef.Reference(guessedRef)), null).toTlsBytes()
        val content = FramedContent(t.alice.groupId, t.alice.epoch, Sender(SenderType.MEMBER, t.alice.leafIndex), ByteArray(0), ContentType.COMMIT, body)
        val signature = Framing.sign(state.signingPrivateKey, WireFormat.PUBLIC_MESSAGE, content, ctx)
        val tag = ByteArray(32)
        val membershipTag = Framing.membershipTag(state.epochSecrets.membershipKey, content, ctx, signature, tag)
        val forged = MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, tag, membershipTag)).toTlsBytes()

        val error = assertFailsWith<IllegalArgumentException> { t.carol.processMessage(forged) }
        assertTrue(error.message.orEmpty().contains("unknown proposal"), "got '${error.message}'")
    }

    // --- What our next commit does to our own leaf survives a restart ---

    @Test
    fun aStagedKeyRotationSurvivesARestart() {
        val t = trio()
        val before =
            t.alice
                .members()
                .first { it.first == t.alice.leafIndex }
                .second.signatureKey
        t.alice.proposeSigningKeyRotation()
        val restored = MlsGroup.restore(MlsGroupState.decodeTls(t.alice.saveState().encodeTls()))
        val commit = restored.commit()
        t.bob.processMessage(commit.framedCommitBytes)
        val after =
            t.bob
                .members()
                .first { it.first == restored.leafIndex }
                .second.signatureKey
        assertFalse(before.contentEquals(after), "the rotation was lost on restart")
        assertSameEpoch(restored, t.bob)
        assertEquals(
            "rotated",
            t.bob
                .decrypt(restored.encrypt("rotated".encodeToByteArray()))
                .content
                .decodeToString(),
        )
    }

    @Test
    fun aStagedAdvertisementSurvivesARestart() {
        val t = trio()
        val leaf =
            t.alice
                .members()
                .first { it.first == t.alice.leafIndex }
                .second
        val advertised = Capabilities(credentials = leaf.capabilities.credentials, extensions = leaf.capabilities.extensions + 0xF0B0)
        t.alice.advertiseInNextCommit(advertised, leaf.extensions)
        val restored = MlsGroup.restore(MlsGroupState.decodeTls(t.alice.saveState().encodeTls()))
        val commit = restored.commit()
        t.bob.processMessage(commit.framedCommitBytes)
        val now =
            t.bob
                .members()
                .first { it.first == restored.leafIndex }
                .second.capabilities
        assertTrue(0xF0B0 in now.extensions, "the advertisement was lost on restart")
    }
}
