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
import com.vitorpamplona.crypto.curve25519.Ed25519KeyPair
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.FramedContent
import com.vitorpamplona.mls.framing.Framing
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.PublicMessage
import com.vitorpamplona.mls.framing.Sender
import com.vitorpamplona.mls.framing.SenderType
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.framing.framedContent
import com.vitorpamplona.mls.messages.Commit
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.messages.ProposalOrRef
import com.vitorpamplona.mls.messages.UpdatePath
import com.vitorpamplona.mls.toHexKey
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.LeafNode
import com.vitorpamplona.mls.tree.LeafNodeSource
import com.vitorpamplona.mls.tree.Lifetime
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * One commit per validation rule, each breaking only that rule and sent by a
 * real member: signed with its key, MACed with the epoch's membership key.
 * Every other member and a [PublicGroup] view must refuse each one, for that
 * rule, and stay exactly where they were. The view is excused only from the
 * two checks that need the epoch's secrets.
 *
 * `docs/guide/validation.md` cites these cases by name, and
 * `ValidationTableSyncTest` keeps the two in step.
 */
class MaliciousMemberTest {
    private class World(
        val alice: MlsGroup,
        val bob: MlsGroup,
        val carol: MlsGroup,
    ) {
        /** Who must refuse the commit; a case that removes someone first takes them off. */
        val receivers = mutableListOf("bob" to bob, "carol" to carol)

        /** Proposals sent before the commit, which the view must see too. */
        val sent = mutableListOf<ByteArray>()
    }

    private fun bundle(
        name: String,
        capabilities: Capabilities = Capabilities(),
    ) = MlsGroup.createKeyPackage(name.encodeToByteArray(), capabilities = capabilities)

    private fun world(capabilities: Capabilities = Capabilities()): World {
        val alice = MlsGroup.create("alice".encodeToByteArray(), capabilities = capabilities)
        val b = bundle("bob", capabilities)
        val c = bundle("carol", capabilities)
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        return World(alice, MlsGroup.processWelcome(add.welcomeBytes!!, b), MlsGroup.processWelcome(add.welcomeBytes!!, c))
    }

    /**
     * A commit from [sender]'s seat. Everything is honest unless overridden:
     * the epoch and group, the sender's leaf, the signing key, the tags.
     */
    private fun forge(
        sender: MlsGroup,
        proposals: List<ProposalOrRef>,
        path: UpdatePath? = null,
        epoch: Long = sender.epoch,
        groupId: ByteArray = sender.groupId,
        senderLeaf: Int = sender.leafIndex,
        signingKey: ByteArray? = null,
        /** Replaces the signature outright, after signing. */
        signatureOverride: ByteArray? = null,
        confirmationTag: ByteArray = ByteArray(32),
        membershipTag: ByteArray? = null,
    ): ByteArray {
        val state = sender.saveState()
        val ctx = state.groupContext.toTlsBytes()
        val content = FramedContent(groupId, epoch, Sender(SenderType.MEMBER, senderLeaf), ByteArray(0), ContentType.COMMIT, Commit(proposals, path).toTlsBytes())
        val signature = signatureOverride ?: Framing.sign(signingKey ?: state.signingPrivateKey, WireFormat.PUBLIC_MESSAGE, content, ctx)
        val tag = membershipTag ?: Framing.membershipTag(state.epochSecrets.membershipKey, content, ctx, signature, confirmationTag)
        return MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, confirmationTag, tag)).toTlsBytes()
    }

    private fun inline(vararg p: Proposal) = p.map { ProposalOrRef.Inline(it) }

    /** alice's honest commit, re-framed with [confirmationTag] and a membership tag that matches it. */
    private fun honestButTagged(
        w: World,
        confirmationTag: (ByteArray) -> ByteArray,
    ): ByteArray {
        val honest =
            w.alice
                .stageCommit()
                .framedCommitBytes
                .also { w.alice.clearPendingCommit() }
        val pub = PublicMessage.decodeTls(TlsReader(MlsMessage.decodeTls(TlsReader(honest)).payload))
        val state = w.alice.saveState()
        val tag = confirmationTag(pub.confirmationTag!!)
        val membership = Framing.membershipTag(state.epochSecrets.membershipKey, pub.framedContent(), state.groupContext.toTlsBytes(), pub.signature, tag)
        return MlsMessage.fromPublicMessage(pub.copy(confirmationTag = tag, membershipTag = membership)).toTlsBytes()
    }

    /**
     * dave's KeyPackage with [leaf] and [edit] applied, re-signed so only the
     * edit is wrong ([resignLeaf] false keeps the leaf's old signature).
     */
    private fun keyPackage(
        resignLeaf: Boolean = true,
        leaf: (LeafNode) -> LeafNode = { it },
        edit: (MlsKeyPackage) -> MlsKeyPackage = { it },
    ): MlsKeyPackage {
        val b = bundle("dave")
        val edited = leaf(b.keyPackage.leafNode)
        val signed = if (resignLeaf) edited.copy(signature = MlsCryptoProvider.signWithLabel(b.signaturePrivateKey, "LeafNodeTBS", edited.encodeTbs())) else edited
        val kp = edit(b.keyPackage.copy(leafNode = signed))
        return kp.copy(signature = MlsCryptoProvider.signWithLabel(b.signaturePrivateKey, "KeyPackageTBS", kp.encodeTbs()))
    }

    private fun add(
        w: World,
        kp: MlsKeyPackage,
    ) = forge(w.alice, inline(Proposal.Add(kp)))

    /** [from] sends [proposal] by reference and every other member stages it; returns its ref. */
    private fun shared(
        w: World,
        from: MlsGroup,
        proposal: Proposal,
    ): ProposalOrRef {
        val message = from.proposalMessage(proposal).also { w.sent += it }
        for (g in listOf(w.alice, w.bob, w.carol)) if (g !== from) g.processMessage(message)
        return ProposalOrRef.Reference(
            w.alice
                .pendingProposalsSnapshot()
                .last()
                .proposalRef!!,
        )
    }

    /** dave's honest external commit, its proposal list replaced by [edit] and re-signed by dave. */
    private fun forgeExternal(
        w: World,
        edit: (List<ProposalOrRef>) -> List<ProposalOrRef>,
    ): ByteArray {
        val joined = MlsGroup.externalJoin(w.alice.groupInfoMessage(), "dave".encodeToByteArray())
        val pub = PublicMessage.decodeTls(TlsReader(MlsMessage.decodeTls(TlsReader(joined.framedCommitBytes)).payload))
        val honest = Commit.decodeTls(TlsReader(pub.content))
        val content = FramedContent(pub.groupId, pub.epoch, pub.sender, pub.authenticatedData, ContentType.COMMIT, Commit(edit(honest.proposals), honest.updatePath).toTlsBytes())
        val signature =
            Framing.sign(
                joined.group.saveState().signingPrivateKey,
                WireFormat.PUBLIC_MESSAGE,
                content,
                w.alice
                    .saveState()
                    .groupContext
                    .toTlsBytes(),
            )
        return MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, pub.confirmationTag, null)).toTlsBytes()
    }

    private fun leafOf(
        w: World,
        g: MlsGroup,
    ) = w.alice
        .members()
        .first { it.first == g.leafIndex }
        .second

    private class Case(
        val name: String,
        /** A substring of the refusal: proves the intended rule caught it. */
        val reason: String,
        /** False for the checks only a member can make (membership and confirmation tags). */
        val viewRefuses: Boolean = true,
        /** The members' leaf capabilities, for a case that needs them to support more. */
        val capabilities: Capabilities = Capabilities(),
        val build: (World) -> ByteArray,
    )

    private val cases =
        listOf(
            Case("signed by someone else", "signature") { w -> forge(w.alice, inline(), signingKey = Ed25519.generateKeyPair().privateKey) },
            Case("no signature", "signature missing") { w -> forge(w.alice, inline(), signatureOverride = ByteArray(0)) },
            Case("claims another member's leaf", "signature") { w -> forge(w.alice, inline(), senderLeaf = w.bob.leafIndex) },
            Case("sender leaf off the end of the tree", "leaf index") { w -> forge(w.alice, inline(), senderLeaf = 99) },
            Case("wrong epoch", "epoch") { w -> forge(w.alice, inline(), epoch = w.alice.epoch + 1) },
            Case("wrong group", "group") { w -> forge(w.alice, inline(), groupId = ByteArray(32) { 1 }) },
            Case("bad membership tag", "membership_tag", viewRefuses = false) { w -> forge(w.alice, inline(), membershipTag = ByteArray(32) { 7 }) },
            Case("no confirmation tag", "Confirmation tag missing") { w -> forge(w.alice, inline(), confirmationTag = ByteArray(0)) },
            Case("bad confirmation tag", "Confirmation tag", viewRefuses = false) { w -> honestButTagged(w) { t -> t.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() } } },
            Case("remove without a path", "required UpdatePath") { w -> forge(w.alice, inline(Proposal.Remove(w.carol.leafIndex))) },
            Case("empty commit without a path", "required UpdatePath") { w -> forge(w.alice, inline()) },
            Case("removes the committer", "must not remove its committer") { w -> forge(w.alice, inline(Proposal.Remove(w.alice.leafIndex))) },
            Case("removes a leaf off the end of the tree", "out of range") { w -> forge(w.alice, inline(Proposal.Remove(7))) },
            Case("removes a blank leaf", "blank leaf") { w ->
                // bob, in the middle of the tree, is removed honestly first, so his leaf is blank.
                val honest = w.alice.removeMember(w.bob.leafIndex)
                w.carol.processMessage(honest.framedCommitBytes)
                w.receivers.removeAll { it.first == "bob" }
                forge(w.alice, inline(Proposal.Remove(w.bob.leafIndex)))
            },
            Case("two removes of one leaf", "Multiple Update/Remove") { w -> forge(w.alice, inline(Proposal.Remove(w.carol.leafIndex), Proposal.Remove(w.carol.leafIndex))) },
            Case("the committer's own update", "committer's own Update") { w -> forge(w.alice, inline(w.alice.proposeSigningKeyRotation())) },
            Case("two updates from one member", "Multiple Update/Remove") { w ->
                listOf(shared(w, w.bob, w.bob.proposeSigningKeyRotation()), shared(w, w.bob, w.bob.proposeSigningKeyRotation())).let { forge(w.alice, it) }
            },
            Case("an update and a remove of one member", "Multiple Update/Remove") { w ->
                forge(w.alice, listOf(shared(w, w.bob, w.bob.proposeSigningKeyRotation())) + inline(Proposal.Remove(w.bob.leafIndex)))
            },
            Case("a self-remove and a remove of one member", "Multiple Update/Remove") { w ->
                forge(w.alice, listOf(shared(w, w.bob, Proposal.SelfRemove())) + inline(Proposal.Remove(w.bob.leafIndex)))
            },
            Case("the committer's own self-remove", "its own SelfRemove") { w -> forge(w.alice, inline(Proposal.SelfRemove())) },
            Case("an external commit without an external init", "exactly one ExternalInit") { w -> forgeExternal(w) { p -> p.filterNot { (it as? ProposalOrRef.Inline)?.proposal is Proposal.ExternalInit } } },
            Case("an external commit with two external inits", "exactly one ExternalInit") { w -> forgeExternal(w) { p -> p + p } },
            Case("an external commit that removes two members", "at most one leaf") { w -> forgeExternal(w) { p -> p + inline(Proposal.Remove(w.bob.leafIndex), Proposal.Remove(w.carol.leafIndex)) } },
            Case("an external commit that adds someone", "only ExternalInit, Remove and PreSharedKey") { w -> forgeExternal(w) { p -> p + inline(Proposal.Add(bundle("erin").keyPackage)) } },
            Case("group context extensions no member supports", "Unsupported extension type") { w ->
                forge(
                    w.alice,
                    inline(
                        Proposal.GroupContextExtensions(
                            listOf(
                                com.vitorpamplona.mls.tree
                                    .Extension(0xF0F2, ByteArray(1)),
                            ),
                        ),
                    ),
                )
            },
            Case("two group context extensions", "Multiple GroupContextExtensions") { w -> forge(w.alice, inline(Proposal.GroupContextExtensions(emptyList()), Proposal.GroupContextExtensions(emptyList()))) },
            Case("reinit with other proposals", "ReInit proposal must be committed alone") { w -> forge(w.alice, inline(Proposal.ReInit(ByteArray(32), 1, 1, emptyList()), Proposal.Remove(w.carol.leafIndex))) },
            Case("external init in a member commit", "Only an external commit") { w -> forge(w.alice, inline(Proposal.ExternalInit(ByteArray(32)))) },
            Case("a proposal type some member does not support", "does not support proposal type") { w -> forge(w.alice, inline(Proposal.Custom(0xF0F0, ByteArray(1)))) },
            Case("an add with a forged key package", "Invalid KeyPackage signature") { w ->
                val kp = bundle("dave").keyPackage
                forge(w.alice, inline(Proposal.Add(kp.copy(signature = kp.signature.copyOf().also { it[0] = (it[0] + 1).toByte() }))))
            },
            Case("an add whose leaf is not a key_package leaf", "leaf_node_source") { w ->
                add(w, keyPackage(resignLeaf = false, leaf = { it.copy(leafNodeSource = LeafNodeSource.UPDATE, lifetime = null) }))
            },
            Case("an add whose leaf signature is forged", "Invalid LeafNode signature") { w ->
                add(w, keyPackage(resignLeaf = false, leaf = { it.copy(signature = it.signature.copyOf().also { s -> s[0] = (s[0] + 1).toByte() }) }))
            },
            Case("an add whose leaf does not support MLS 1.0", "protocol version") { w ->
                add(w, keyPackage(leaf = { it.copy(capabilities = it.capabilities.copy(versions = listOf(2))) }))
            },
            Case("an add whose leaf does not support the group's suite", "ciphersuite 0x0001") { w ->
                add(w, keyPackage(leaf = { it.copy(capabilities = it.capabilities.copy(ciphersuites = listOf(2))) }))
            },
            Case("an add whose leaf does not support its own credential", "its own credential type") { w ->
                add(w, keyPackage(leaf = { it.copy(capabilities = it.capabilities.copy(credentials = emptyList())) }))
            },
            Case("an add with a credential the members do not support", "does not support credential type") { w ->
                add(w, keyPackage(leaf = { it.copy(credential = Credential.Custom(OTHER_CREDENTIAL, ByteArray(4)), capabilities = it.capabilities.copy(credentials = listOf(1, OTHER_CREDENTIAL))) }))
            },
            Case(
                "an add that does not support the members' credential",
                "used by leaf",
                capabilities = Capabilities(credentials = listOf(1, OTHER_CREDENTIAL)),
            ) { w ->
                add(w, keyPackage(leaf = { it.copy(credential = Credential.Custom(OTHER_CREDENTIAL, ByteArray(4)), capabilities = it.capabilities.copy(credentials = listOf(OTHER_CREDENTIAL))) }))
            },
            Case("an add that reuses a member's encryption key", "Duplicate encryption key") { w ->
                add(w, keyPackage(leaf = { it.copy(encryptionKey = leafOf(w, w.bob).encryptionKey) }))
            },
            Case("an add of a key package for another protocol version", "version") { w -> add(w, keyPackage(edit = { it.copy(version = 2) })) },
            Case("an add of a key package for another suite", "ciphersuite") { w -> add(w, keyPackage(edit = { it.copy(cipherSuite = 2) })) },
            Case("an add whose init key is its encryption key", "init_key equals") { w -> add(w, keyPackage(edit = { it.copy(initKey = it.leafNode.encryptionKey) })) },
            Case("an add of a member already in the group", "Duplicate signature key") { w ->
                val bobsKey =
                    Ed25519KeyPair(
                        w.bob.saveState().signingPrivateKey,
                        w.alice
                            .members()
                            .first { it.first == w.bob.leafIndex }
                            .second.signatureKey,
                    )
                forge(w.alice, inline(Proposal.Add(MlsGroup.createKeyPackage("bob".encodeToByteArray(), leafSignatureKeyPair = bobsKey).keyPackage)))
            },
            Case("two adds of one client", "Duplicate") { w ->
                val kp = bundle("dave").keyPackage
                forge(w.alice, inline(Proposal.Add(kp), Proposal.Add(kp)))
            },
            Case("a psk with a short nonce", "psk_nonce") { w -> forge(w.alice, inline(Proposal.Psk(PreSharedKeyId.External("x".encodeToByteArray(), ByteArray(3))))) },
            Case("the same psk twice", "Multiple PreSharedKey") { w ->
                // Every member holds the PSK, so only the repetition is wrong.
                for (g in listOf(w.alice, w.bob, w.carol)) g.registerPsk("x".encodeToByteArray(), ByteArray(32) { 4 })
                val psk = Proposal.Psk(PreSharedKeyId.External("x".encodeToByteArray(), ByteArray(32)))
                forge(w.alice, inline(psk, psk))
            },
            Case("a branch psk outside a new group's first commit", "new group's first commit") { w ->
                forge(w.alice, inline(Proposal.Psk(PreSharedKeyId.Resumption(PreSharedKeyId.USAGE_BRANCH, w.alice.groupId, 0, ByteArray(32)))))
            },
            Case("a reinit to an older protocol version", "older protocol version") { w -> forge(w.alice, inline(Proposal.ReInit(ByteArray(32), 0, 1, emptyList()))) },
            Case("a grease proposal", "GREASE proposal type") { w -> forge(w.alice, inline(Proposal.Custom(0x0A0A, ByteArray(1)))) },
            Case("a reference to an unknown proposal", "unknown proposal") { w -> forge(w.alice, listOf(ProposalOrRef.Reference(ByteArray(32) { 9 }))) },
            Case("a tampered update path", "Parent hash verification failed") { w ->
                val honest = w.alice.stageCommit().also { w.alice.clearPendingCommit() }
                val path = Commit.decodeTls(TlsReader(honest.commitBytes)).updatePath!!
                forge(w.alice, inline(), path.copy(nodes = path.nodes.toMutableList().also { it[0] = it[0].copy(encryptionKey = ByteArray(32) { 5 }) }))
            },
            Case("an update path that reuses the committer's encryption key", "reuses") { w ->
                val honest = w.alice.stageCommit().also { w.alice.clearPendingCommit() }
                val path = Commit.decodeTls(TlsReader(honest.commitBytes)).updatePath!!
                val oldKey =
                    w.alice
                        .members()
                        .first { it.first == w.alice.leafIndex }
                        .second.encryptionKey
                val unsigned = path.leafNode.copy(encryptionKey = oldKey)
                // Re-signed, so only the key reuse is wrong.
                val signature = MlsCryptoProvider.signWithLabel(w.alice.saveState().signingPrivateKey, "LeafNodeTBS", unsigned.encodeTbs(w.alice.groupId, w.alice.leafIndex))
                forge(w.alice, inline(), path.copy(leafNode = unsigned.copy(signature = signature)))
            },
        )

    private fun MlsGroup.fingerprint() = epochAuthenticator.toHexKey() + exportTreeBytes().toHexKey() + pendingProposalsSnapshot().size

    @Test
    fun everyMemberAndTheViewRefuseEveryViolation() {
        val problems = mutableListOf<String>()
        for (case in cases) {
            val w = world(case.capabilities)
            val commit = case.build(w)
            for ((who, group) in w.receivers) {
                val before = group.fingerprint()
                val error = runCatching { group.processMessage(commit) }.exceptionOrNull()
                when {
                    error == null -> problems += "${case.name}: $who ACCEPTED it"
                    error !is IllegalArgumentException && error !is IllegalStateException -> problems += "${case.name}: $who threw $error"
                    !error.message.orEmpty().contains(case.reason, ignoreCase = true) -> problems += "${case.name}: $who refused for another reason: ${error.message}"
                    group.fingerprint() != before -> problems += "${case.name}: $who refused it but its state changed"
                }
            }
            val view = PublicGroup.fromGroupInfo(w.alice.groupInfoMessage())
            for (m in w.sent) view.processMessage(m)
            val before = view.saveState().encodeTls().toHexKey()
            val error = runCatching { view.processMessage(commit) }.exceptionOrNull()
            if (case.viewRefuses) {
                when {
                    error == null -> problems += "${case.name}: the view ACCEPTED it"
                    !error.message.orEmpty().contains(case.reason, ignoreCase = true) -> problems += "${case.name}: the view refused for another reason: ${error.message}"
                    view.saveState().encodeTls().toHexKey() != before -> problems += "${case.name}: the view refused it but changed"
                }
            }
        }
        if (problems.isNotEmpty()) fail(problems.joinToString("\n"))
    }

    /** Receivers no longer check an Add's lifetime (an old commit stays valid); its committer does. */
    @Test
    fun theCommitterRefusesAnExpiredKeyPackage() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val expired = MlsGroup.createKeyPackage("dave".encodeToByteArray(), lifetime = Lifetime(0, 1))
        val error = assertFailsWith<IllegalArgumentException> { alice.proposeAdd(expired.keyPackage.toTlsBytes()) }
        assertContains(error.message.orEmpty(), "lifetime")
    }

    @Test
    fun theCaseNamesAreUnique() = assertTrue(cases.map { it.name }.toSet().size == cases.size)

    private companion object {
        /** A credential type no default leaf lists. */
        const val OTHER_CREDENTIAL = 0xF0F1
    }
}
