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
package com.vitorpamplona.mls.interop

import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.messages.CommitResult
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.toHexKey
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Extension
import kotlin.random.Random

/**
 * Passive-client vectors AUTHORED by mls-kmp, in the mlswg
 * `passive-client-*` format.
 *
 * The RFC vectors prove mls-kmp can follow a group another implementation
 * runs. These prove the converse: a group of mls-kmp members goes through
 * every kind of epoch change — commits with and without proposals, as
 * PublicMessage and PrivateMessage, proposals by reference from several
 * members, Adds, Removes, Updates, GroupContextExtensions, external and
 * resumption PSKs, external joins and resyncs — while a passive member that
 * never sends records what it receives. Any implementation that replays the
 * result as that passive member (`tools/tsmls-vector-gen/verify-passive-client.mjs`
 * does for ts-mls) accepts exactly what mls-kmp sends.
 */
internal object MlsKmpAuthoredVectors {
    private val pskId = "mls-kmp external psk".encodeToByteArray()

    /** A custom proposal type every leaf advertises, so commits can carry one. */
    const val CUSTOM_PROPOSAL = 0xF0F0
    private val caps = Capabilities(proposals = listOf(CUSTOM_PROPOSAL))
    private val psk = ByteArray(32) { (it * 7 + 3).toByte() }

    /** One scenario: the members, the passive member's KeyPackage, and the epochs recorded since it joined. */
    private class Scenario(
        val description: String,
    ) {
        val members = mutableListOf<MlsGroup>()
        val epochs = mutableListOf<PassiveClientEpoch>()
        private val proposals = mutableListOf<String>()
        private var names = 0

        fun keyPackage(name: String = "member-${names++}"): KeyPackageBundle = MlsGroup.create(name.encodeToByteArray()).createKeyPackage(name.encodeToByteArray(), ByteArray(0), capabilities = caps)

        /** Deliver a standalone proposal message from [from] to every other member. */
        fun propose(
            from: MlsGroup,
            message: ByteArray,
        ) {
            for (m in members) if (m !== from) m.processMessage(message)
            proposals.add(message.toHexKey())
        }

        /** [committer] commits; everyone else processes it; joiners join; the epoch is recorded. */
        fun commit(
            committer: MlsGroup,
            joiners: List<KeyPackageBundle> = emptyList(),
            build: (MlsGroup) -> CommitResult = { it.commit() },
        ) {
            val result = build(committer)
            deliver(committer, result.framedCommitBytes)
            for (j in joiners) members.add(MlsGroup.processWelcome(result.welcomeBytes!!, j).also { it.registerPsk(pskId, psk) })
        }

        /** A non-member joins with an external commit built from [groupInfoFrom]'s GroupInfo. */
        fun externalJoin(
            groupInfoFrom: MlsGroup,
            identity: String,
            replacing: MlsGroup? = null,
        ) {
            val join =
                MlsGroup.externalJoin(
                    groupInfoFrom.groupInfoMessage(),
                    identity.encodeToByteArray(),
                    capabilities = caps,
                    resyncLeafIndex = replacing?.leafIndex,
                )
            if (replacing != null) members.remove(replacing)
            deliver(null, join.framedCommitBytes)
            members.add(join.group.also { it.registerPsk(pskId, psk) })
        }

        private fun deliver(
            committer: MlsGroup?,
            framed: ByteArray,
        ) {
            for (m in members.toList()) {
                if (m === committer) continue
                m.processMessage(framed)
                if (!m.isLocalMember()) members.remove(m)
            }
            val reference = committer ?: members.first()
            epochs.add(PassiveClientEpoch(proposals.toList(), framed.toHexKey(), reference.epochAuthenticator.toHexKey()))
            proposals.clear()
        }

        fun member(identity: String): MlsGroup = members.first { it.myIdentityHex() == identity.encodeToByteArray().toHexKey() }
    }

    /**
     * Start a group of alice, bob and carol plus the passive member, which
     * alice adds together with the others so its Welcome covers several joiners.
     */
    private fun start(
        description: String,
        includeTreeInWelcome: Boolean,
    ): Triple<Scenario, PassiveClientVector, () -> PassiveClientVector> {
        val s = Scenario(description)
        val alice = MlsGroup.create("alice".encodeToByteArray(), capabilities = caps)
        val bob = s.keyPackage("bob")
        val carol = s.keyPackage("carol")
        val passive = s.keyPackage("passive")
        val add =
            alice
                .apply {
                    proposeAdd(bob.keyPackage.toTlsBytes())
                    proposeAdd(passive.keyPackage.toTlsBytes())
                    proposeAdd(carol.keyPackage.toTlsBytes())
                }.commit(includeRatchetTreeInWelcome = includeTreeInWelcome)
        val tree = if (includeTreeInWelcome) null else alice.exportTreeBytes()
        s.members.add(alice)
        s.members.add(MlsGroup.processWelcome(add.welcomeBytes!!, bob, ratchetTree = tree))
        s.members.add(MlsGroup.processWelcome(add.welcomeBytes!!, carol, ratchetTree = tree))
        for (m in s.members) m.registerPsk(pskId, psk)

        val header =
            PassiveClientVector(
                cipherSuite = 1,
                description = description,
                externalPsks = listOf(PassiveClientPsk(pskId.toHexKey(), psk.toHexKey())),
                keyPackage = MlsMessage(wireFormat = WireFormat.KEY_PACKAGE, payload = passive.keyPackage.toTlsBytes()).toTlsBytes().toHexKey(),
                // The vectors carry the raw Ed25519 seed; ours is seed || public key.
                signaturePriv = passive.signaturePrivateKey.copyOf(32).toHexKey(),
                encryptionPriv = passive.encryptionPrivateKey.toHexKey(),
                initPriv = passive.initPrivateKey.toHexKey(),
                welcome = add.welcomeBytes!!.toHexKey(),
                ratchetTree = tree?.toHexKey(),
                initialEpochAuthenticator = alice.epochAuthenticator.toHexKey(),
            )
        return Triple(s, header) { header.copy(epochs = s.epochs.toList()) }
    }

    /** One epoch change of every kind, in a fixed order. */
    private fun scripted(includeTreeInWelcome: Boolean): PassiveClientVector {
        val (s, _, finish) =
            start(
                if (includeTreeInWelcome) "mls-kmp: every commit shape" else "mls-kmp: every commit shape, ratchet tree out of band",
                includeTreeInWelcome,
            )
        val alice = s.member("alice")
        val bob = s.member("bob")
        val carol = s.member("carol")

        // A commit with no proposals, then one as a PrivateMessage with authenticated data and padding.
        s.commit(bob)
        s.commit(carol) { it.commit(authenticatedData = "aad".encodeToByteArray(), wireFormat = WireFormat.PRIVATE_MESSAGE, paddingLength = 16) }

        // An Update by reference, committed by someone else.
        s.propose(bob, bob.proposalMessage(bob.proposeSigningKeyRotation()))
        s.commit(alice)

        // An inline Add, then a Remove by reference as a PrivateMessage.
        val dave = s.keyPackage("dave")
        s.commit(alice, listOf(dave)) { it.apply { proposeAdd(dave.keyPackage.toTlsBytes()) }.commit() }
        s.propose(carol, carol.proposalMessage(Proposal.Remove(s.member("dave").leafIndex), WireFormat.PRIVATE_MESSAGE))
        s.commit(bob)

        // An Add by reference.
        val erin = s.keyPackage("erin")
        s.propose(alice, alice.proposalMessage(Proposal.Add(erin.keyPackage)))
        s.commit(carol, listOf(erin))

        // GroupContextExtensions by reference: required_capabilities naming BasicCredential.
        val required =
            TlsWriter().apply {
                putOpaqueVarInt(ByteArray(0))
                putOpaqueVarInt(ByteArray(0))
                putOpaqueVarInt(byteArrayOf(0, 1))
            }
        s.propose(bob, bob.proposalMessage(Proposal.GroupContextExtensions(listOf(Extension(MlsGroup.REQUIRED_CAPABILITIES_EXTENSION_TYPE, required.toByteArray())))))
        s.commit(alice)

        // An external PSK, then a resumption PSK of the previous epoch.
        s.commit(alice) { it.apply { proposePsk(pskId) }.commit() }
        s.commit(bob) { it.apply { proposeResumptionPsk(it.epoch - 1) }.commit() }

        // An external join, then a member resyncing its own leaf.
        s.externalJoin(carol, "frank")
        s.externalJoin(alice, "bob", replacing = bob)

        // Several members' proposals by reference in one commit, plus an inline Add.
        val newBob = s.member("bob")
        s.propose(carol, carol.proposalMessage(carol.proposeSigningKeyRotation(), WireFormat.PRIVATE_MESSAGE))
        s.propose(s.member("erin"), s.member("erin").proposalMessage(Proposal.Remove(s.member("frank").leafIndex)))
        val gina = s.keyPackage("gina")
        s.commit(alice, listOf(gina)) { it.apply { proposeAdd(gina.keyPackage.toTlsBytes()) }.commit() }

        // A custom proposal type by reference, then inline.
        s.propose(carol, carol.proposalMessage(Proposal.Custom(CUSTOM_PROPOSAL, "by reference".encodeToByteArray())))
        s.commit(alice) { it.apply { proposeCustom(CUSTOM_PROPOSAL, "inline".encodeToByteArray()) }.commit() }

        // An inline Remove as a PrivateMessage, then a newcomer's first commit.
        s.commit(newBob) { it.apply { proposeRemove(s.member("erin").leafIndex) }.commit(wireFormat = WireFormat.PRIVATE_MESSAGE) }
        s.commit(s.member("gina"))
        return finish()
    }

    /** A long random run of adds, removes, updates and empty commits from random members. */
    private fun random(
        seed: Int,
        epochs: Int,
    ): PassiveClientVector {
        val (s, _, finish) = start("mls-kmp: random run (seed $seed)", includeTreeInWelcome = true)
        val rnd = Random(seed)
        repeat(epochs) {
            val committer = s.members[rnd.nextInt(s.members.size)]
            when (rnd.nextInt(6)) {
                0 -> {
                    val joiner = s.keyPackage()
                    s.commit(committer, listOf(joiner)) { it.apply { proposeAdd(joiner.keyPackage.toTlsBytes()) }.commit() }
                }

                1 -> {
                    val others = s.members.filter { it !== committer }
                    if (s.members.size > 3) {
                        val target = others[rnd.nextInt(others.size)]
                        s.commit(committer) { it.apply { proposeRemove(target.leafIndex) }.commit() }
                    } else {
                        s.commit(committer)
                    }
                }

                2 -> {
                    val proposer = s.members.filter { it !== committer }.let { it[rnd.nextInt(it.size)] }
                    s.propose(proposer, proposer.proposalMessage(proposer.proposeSigningKeyRotation(), if (rnd.nextBoolean()) WireFormat.PRIVATE_MESSAGE else WireFormat.PUBLIC_MESSAGE))
                    s.commit(committer)
                }

                3 -> {
                    s.commit(committer) { it.commit(wireFormat = WireFormat.PRIVATE_MESSAGE) }
                }

                4 -> {
                    if (s.members.size > 3) {
                        val others = s.members.filter { it !== committer }
                        val proposer = others[rnd.nextInt(others.size)]
                        val target = others.filter { it !== proposer }.let { it[rnd.nextInt(it.size)] }
                        s.propose(proposer, proposer.proposalMessage(Proposal.Remove(target.leafIndex)))
                    }
                    s.commit(committer)
                }

                else -> {
                    s.commit(committer)
                }
            }
        }
        return finish()
    }

    /**
     * A few epochs, then a ReInit (or nothing, for a branch), then the
     * successor group the passive member joins with a fresh KeyPackage.
     */
    private fun successor(usage: String): PassiveClientVector {
        val (s, _, finish) = start("mls-kmp: $usage successor group", includeTreeInWelcome = true)
        val alice = s.member("alice")
        val bob = s.member("bob")
        s.commit(bob)
        s.propose(bob, bob.proposalMessage(bob.proposeSigningKeyRotation()))
        s.commit(alice)
        if (usage == "reinit") {
            s.commit(alice) { it.apply { proposeReInit(newGroupId = "mls-kmp reinit".encodeToByteArray(), newExtensions = it.extensions) }.commit() }
        }
        val passive = s.keyPackage("passive")
        val others = s.members.filter { it !== alice && (usage == "reinit" || it === bob) }.map { it to s.keyPackage(it.memberName()) }
        val packages = listOf(passive.keyPackage.toTlsBytes()) + others.map { it.second.keyPackage.toTlsBytes() }
        val result = if (usage == "reinit") alice.reinit(packages) else alice.branch(packages)
        // The other members follow too, so the scenario is the real thing.
        for ((member, kp) in others) MlsGroup.joinSuccessor(result.commit.welcomeBytes!!, kp, predecessor = member)
        return finish().copy(
            successor =
                PassiveClientSuccessor(
                    usage = usage,
                    keyPackage = MlsMessage(wireFormat = WireFormat.KEY_PACKAGE, payload = passive.keyPackage.toTlsBytes()).toTlsBytes().toHexKey(),
                    signaturePriv = passive.signaturePrivateKey.copyOf(32).toHexKey(),
                    encryptionPriv = passive.encryptionPrivateKey.toHexKey(),
                    initPriv = passive.initPrivateKey.toHexKey(),
                    welcome = result.commit.welcomeBytes!!.toHexKey(),
                    epochAuthenticator = result.group.epochAuthenticator.toHexKey(),
                ),
        )
    }

    private fun MlsGroup.memberName(): String = (members().first { it.first == leafIndex }.second.credential as com.vitorpamplona.mls.tree.Credential.Basic).identity.decodeToString()

    fun generate(): List<PassiveClientVector> =
        listOf(
            scripted(includeTreeInWelcome = true),
            scripted(includeTreeInWelcome = false),
            random(seed = 9420, epochs = 60),
            successor("reinit"),
            successor("branch"),
        )
}
