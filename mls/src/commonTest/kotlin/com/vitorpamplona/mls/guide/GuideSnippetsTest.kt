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
package com.vitorpamplona.mls.guide

import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.group.MlsGroupState
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.group.ProcessedMessage
import com.vitorpamplona.mls.group.PublicGroup
import com.vitorpamplona.mls.group.WireFormatPolicy
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.ProposalType
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Credential
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The code in `docs/guide`. Every Kotlin block there is a `// region` of this
 * file, copied verbatim; `GuideSnippetsSyncTest` fails when a block and its
 * region differ. So the guide compiles, and its examples run, in every build.
 *
 * Regions hold what a reader should see; the assertions around them check it
 * did what the guide says.
 */
class GuideSnippetsTest {
    /** Stands in for the application's network, store and UI. */
    private val published = mutableListOf<ByteArray>()

    private fun publish(bytes: ByteArray) {
        published += bytes
    }

    private val shown = mutableListOf<String>()

    private fun show(text: String) {
        shown += text
    }

    private fun keyPackageOf(name: String) = MlsGroup.createKeyPackage(name.encodeToByteArray())

    @Test
    fun keyPackages() {
        // region key-package
        val bundle = MlsGroup.createKeyPackage(identity = "bob".encodeToByteArray())
        publish(bundle.keyPackage.toTlsBytes()) // what others add bob with
        val stored: ByteArray = bundle.encodeTls() // keep it, encrypted: it holds private keys
        // endregion

        // region key-package-restore
        val restored = KeyPackageBundle.decodeTls(stored)
        // endregion
        assertEquals(bundle, restored)
        assertContentEquals(bundle.initPrivateKey, restored.initPrivateKey)
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val bob = MlsGroup.processWelcome(alice.addMember(published.last()).welcomeBytes!!, restored)
        assertContentEquals(alice.epochAuthenticator, bob.epochAuthenticator)
    }

    @Test
    fun createAndAdd() {
        val bob = keyPackageOf("bob")
        val carol = keyPackageOf("carol")
        val bobKeyPackageBytes = bob.keyPackage.toTlsBytes()
        val carolKeyPackageBytes = carol.keyPackage.toTlsBytes()

        // region create-group
        val alice = MlsGroup.create(identity = "alice".encodeToByteArray())
        // endregion

        // region add-members
        val result = alice.addMembers(listOf(bobKeyPackageBytes, carolKeyPackageBytes))
        publish(result.framedCommitBytes) // to the members already in the group: none yet
        publish(result.welcomeBytes!!) // to bob and carol
        // endregion

        assertEquals(3, alice.members().size)
        assertEquals(1L, alice.epoch)
    }

    @Test
    fun joiningFromAWelcome() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val bundle = keyPackageOf("bob")
        val welcomeBytes = alice.addMember(bundle.keyPackage.toTlsBytes()).welcomeBytes!!

        // region join-welcome
        val bob = MlsGroup.processWelcome(welcomeBytes, bundle)
        // endregion
        assertContentEquals(alice.epochAuthenticator, bob.epochAuthenticator)

        val carolBundle = keyPackageOf("carol")
        val secondWelcome = alice.addMember(carolBundle.keyPackage.toTlsBytes()).welcomeBytes!!
        // region stage-welcome
        val staged = MlsGroup.stageWelcome(secondWelcome, carolBundle)
        val inviter = (staged.welcomer.credential as Credential.Basic).identity.decodeToString()
        val everyone = staged.members().map { (_, leaf) -> (leaf.credential as Credential.Basic).identity.decodeToString() }
        val carol = if (inviter == "alice" && "mallory" !in everyone) staged.join() else null
        // endregion
        assertEquals(listOf("alice", "bob", "carol"), everyone)
        assertContentEquals(alice.epochAuthenticator, carol!!.epochAuthenticator)

        val daveBundle = keyPackageOf("dave")
        // region welcome-without-tree
        alice.proposeAdd(daveBundle.keyPackage.toTlsBytes())
        val commit = alice.commit(includeRatchetTreeInWelcome = false)
        val treeBytes = alice.exportTreeBytes() // deliver it some other way
        val dave = MlsGroup.processWelcome(commit.welcomeBytes!!, daveBundle, ratchetTree = treeBytes)
        // endregion
        assertContentEquals(alice.epochAuthenticator, dave.epochAuthenticator)
    }

    @Test
    fun joiningByExternalCommit() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        // region group-info
        val groupInfoBytes = alice.groupInfoMessage() // signed; carries the tree and external_pub
        publish(groupInfoBytes)
        // endregion

        // region external-join
        val joined = MlsGroup.externalJoin(groupInfoBytes, identity = "zara".encodeToByteArray())
        val zara = joined.group
        publish(joined.framedCommitBytes) // every member processes it
        // endregion
        alice.processMessage(joined.framedCommitBytes)
        assertContentEquals(alice.epochAuthenticator, zara.epochAuthenticator)

        // region external-resync
        val again = MlsGroup.externalJoin(alice.groupInfoMessage(), identity = "zara".encodeToByteArray(), resyncLeafIndex = zara.leafIndex)
        // endregion
        alice.processMessage(again.framedCommitBytes)
        assertContentEquals(alice.epochAuthenticator, again.group.epochAuthenticator)
    }

    /** alice and bob in one group. */
    private fun pair(policy: MlsGroupPolicy = MlsGroupPolicy.Permissive): Pair<MlsGroup, MlsGroup> {
        val alice = MlsGroup.create("alice".encodeToByteArray(), policy = policy)
        val bundle = MlsGroup.createKeyPackage("bob".encodeToByteArray(), policy)
        return alice to MlsGroup.processWelcome(alice.addMember(bundle.keyPackage.toTlsBytes()).welcomeBytes!!, bundle, policy)
    }

    @Test
    fun applicationMessages() {
        val (alice, bob) = pair()
        // region send-message
        val ciphertext = alice.encrypt("hello".encodeToByteArray())
        publish(ciphertext)
        // endregion

        // region receive-message
        when (val received = bob.processMessage(ciphertext)) {
            is ProcessedMessage.Application -> show(received.message.content.decodeToString())
            else -> Unit
        }
        // endregion

        // region authenticated-data
        val tagged =
            alice.encrypt(
                plaintext = "hello again".encodeToByteArray(),
                authenticatedData = "thread:42".encodeToByteArray(), // readable by the server, but tamper-proof
                paddingLength = 64, // hides the message length
            )
        // endregion
        val opened = assertIs<ProcessedMessage.Application>(bob.processMessage(tagged)).message
        assertEquals("hello again", opened.content.decodeToString())
        assertEquals("thread:42", opened.authenticatedData.decodeToString())

        val lateBytes = alice.encrypt("sent before the commit".encodeToByteArray())
        alice.processMessage(bob.commit().framedCommitBytes)
        // region late-message
        // Sealed in an epoch we already left: its sender had not seen the latest commit yet.
        val late = bob.decryptFormerEpoch(lateBytes)
        // endregion
        assertEquals("sent before the commit", late.content.decodeToString())
    }

    @Test
    fun processingEverything() {
        val (alice, bob) = pair()
        val fromAlice = listOf(alice.encrypt("hi".encodeToByteArray()), alice.proposalMessage(alice.proposeSigningKeyRotation()))
        val group = bob
        for (bytes in fromAlice + bob.stageCommit().framedCommitBytes) {
            // region process-message
            when (val result = group.processMessage(bytes)) {
                is ProcessedMessage.Application -> show(result.message.content.decodeToString())
                is ProcessedMessage.StagedProposal -> Unit // waits in the pending pool for a commit
                is ProcessedMessage.AppliedCommit -> if (result.removedSelf) show("removed") else show("now at epoch ${result.epoch}")
            }
            // endregion
        }
        assertEquals(listOf("hi", "now at epoch 2"), shown)
    }

    // region capabilities
    object WithSelfRemoveAndPins : MlsGroupPolicy {
        // A proposal type beyond RFC 9420's own can only be committed once every
        // member's leaf lists it; the policy's default leaf capabilities do that.
        override val defaultLeafCapabilities = Capabilities(proposals = listOf(ProposalType.SELF_REMOVE.value, 0xF0F0))
    }
    // endregion

    @Test
    fun membership() {
        val (alice, bob) = pair(WithSelfRemoveAndPins)
        val carol = MlsGroup.createKeyPackage("carol".encodeToByteArray(), WithSelfRemoveAndPins)
        val carolGroup = MlsGroup.processWelcome(alice.addMember(carol.keyPackage.toTlsBytes()).also { bob.processMessage(it.framedCommitBytes) }.welcomeBytes!!, carol, WithSelfRemoveAndPins)

        // region remove-member
        val removal = alice.removeMember(targetLeafIndex = carolGroup.leafIndex)
        publish(removal.framedCommitBytes)
        // endregion
        val result = assertIs<ProcessedMessage.AppliedCommit>(carolGroup.processMessage(removal.framedCommitBytes))
        assertTrue(result.removedSelf)
        bob.processMessage(removal.framedCommitBytes)

        // region update-keys
        bob.proposeSigningKeyRotation() // a fresh leaf: new encryption and signature keys
        val update = bob.commit()
        // endregion
        alice.processMessage(update.framedCommitBytes)
        assertContentEquals(alice.epochAuthenticator, bob.epochAuthenticator)

        // region leave
        val (leaveRequest, _) = bob.buildSelfRemoveProposalMessage()
        publish(leaveRequest) // another member commits it
        // endregion
        alice.processMessage(leaveRequest)
        val leave = alice.commit()
        assertTrue(assertIs<ProcessedMessage.AppliedCommit>(bob.processMessage(leave.framedCommitBytes)).removedSelf)
    }

    @Test
    fun proposalsAndCommits() {
        val (alice, bob) = pair(WithSelfRemoveAndPins)
        // region propose-by-reference
        val proposal = bob.proposalMessage(bob.proposeSigningKeyRotation())
        publish(proposal) // any member may commit it
        // endregion
        alice.processMessage(proposal)

        // region staged-commit
        val staged = alice.stageCommit() // built, signed, not applied
        val accepted = true // the delivery service took it, and no other commit won the epoch
        if (accepted) alice.mergePendingCommit() else alice.clearPendingCommit()
        // endregion
        bob.processMessage(staged.framedCommitBytes)
        assertContentEquals(alice.epochAuthenticator, bob.epochAuthenticator)

        // region custom-proposal
        alice.proposeCustom(proposalType = 0xF0F0, data = "pin message 7".encodeToByteArray())
        val withCustom = alice.commit()
        // endregion
        val applied = assertIs<ProcessedMessage.AppliedCommit>(bob.processMessage(withCustom.framedCommitBytes))
        assertEquals(1, applied.proposals.size)
    }

    @Test
    fun wireFormatPolicy() {
        // region wire-format-policy
        val hidden =
            object : MlsGroupPolicy {
                override val wireFormatPolicy = WireFormatPolicy.PURE_CIPHERTEXT
            }
        val group = MlsGroup.create("alice".encodeToByteArray(), policy = hidden)
        // group.commit() and group.proposalMessage(...) now send PrivateMessages,
        // and a member's PublicMessage proposal or commit is refused.
        // endregion
        val commit = group.commit()
        assertEquals(
            WireFormat.PRIVATE_MESSAGE,
            com.vitorpamplona.mls.framing.MlsMessage
                .decodeTls(
                    com.vitorpamplona.mls.codec
                        .TlsReader(commit.framedCommitBytes),
                ).wireFormat,
        )
    }

    @Test
    fun persistence() {
        val (alice, bob) = pair()
        // region save-state
        val bytes: ByteArray = alice.saveState().encodeTls() // after every change; encrypt at rest
        // endregion

        // region restore-state
        val restored = MlsGroup.restore(MlsGroupState.decodeTls(bytes), policy = MlsGroupPolicy.Permissive)
        // endregion
        assertEquals("still here", bob.decrypt(restored.encrypt("still here".encodeToByteArray())).content.decodeToString())
    }

    @Test
    fun exporter() {
        val (alice, bob) = pair()
        // region exporter
        val key = alice.exporterSecret(label = "my-app file key", context = "file 9".encodeToByteArray(), length = 32)
        // endregion
        assertContentEquals(key, bob.exporterSecret("my-app file key", "file 9".encodeToByteArray(), 32))
    }

    // region policy
    class OurRules(
        private val admins: Set<String>,
    ) : MlsGroupPolicy {
        override fun validateCredential(
            credential: Credential,
            signatureKey: ByteArray,
        ) {
            val identity = (credential as? Credential.Basic)?.identity ?: throw IllegalArgumentException("basic credentials only")
            require(identity.isNotEmpty()) { "empty identity" }
        }

        override fun authorizeCommit(
            group: GroupView,
            proposals: List<PendingProposal>,
            committerLeafIndex: Int,
        ) {
            val committer = group.memberIdentityHex(committerLeafIndex)
            require(committer in admins) { "only admins commit" }
        }
    }
    // endregion

    @Test
    fun applicationRules() {
        val aliceHex = "alice".encodeToByteArray().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        val rules = OurRules(admins = setOf(aliceHex))
        val (alice, bob) = pair(rules)
        bob.processMessage(alice.commit().framedCommitBytes)
        assertFailsWith<IllegalArgumentException> { bob.commit() }
        assertEquals(2L, bob.epoch, "bob's refused commit did not move the group")
    }

    @Test
    fun publicGroup() {
        val (alice, bob) = pair()
        val groupInfoBytes = alice.groupInfoMessage()
        // region public-group
        val view = PublicGroup.fromGroupInfo(groupInfoBytes)
        val incoming = bob.commit().framedCommitBytes
        val forward =
            try {
                view.processMessage(incoming) // checked as a member would, minus the secrets
                true
            } catch (e: IllegalArgumentException) {
                false // refuse it: the members would too
            }
        // endregion
        assertTrue(forward)
        alice.processMessage(incoming)
        assertEquals(alice.epoch, view.epoch)
    }

    @Test
    fun forkRecovery() {
        // Make a fork: alice and bob each merge their own commit adding charlie.
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val bobBundle = keyPackageOf("bob")
        val bob = MlsGroup.processWelcome(alice.addMember(bobBundle.keyPackage.toTlsBytes()).welcomeBytes!!, bobBundle)
        val charlieBundle = keyPackageOf("charlie")
        val charlie = MlsGroup.processWelcome(alice.addMember(charlieBundle.keyPackage.toTlsBytes()).welcomeBytes!!, charlieBundle)
        bob.addMember(keyPackageOf("charlie").keyPackage.toTlsBytes())
        val freshBob = keyPackageOf("bob")
        val freshBobBytes = freshBob.keyPackage.toTlsBytes()

        // region fork-readd
        val ourSide = listOf(alice.leafIndex, charlie.leafIndex) // who merged the same commit we did
        val stranded = alice.forkComplement(ourSide) // [bob]
        val repair = alice.recoverForkByReadding(ourSide, keyPackages = listOf(freshBobBytes))
        // endregion
        assertEquals(1, stranded.size)
        charlie.processMessage(repair.framedCommitBytes)
        val newBob = MlsGroup.processWelcome(repair.welcomeBytes!!, freshBob)
        assertContentEquals(alice.epochAuthenticator, newBob.epochAuthenticator)
        assertContentEquals(alice.epochAuthenticator, charlie.epochAuthenticator)

        val keyPackagesForEveryoneElse = alice.rebootMembers().map { (_, leaf) -> keyPackageOf((leaf.credential as Credential.Basic).identity.decodeToString()) }
        // region fork-reboot
        val others = alice.rebootMembers() // everyone to re-invite
        val rebooted = alice.reboot(keyPackages = keyPackagesForEveryoneElse.map { it.keyPackage.toTlsBytes() })
        publish(rebooted.commit.welcomeBytes!!) // they join with processWelcome
        // endregion
        assertEquals(2, others.size)
        val joined = keyPackagesForEveryoneElse.map { MlsGroup.processWelcome(rebooted.commit.welcomeBytes!!, it) }
        joined.forEach { assertContentEquals(rebooted.group.epochAuthenticator, it.epochAuthenticator) }
    }

    @Test
    fun successorGroups() {
        val (alice, bob) = pair()
        // region reinit
        alice.proposeReInit(newGroupId = "group-v2".encodeToByteArray())
        bob.processMessage(alice.commit().framedCommitBytes) // both groups are now frozen

        val bobNext = bob.createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
        val successor = alice.reinit(keyPackages = listOf(bobNext.keyPackage.toTlsBytes()))
        val bobInNewGroup = MlsGroup.joinSuccessor(successor.commit.welcomeBytes!!, bobNext, predecessor = bob)
        // endregion
        assertContentEquals(successor.group.epochAuthenticator, bobInNewGroup.epochAuthenticator)

        val (carol, dave) = pair()
        // region branch
        val daveNext = MlsGroup.createKeyPackage("bob".encodeToByteArray())
        val side = carol.branch(keyPackages = listOf(daveNext.keyPackage.toTlsBytes()))
        val daveInBranch = MlsGroup.joinSuccessor(side.commit.welcomeBytes!!, daveNext, predecessor = dave)
        // endregion
        assertContentEquals(side.group.epochAuthenticator, daveInBranch.epochAuthenticator)
    }
}
