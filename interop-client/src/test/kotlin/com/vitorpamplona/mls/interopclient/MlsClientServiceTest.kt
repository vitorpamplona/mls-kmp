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
package com.vitorpamplona.mls.interopclient

import com.google.protobuf.ByteString
import io.grpc.ManagedChannel
import io.grpc.Server
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import mls_client.MLSClientGrpc
import mls_client.MlsClient.AddExternalSignerRequest
import mls_client.MlsClient.AddProposalRequest
import mls_client.MlsClient.CommitRequest
import mls_client.MlsClient.CreateBranchRequest
import mls_client.MlsClient.CreateExternalSignerRequest
import mls_client.MlsClient.CreateGroupRequest
import mls_client.MlsClient.CreateKeyPackageRequest
import mls_client.MlsClient.ExportRequest
import mls_client.MlsClient.ExternalJoinRequest
import mls_client.MlsClient.ExternalSignerProposalRequest
import mls_client.MlsClient.GroupInfoRequest
import mls_client.MlsClient.HandleBranchRequest
import mls_client.MlsClient.HandleCommitRequest
import mls_client.MlsClient.HandlePendingCommitRequest
import mls_client.MlsClient.HandleReInitWelcomeRequest
import mls_client.MlsClient.JoinGroupRequest
import mls_client.MlsClient.NameRequest
import mls_client.MlsClient.NewMemberAddProposalRequest
import mls_client.MlsClient.ProposalDescription
import mls_client.MlsClient.ProtectRequest
import mls_client.MlsClient.ReInitProposalRequest
import mls_client.MlsClient.ReInitWelcomeRequest
import mls_client.MlsClient.RemoveProposalRequest
import mls_client.MlsClient.StateAuthRequest
import mls_client.MlsClient.StorePSKRequest
import mls_client.MlsClient.UnprotectRequest
import mls_client.MlsClient.UpdateProposalRequest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The test-runner's scenarios (mls-implementations interop/configs), with
 * mls-kmp on every side, through a real gRPC channel. The Go runner itself
 * drives mixed clients; this pins that each call means what the runner thinks.
 */
class MlsClientServiceTest {
    private lateinit var server: Server
    private lateinit var channel: ManagedChannel
    private lateinit var c: MLSClientGrpc.MLSClientBlockingStub

    @BeforeTest
    fun start() {
        val name = InProcessServerBuilder.generateName()
        server =
            InProcessServerBuilder
                .forName(name)
                .directExecutor()
                .addService(MlsClientService())
                .build()
                .start()
        channel = InProcessChannelBuilder.forName(name).directExecutor().build()
        c = MLSClientGrpc.newBlockingStub(channel)
    }

    @AfterTest
    fun stop() {
        channel.shutdownNow()
        server.shutdownNow()
    }

    private fun bs(s: String) = ByteString.copyFromUtf8(s)

    private fun createGroup(
        identity: String,
        encrypt: Boolean = false,
    ) = c
        .createGroup(
            CreateGroupRequest
                .newBuilder()
                .setGroupId(bs("group"))
                .setCipherSuite(1)
                .setIdentity(bs(identity))
                .setEncryptHandshake(encrypt)
                .build(),
        ).stateId

    private fun keyPackage(identity: String) =
        c.createKeyPackage(
            CreateKeyPackageRequest
                .newBuilder()
                .setCipherSuite(1)
                .setIdentity(bs(identity))
                .build(),
        )

    private fun auth(state: Int) = c.stateAuth(StateAuthRequest.newBuilder().setStateId(state).build()).stateAuthSecret

    private fun add(kp: ByteString) =
        ProposalDescription
            .newBuilder()
            .setProposalType(bs("add"))
            .setKeyPackage(kp)
            .build()

    /** [creator] adds [identity] by Welcome; returns the joiner's state. */
    private fun invite(
        creator: Int,
        identity: String,
        externalTree: Boolean = false,
        others: List<Int> = emptyList(),
        encrypt: Boolean = false,
    ): Int {
        val kp = keyPackage(identity)
        val commit =
            c.commit(
                CommitRequest
                    .newBuilder()
                    .setStateId(creator)
                    .addByValue(add(kp.keyPackage))
                    .setExternalTree(externalTree)
                    .build(),
            )
        c.handlePendingCommit(HandlePendingCommitRequest.newBuilder().setStateId(creator).build())
        for (o in others) {
            c.handleCommit(
                HandleCommitRequest
                    .newBuilder()
                    .setStateId(o)
                    .setCommit(commit.commit)
                    .build(),
            )
        }
        val join =
            JoinGroupRequest
                .newBuilder()
                .setTransactionId(kp.transactionId)
                .setWelcome(commit.welcome)
                .setEncryptHandshake(encrypt)
        if (externalTree) join.setRatchetTree(commit.ratchetTree)
        val joined = c.joinGroup(join.build())
        assertEquals(auth(creator), joined.epochAuthenticator)
        return joined.stateId
    }

    private fun assertTalk(
        from: Int,
        to: Int,
    ) {
        val ct =
            c
                .protect(
                    ProtectRequest
                        .newBuilder()
                        .setStateId(from)
                        .setPlaintext(bs("hi"))
                        .setAuthenticatedData(bs("ad"))
                        .build(),
                ).ciphertext
        val pt =
            c.unprotect(
                UnprotectRequest
                    .newBuilder()
                    .setStateId(to)
                    .setCiphertext(ct)
                    .build(),
            )
        assertEquals("hi", pt.plaintext.toStringUtf8())
        assertEquals("ad", pt.authenticatedData.toStringUtf8())
        val export = { s: Int ->
            c
                .export(
                    ExportRequest
                        .newBuilder()
                        .setStateId(s)
                        .setLabel("l")
                        .setContext(bs("c"))
                        .setKeyLength(32)
                        .build(),
                ).exportedSecret
        }
        assertEquals(export(from), export(to))
    }

    @Test
    fun name() = assertEquals("mls-kmp", c.name(NameRequest.getDefaultInstance()).name)

    @Test
    fun welcomeJoinAndApplication() {
        for ((encrypt, external) in listOf(false to false, true to false, false to true)) {
            val alice = createGroup("alice", encrypt)
            val bob = invite(alice, "bob", externalTree = external, encrypt = encrypt)
            assertTalk(alice, bob)
            assertTalk(bob, alice)
        }
    }

    /** What every runner script does: the committer hands back its own proposal by reference. */
    @Test
    fun ownProposalByReference() {
        val alice = createGroup("alice")
        val bob = invite(alice, "bob")
        val carolKp = keyPackage("carol")
        val addCarol =
            c
                .addProposal(
                    AddProposalRequest
                        .newBuilder()
                        .setStateId(alice)
                        .setKeyPackage(carolKp.keyPackage)
                        .build(),
                ).proposal
        val commit =
            c.commit(
                CommitRequest
                    .newBuilder()
                    .setStateId(alice)
                    .addByReference(addCarol)
                    .build(),
            )
        c.handlePendingCommit(HandlePendingCommitRequest.newBuilder().setStateId(alice).build())
        c.handleCommit(
            HandleCommitRequest
                .newBuilder()
                .setStateId(bob)
                .addProposal(addCarol)
                .setCommit(commit.commit)
                .build(),
        )
        val carol =
            c.joinGroup(
                JoinGroupRequest
                    .newBuilder()
                    .setTransactionId(carolKp.transactionId)
                    .setWelcome(commit.welcome)
                    .build(),
            )
        assertEquals(auth(bob), carol.epochAuthenticator)
        assertTalk(carol.stateId, bob)
    }

    @Test
    fun commitByReference() {
        val alice = createGroup("alice")
        val bob = invite(alice, "bob")
        val carol = invite(alice, "carol", others = listOf(bob))
        // Bob proposes an Update and Carol's removal; Alice commits both.
        val update = c.updateProposal(UpdateProposalRequest.newBuilder().setStateId(bob).build()).proposal
        val remove =
            c
                .removeProposal(
                    RemoveProposalRequest
                        .newBuilder()
                        .setStateId(bob)
                        .setRemovedId(bs("carol"))
                        .build(),
                ).proposal
        val commit =
            c
                .commit(
                    CommitRequest
                        .newBuilder()
                        .setStateId(alice)
                        .addByReference(update)
                        .addByReference(remove)
                        .build(),
                ).commit
        c.handlePendingCommit(HandlePendingCommitRequest.newBuilder().setStateId(alice).build())
        c.handleCommit(
            HandleCommitRequest
                .newBuilder()
                .setStateId(bob)
                .addProposal(update)
                .addProposal(remove)
                .setCommit(commit)
                .build(),
        )
        assertEquals(auth(alice), auth(bob))
        assertTalk(bob, alice)
    }

    @Test
    fun externalJoinAndResync() {
        val alice = createGroup("alice")
        val bob = invite(alice, "bob")
        for (removePrior in listOf(false, true)) {
            val identity = if (removePrior) "bob" else "carol"
            val info =
                c.groupInfo(
                    GroupInfoRequest
                        .newBuilder()
                        .setStateId(alice)
                        .setExternalTree(true)
                        .build(),
                )
            val joined =
                c.externalJoin(
                    ExternalJoinRequest
                        .newBuilder()
                        .setGroupInfo(info.groupInfo)
                        .setRatchetTree(info.ratchetTree)
                        .setIdentity(bs(identity))
                        .setRemovePrior(removePrior)
                        .build(),
                )
            c.handleCommit(
                HandleCommitRequest
                    .newBuilder()
                    .setStateId(alice)
                    .setCommit(joined.commit)
                    .build(),
            )
            if (!removePrior) {
                c.handleCommit(
                    HandleCommitRequest
                        .newBuilder()
                        .setStateId(bob)
                        .setCommit(joined.commit)
                        .build(),
                )
            }
            assertEquals(auth(alice), joined.epochAuthenticator)
            assertTalk(joined.stateId, alice)
        }
    }

    @Test
    fun externalPsk() {
        val alice = createGroup("alice")
        val bobKp = keyPackage("bob")
        val psk = StorePSKRequest.newBuilder().setPskId(bs("psk")).setPskSecret(ByteString.copyFrom(ByteArray(32) { 7 }))
        c.storePSK(psk.setStateOrTransactionId(alice).build())
        c.storePSK(psk.setStateOrTransactionId(bobKp.transactionId).build())
        val commit =
            c.commit(
                CommitRequest
                    .newBuilder()
                    .setStateId(alice)
                    .addByValue(add(bobKp.keyPackage))
                    .addByValue(ProposalDescription.newBuilder().setProposalType(bs("externalPSK")).setPskId(bs("psk")))
                    .build(),
            )
        c.handlePendingCommit(HandlePendingCommitRequest.newBuilder().setStateId(alice).build())
        val bob =
            c.joinGroup(
                JoinGroupRequest
                    .newBuilder()
                    .setTransactionId(bobKp.transactionId)
                    .setWelcome(commit.welcome)
                    .build(),
            )
        assertEquals(auth(alice), bob.epochAuthenticator)
    }

    @Test
    fun reinit() {
        val alice = createGroup("alice")
        val bob = invite(alice, "bob")
        val proposal =
            c
                .reInitProposal(
                    ReInitProposalRequest
                        .newBuilder()
                        .setStateId(bob)
                        .setGroupId(bs("next"))
                        .setCipherSuite(1)
                        .build(),
                ).proposal
        val commit =
            c
                .reInitCommit(
                    CommitRequest
                        .newBuilder()
                        .setStateId(alice)
                        .addByReference(proposal)
                        .build(),
                ).commit
        val aliceRe = c.handlePendingReInitCommit(HandlePendingCommitRequest.newBuilder().setStateId(alice).build())
        val bobRe =
            c.handleReInitCommit(
                HandleCommitRequest
                    .newBuilder()
                    .setStateId(bob)
                    .addProposal(proposal)
                    .setCommit(commit)
                    .build(),
            )
        val welcome =
            c.reInitWelcome(
                ReInitWelcomeRequest
                    .newBuilder()
                    .setReinitId(aliceRe.reinitId)
                    .addKeyPackage(bobRe.keyPackage)
                    .build(),
            )
        val bobNext =
            c.handleReInitWelcome(
                HandleReInitWelcomeRequest
                    .newBuilder()
                    .setReinitId(bobRe.reinitId)
                    .setWelcome(welcome.welcome)
                    .build(),
            )
        assertEquals(welcome.epochAuthenticator, bobNext.epochAuthenticator)
        assertTalk(welcome.stateId, bobNext.stateId)
    }

    @Test
    fun branch() {
        val alice = createGroup("alice")
        val bob = invite(alice, "bob")
        val bobKp = keyPackage("bob")
        val branch =
            c.createBranch(
                CreateBranchRequest
                    .newBuilder()
                    .setStateId(alice)
                    .setGroupId(bs("branch"))
                    .addKeyPackages(bobKp.keyPackage)
                    .build(),
            )
        val joined =
            c.handleBranch(
                HandleBranchRequest
                    .newBuilder()
                    .setStateId(bob)
                    .setTransactionId(bobKp.transactionId)
                    .setWelcome(branch.welcome)
                    .build(),
            )
        assertEquals(branch.epochAuthenticator, joined.epochAuthenticator)
        assertTalk(joined.stateId, branch.stateId)
    }

    @Test
    fun newMemberAddProposal() {
        val alice = createGroup("alice")
        val info = c.groupInfo(GroupInfoRequest.newBuilder().setStateId(alice).build()).groupInfo
        val bob =
            c.newMemberAddProposal(
                NewMemberAddProposalRequest
                    .newBuilder()
                    .setGroupInfo(info)
                    .setIdentity(bs("bob"))
                    .build(),
            )
        val commit =
            c.commit(
                CommitRequest
                    .newBuilder()
                    .setStateId(alice)
                    .addByReference(bob.proposal)
                    .build(),
            )
        c.handlePendingCommit(HandlePendingCommitRequest.newBuilder().setStateId(alice).build())
        val joined =
            c.joinGroup(
                JoinGroupRequest
                    .newBuilder()
                    .setTransactionId(bob.transactionId)
                    .setWelcome(commit.welcome)
                    .build(),
            )
        assertEquals(auth(alice), joined.epochAuthenticator)
    }

    @Test
    fun externalSigner() {
        val alice = createGroup("alice")
        val bob = invite(alice, "bob")
        val signer =
            c.createExternalSigner(
                CreateExternalSignerRequest
                    .newBuilder()
                    .setCipherSuite(1)
                    .setIdentity(bs("ds"))
                    .build(),
            )
        val gce =
            c
                .addExternalSigner(
                    AddExternalSignerRequest
                        .newBuilder()
                        .setStateId(alice)
                        .setExternalSender(signer.externalSender)
                        .build(),
                ).proposal
        val commit =
            c
                .commit(
                    CommitRequest
                        .newBuilder()
                        .setStateId(alice)
                        .addByReference(gce)
                        .build(),
                ).commit
        c.handlePendingCommit(HandlePendingCommitRequest.newBuilder().setStateId(alice).build())
        c.handleCommit(
            HandleCommitRequest
                .newBuilder()
                .setStateId(bob)
                .addProposal(gce)
                .setCommit(commit)
                .build(),
        )

        // The external sender removes Bob.
        val info = c.groupInfo(GroupInfoRequest.newBuilder().setStateId(alice).build()).groupInfo
        val remove =
            c
                .externalSignerProposal(
                    ExternalSignerProposalRequest
                        .newBuilder()
                        .setSignerId(signer.signerId)
                        .setGroupInfo(info)
                        .setDescription(ProposalDescription.newBuilder().setProposalType(bs("remove")).setRemovedId(bs("bob")))
                        .build(),
                ).proposal
        val removal =
            c
                .commit(
                    CommitRequest
                        .newBuilder()
                        .setStateId(alice)
                        .addByReference(remove)
                        .build(),
                ).commit
        c.handlePendingCommit(HandlePendingCommitRequest.newBuilder().setStateId(alice).build())
        assertTrue(!removal.isEmpty)
    }
}
