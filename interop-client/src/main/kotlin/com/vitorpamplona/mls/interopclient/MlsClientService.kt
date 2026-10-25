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
@file:OptIn(InternalMlsApi::class)

package com.vitorpamplona.mls.interopclient

import com.google.protobuf.ByteString
import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.mls.InternalMlsApi
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.FramedContent
import com.vitorpamplona.mls.framing.Framing
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.Sender
import com.vitorpamplona.mls.framing.SenderType
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.group.ProcessedMessage
import com.vitorpamplona.mls.group.PublicGroup
import com.vitorpamplona.mls.group.WireFormatPolicy
import com.vitorpamplona.mls.messages.GroupInfo
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import io.grpc.Status
import io.grpc.stub.StreamObserver
import mls_client.MLSClientGrpc
import mls_client.MlsClient.AddExternalSignerRequest
import mls_client.MlsClient.AddProposalRequest
import mls_client.MlsClient.CommitRequest
import mls_client.MlsClient.CommitResponse
import mls_client.MlsClient.CreateBranchRequest
import mls_client.MlsClient.CreateExternalSignerRequest
import mls_client.MlsClient.CreateExternalSignerResponse
import mls_client.MlsClient.CreateGroupRequest
import mls_client.MlsClient.CreateGroupResponse
import mls_client.MlsClient.CreateKeyPackageRequest
import mls_client.MlsClient.CreateKeyPackageResponse
import mls_client.MlsClient.CreateSubgroupResponse
import mls_client.MlsClient.ExportRequest
import mls_client.MlsClient.ExportResponse
import mls_client.MlsClient.ExternalJoinRequest
import mls_client.MlsClient.ExternalJoinResponse
import mls_client.MlsClient.ExternalPSKProposalRequest
import mls_client.MlsClient.ExternalSignerProposalRequest
import mls_client.MlsClient.FreeRequest
import mls_client.MlsClient.FreeResponse
import mls_client.MlsClient.GroupContextExtensionsProposalRequest
import mls_client.MlsClient.GroupInfoRequest
import mls_client.MlsClient.GroupInfoResponse
import mls_client.MlsClient.HandleBranchRequest
import mls_client.MlsClient.HandleBranchResponse
import mls_client.MlsClient.HandleCommitRequest
import mls_client.MlsClient.HandleCommitResponse
import mls_client.MlsClient.HandlePendingCommitRequest
import mls_client.MlsClient.HandleReInitCommitResponse
import mls_client.MlsClient.HandleReInitWelcomeRequest
import mls_client.MlsClient.JoinGroupRequest
import mls_client.MlsClient.JoinGroupResponse
import mls_client.MlsClient.NameRequest
import mls_client.MlsClient.NameResponse
import mls_client.MlsClient.NewMemberAddProposalRequest
import mls_client.MlsClient.NewMemberAddProposalResponse
import mls_client.MlsClient.ProposalDescription
import mls_client.MlsClient.ProposalResponse
import mls_client.MlsClient.ProtectRequest
import mls_client.MlsClient.ProtectResponse
import mls_client.MlsClient.ReInitProposalRequest
import mls_client.MlsClient.ReInitWelcomeRequest
import mls_client.MlsClient.RemoveProposalRequest
import mls_client.MlsClient.ResumptionPSKProposalRequest
import mls_client.MlsClient.StateAuthRequest
import mls_client.MlsClient.StateAuthResponse
import mls_client.MlsClient.StorePSKRequest
import mls_client.MlsClient.StorePSKResponse
import mls_client.MlsClient.SupportedCiphersuitesRequest
import mls_client.MlsClient.SupportedCiphersuitesResponse
import mls_client.MlsClient.UnprotectRequest
import mls_client.MlsClient.UnprotectResponse
import mls_client.MlsClient.UpdateProposalRequest

/**
 * The mlswg interop test-runner's MLSClient, over mls-kmp.
 *
 * The runner names every object by an id: a group (state), a KeyPackage
 * waiting for its Welcome (transaction), a group waiting for its ReInit
 * successor, an external signer. One counter numbers them all, because
 * StorePSK takes either a state or a transaction id. Messages travel as
 * MLSMessages; ratchet trees bare. One lock serializes every call: the
 * runner drives one step at a time anyway, and an MlsGroup wants one thread.
 */
public class MlsClientService : MLSClientGrpc.MLSClientImplBase() {
    private class Transaction(
        val bundle: KeyPackageBundle,
        val psks: MutableMap<String, ByteArray> = mutableMapOf(),
    )

    private class ReInitPending(
        val group: MlsGroup,
        val bundle: KeyPackageBundle,
    )

    private class Signer(
        val identity: ByteArray,
        val privateKey: ByteArray,
        val publicKey: ByteArray,
    )

    private val lock = Any()
    private var nextId = 1
    private val groups = mutableMapOf<Int, MlsGroup>()
    private val transactions = mutableMapOf<Int, Transaction>()
    private val reinits = mutableMapOf<Int, ReInitPending>()
    private val signers = mutableMapOf<Int, Signer>()

    private fun id() = nextId++

    private fun policy(encrypt: Boolean): MlsGroupPolicy =
        object : MlsGroupPolicy {
            override val wireFormatPolicy: WireFormatPolicy = if (encrypt) WireFormatPolicy.MIXED_CIPHERTEXT else WireFormatPolicy.MIXED_PLAINTEXT
        }

    private fun group(id: Int) = groups[id] ?: throw IllegalArgumentException("No group state $id")

    private fun ByteArray.bytes(): ByteString = ByteString.copyFrom(this)

    /** A KeyPackage as the runner passes it: an MLSMessage, or the bare struct. */
    private fun keyPackage(bytes: ByteArray): MlsKeyPackage {
        val reader = TlsReader(bytes)
        if (bytes.size >= 4 && reader.readUint16() == MlsMessage.MLS_VERSION_10 && reader.readUint16() == WireFormat.KEY_PACKAGE.value) {
            return MlsKeyPackage.decodeTls(TlsReader(MlsMessage.decodeTls(TlsReader(bytes)).payload))
        }
        return MlsKeyPackage.decodeTls(TlsReader(bytes))
    }

    private fun keyPackageMessage(kp: MlsKeyPackage): ByteArray = MlsMessage(wireFormat = WireFormat.KEY_PACKAGE, payload = kp.toTlsBytes()).toTlsBytes()

    private fun groupInfoOf(bytes: ByteArray): GroupInfo {
        val m = MlsMessage.decodeTls(TlsReader(bytes))
        return GroupInfo.decodeTls(TlsReader(m.payload))
    }

    private fun identityOf(leaf: com.vitorpamplona.mls.tree.LeafNode) = (leaf.credential as? Credential.Basic)?.identity

    private fun leafOf(
        members: List<Pair<Int, com.vitorpamplona.mls.tree.LeafNode>>,
        identity: ByteArray,
    ): Int = members.firstOrNull { identityOf(it.second)?.contentEquals(identity) == true }?.first ?: throw IllegalArgumentException("No member ${identity.decodeToString()}")

    private fun newKeyPackage(identity: ByteArray): Pair<Int, KeyPackageBundle> {
        val bundle = MlsGroup.createKeyPackage(identity)
        val id = id()
        transactions[id] = Transaction(bundle)
        return id to bundle
    }

    private fun <T> call(
        observer: StreamObserver<T>,
        block: () -> T,
    ) {
        val result =
            try {
                synchronized(lock) { block() }
            } catch (e: UnsupportedOperationException) {
                observer.onError(Status.UNIMPLEMENTED.withDescription(e.message).asRuntimeException())
                return
            } catch (e: Throwable) {
                observer.onError(
                    Status.INVALID_ARGUMENT
                        .withDescription("${e::class.simpleName}: ${e.message}")
                        .withCause(e)
                        .asRuntimeException(),
                )
                return
            }
        observer.onNext(result)
        observer.onCompleted()
    }

    override fun name(
        request: NameRequest,
        observer: StreamObserver<NameResponse>,
    ): Unit = call(observer) { NameResponse.newBuilder().setName("mls-kmp").build() }

    override fun supportedCiphersuites(
        request: SupportedCiphersuitesRequest,
        observer: StreamObserver<SupportedCiphersuitesResponse>,
    ): Unit = call(observer) { SupportedCiphersuitesResponse.newBuilder().addCiphersuites(1).build() }

    override fun createGroup(
        request: CreateGroupRequest,
        observer: StreamObserver<CreateGroupResponse>,
    ): Unit =
        call(observer) {
            require(request.cipherSuite == 1) { "Only ciphersuite 1" }
            val group = MlsGroup.create(request.identity.toByteArray(), policy = policy(request.encryptHandshake), groupId = request.groupId.toByteArray().takeIf { it.isNotEmpty() })
            val id = id()
            groups[id] = group
            CreateGroupResponse.newBuilder().setStateId(id).build()
        }

    override fun createKeyPackage(
        request: CreateKeyPackageRequest,
        observer: StreamObserver<CreateKeyPackageResponse>,
    ): Unit =
        call(observer) {
            require(request.cipherSuite == 1) { "Only ciphersuite 1" }
            val (id, bundle) = newKeyPackage(request.identity.toByteArray())
            CreateKeyPackageResponse
                .newBuilder()
                .setTransactionId(id)
                .setKeyPackage(keyPackageMessage(bundle.keyPackage).bytes())
                .setInitPriv(bundle.initPrivateKey.bytes())
                .setEncryptionPriv(bundle.encryptionPrivateKey.bytes())
                .setSignaturePriv(bundle.signaturePrivateKey.copyOf(32).bytes())
                .build()
        }

    override fun joinGroup(
        request: JoinGroupRequest,
        observer: StreamObserver<JoinGroupResponse>,
    ): Unit =
        call(observer) {
            val tx = transactions.remove(request.transactionId) ?: throw IllegalArgumentException("No transaction ${request.transactionId}")
            val group =
                MlsGroup.processWelcome(
                    request.welcome.toByteArray(),
                    tx.bundle,
                    policy(request.encryptHandshake),
                    ratchetTree = request.ratchetTree.toByteArray().takeIf { it.isNotEmpty() },
                    psks = { id -> (id as? PreSharedKeyId.External)?.let { tx.psks[it.pskId.toHex()] } },
                )
            for ((pskId, secret) in tx.psks) group.registerPsk(pskId.fromHex(), secret)
            val id = id()
            groups[id] = group
            JoinGroupResponse
                .newBuilder()
                .setStateId(id)
                .setEpochAuthenticator(group.epochAuthenticator.bytes())
                .build()
        }

    override fun externalJoin(
        request: ExternalJoinRequest,
        observer: StreamObserver<ExternalJoinResponse>,
    ): Unit =
        call(observer) {
            val info = request.groupInfo.toByteArray()
            val tree = request.ratchetTree.toByteArray().takeIf { it.isNotEmpty() }
            val identity = request.identity.toByteArray()
            val resync = if (request.removePrior) leafOf(PublicGroup.fromGroupInfo(info, ratchetTree = tree).members(), identity) else null
            val psks =
                request.psksList.map {
                    PreSharedKeyId.External(
                        it.pskId.toByteArray(),
                        com.vitorpamplona.mls.crypto.MlsCryptoProvider
                            .randomBytes(32),
                    ) to it.pskSecret.toByteArray()
                }
            val joined = MlsGroup.externalJoin(info, identity, policy = policy(request.encryptHandshake), ratchetTree = tree, resyncLeafIndex = resync, psks = psks)
            for (p in request.psksList) joined.group.registerPsk(p.pskId.toByteArray(), p.pskSecret.toByteArray())
            val id = id()
            groups[id] = joined.group
            ExternalJoinResponse
                .newBuilder()
                .setStateId(id)
                .setCommit(joined.framedCommitBytes.bytes())
                .setEpochAuthenticator(joined.group.epochAuthenticator.bytes())
                .build()
        }

    override fun groupInfo(
        request: GroupInfoRequest,
        observer: StreamObserver<GroupInfoResponse>,
    ): Unit =
        call(observer) {
            val group = group(request.stateId)
            val b = GroupInfoResponse.newBuilder().setGroupInfo(group.groupInfoMessage(includeRatchetTree = !request.externalTree).bytes())
            if (request.externalTree) b.setRatchetTree(group.exportTreeBytes().bytes())
            b.build()
        }

    override fun stateAuth(
        request: StateAuthRequest,
        observer: StreamObserver<StateAuthResponse>,
    ): Unit = call(observer) { StateAuthResponse.newBuilder().setStateAuthSecret(group(request.stateId).epochAuthenticator.bytes()).build() }

    override fun export(
        request: ExportRequest,
        observer: StreamObserver<ExportResponse>,
    ): Unit =
        call(observer) {
            val secret = group(request.stateId).exporterSecret(request.label, request.context.toByteArray(), request.keyLength)
            ExportResponse.newBuilder().setExportedSecret(secret.bytes()).build()
        }

    override fun protect(
        request: ProtectRequest,
        observer: StreamObserver<ProtectResponse>,
    ): Unit =
        call(observer) {
            val ct = group(request.stateId).encrypt(request.plaintext.toByteArray(), request.authenticatedData.toByteArray())
            ProtectResponse.newBuilder().setCiphertext(ct.bytes()).build()
        }

    override fun unprotect(
        request: UnprotectRequest,
        observer: StreamObserver<UnprotectResponse>,
    ): Unit =
        call(observer) {
            val group = group(request.stateId)
            val bytes = request.ciphertext.toByteArray()
            val message =
                try {
                    (group.processMessage(bytes) as ProcessedMessage.Application).message
                } catch (e: Exception) {
                    // Sealed in an epoch we already left, or simply bad.
                    runCatching { group.decryptFormerEpoch(bytes) }.getOrElse { throw e }
                }
            UnprotectResponse
                .newBuilder()
                .setPlaintext(message.content.bytes())
                .setAuthenticatedData(message.authenticatedData.bytes())
                .build()
        }

    override fun storePSK(
        request: StorePSKRequest,
        observer: StreamObserver<StorePSKResponse>,
    ): Unit =
        call(observer) {
            val id = request.stateOrTransactionId
            val pskId = request.pskId.toByteArray()
            val secret = request.pskSecret.toByteArray()
            when {
                groups.containsKey(id) -> groups.getValue(id).registerPsk(pskId, secret)
                transactions.containsKey(id) -> transactions.getValue(id).psks[pskId.toHex()] = secret
                else -> throw IllegalArgumentException("No state or transaction $id")
            }
            StorePSKResponse.getDefaultInstance()
        }

    private fun proposal(
        stateId: Int,
        make: (MlsGroup) -> Proposal,
    ): ProposalResponse {
        val group = group(stateId)
        return ProposalResponse.newBuilder().setProposal(group.proposalMessage(make(group)).bytes()).build()
    }

    override fun addProposal(
        request: AddProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit = call(observer) { proposal(request.stateId) { it.proposeAdd(keyPackage(request.keyPackage.toByteArray()).toTlsBytes()) } }

    override fun updateProposal(
        request: UpdateProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit = call(observer) { proposal(request.stateId) { it.proposeSigningKeyRotation() } }

    override fun removeProposal(
        request: RemoveProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit = call(observer) { proposal(request.stateId) { it.proposeRemove(leafOf(it.members(), request.removedId.toByteArray())) } }

    override fun externalPSKProposal(
        request: ExternalPSKProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit = call(observer) { proposal(request.stateId) { it.proposePsk(request.pskId.toByteArray()) } }

    override fun resumptionPSKProposal(
        request: ResumptionPSKProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit = call(observer) { proposal(request.stateId) { it.proposeResumptionPsk(request.epochId) } }

    override fun groupContextExtensionsProposal(
        request: GroupContextExtensionsProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit = call(observer) { proposal(request.stateId) { it.proposeGroupContextExtensions(request.extensionsList.map { e -> Extension(e.extensionType, e.extensionData.toByteArray()) }) } }

    override fun reInitProposal(
        request: ReInitProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit =
        call(observer) {
            proposal(request.stateId) {
                it.proposeReInit(
                    newGroupId = request.groupId.toByteArray(),
                    newCipherSuite = request.cipherSuite,
                    newExtensions = request.extensionsList.map { e -> Extension(e.extensionType, e.extensionData.toByteArray()) },
                )
            }
        }

    /** Stage our own proposal for a by-value description. */
    private fun propose(
        group: MlsGroup,
        d: ProposalDescription,
    ) {
        when (val type = d.proposalType.toStringUtf8()) {
            "add" -> group.proposeAdd(keyPackage(d.keyPackage.toByteArray()).toTlsBytes())
            "remove" -> group.proposeRemove(leafOf(group.members(), d.removedId.toByteArray()))
            "externalPSK" -> group.proposePsk(d.pskId.toByteArray())
            "resumptionPSK" -> group.proposeResumptionPsk(d.epochId)
            "groupContextExtensions" -> group.proposeGroupContextExtensions(d.extensionsList.map { Extension(it.extensionType, it.extensionData.toByteArray()) })
            "reinit" -> group.proposeReInit(d.groupId.toByteArray(), newCipherSuite = d.cipherSuite, newExtensions = d.extensionsList.map { Extension(it.extensionType, it.extensionData.toByteArray()) })
            else -> throw UnsupportedOperationException("Proposal type $type")
        }
    }

    private fun stageCommit(request: CommitRequest): CommitResponse {
        val group = group(request.stateId)
        for (p in request.byReferenceList) group.processMessage(p.toByteArray())
        for (d in request.byValueList) propose(group, d)
        val result = group.stageCommit(includeRatchetTreeInWelcome = !request.externalTree)
        val b = CommitResponse.newBuilder().setCommit(result.framedCommitBytes.bytes())
        result.welcomeBytes?.let { b.setWelcome(it.bytes()) }
        if (request.externalTree) {
            // The tree the commit leads to: what a joiner needs.
            val after = MlsGroup.restore(group.saveState())
            after.mergePendingCommit()
            b.setRatchetTree(after.exportTreeBytes().bytes())
        }
        return b.build()
    }

    override fun commit(
        request: CommitRequest,
        observer: StreamObserver<CommitResponse>,
    ): Unit = call(observer) { stageCommit(request) }

    override fun handlePendingCommit(
        request: HandlePendingCommitRequest,
        observer: StreamObserver<HandleCommitResponse>,
    ): Unit =
        call(observer) {
            val group = group(request.stateId)
            group.mergePendingCommit()
            HandleCommitResponse
                .newBuilder()
                .setStateId(request.stateId)
                .setEpochAuthenticator(group.epochAuthenticator.bytes())
                .build()
        }

    private fun handleCommit(request: HandleCommitRequest): MlsGroup {
        val group = group(request.stateId)
        for (p in request.proposalList) group.processMessage(p.toByteArray())
        group.processMessage(request.commit.toByteArray())
        return group
    }

    override fun handleCommit(
        request: HandleCommitRequest,
        observer: StreamObserver<HandleCommitResponse>,
    ): Unit =
        call(observer) {
            val group = handleCommit(request)
            HandleCommitResponse
                .newBuilder()
                .setStateId(request.stateId)
                .setEpochAuthenticator(group.epochAuthenticator.bytes())
                .build()
        }

    override fun reInitCommit(
        request: CommitRequest,
        observer: StreamObserver<CommitResponse>,
    ): Unit = call(observer) { stageCommit(request) }

    /** After the ReInit commit: a KeyPackage for the successor group, held under a reinit id. */
    private fun reinitPending(group: MlsGroup): HandleReInitCommitResponse {
        val identity = identityOf(group.members().first { it.first == group.leafIndex }.second) ?: ByteArray(0)
        val bundle = MlsGroup.createKeyPackage(identity)
        val id = id()
        reinits[id] = ReInitPending(group, bundle)
        return HandleReInitCommitResponse
            .newBuilder()
            .setReinitId(id)
            .setKeyPackage(keyPackageMessage(bundle.keyPackage).bytes())
            .setEpochAuthenticator(group.epochAuthenticator.bytes())
            .build()
    }

    override fun handlePendingReInitCommit(
        request: HandlePendingCommitRequest,
        observer: StreamObserver<HandleReInitCommitResponse>,
    ): Unit =
        call(observer) {
            val group = group(request.stateId)
            group.mergePendingCommit()
            reinitPending(group)
        }

    override fun handleReInitCommit(
        request: HandleCommitRequest,
        observer: StreamObserver<HandleReInitCommitResponse>,
    ): Unit = call(observer) { reinitPending(handleCommit(request)) }

    override fun reInitWelcome(
        request: ReInitWelcomeRequest,
        observer: StreamObserver<CreateSubgroupResponse>,
    ): Unit =
        call(observer) {
            val pending = reinits.remove(request.reinitId) ?: throw IllegalArgumentException("No reinit ${request.reinitId}")
            val successor = pending.group.reinit(request.keyPackageList.map { keyPackage(it.toByteArray()).toTlsBytes() }, includeRatchetTreeInWelcome = !request.externalTree)
            subgroup(successor)
        }

    private fun subgroup(successor: MlsGroup.SuccessorGroup): CreateSubgroupResponse {
        val id = id()
        groups[id] = successor.group
        val b =
            CreateSubgroupResponse
                .newBuilder()
                .setStateId(id)
                .setEpochAuthenticator(successor.group.epochAuthenticator.bytes())
                .setRatchetTree(successor.group.exportTreeBytes().bytes())
        successor.commit.welcomeBytes?.let { b.setWelcome(it.bytes()) }
        return b.build()
    }

    override fun handleReInitWelcome(
        request: HandleReInitWelcomeRequest,
        observer: StreamObserver<JoinGroupResponse>,
    ): Unit =
        call(observer) {
            val pending = reinits.remove(request.reinitId) ?: throw IllegalArgumentException("No reinit ${request.reinitId}")
            val group =
                MlsGroup.joinSuccessor(
                    request.welcome.toByteArray(),
                    pending.bundle,
                    predecessor = pending.group,
                    ratchetTree = request.ratchetTree.toByteArray().takeIf { it.isNotEmpty() },
                )
            val id = id()
            groups[id] = group
            JoinGroupResponse
                .newBuilder()
                .setStateId(id)
                .setEpochAuthenticator(group.epochAuthenticator.bytes())
                .build()
        }

    override fun createBranch(
        request: CreateBranchRequest,
        observer: StreamObserver<CreateSubgroupResponse>,
    ): Unit =
        call(observer) {
            val group = group(request.stateId)
            val branch =
                group.branch(
                    request.keyPackagesList.map { keyPackage(it.toByteArray()).toTlsBytes() },
                    newGroupId = request.groupId.toByteArray(),
                    extensions = request.extensionsList.map { Extension(it.extensionType, it.extensionData.toByteArray()) },
                    includeRatchetTreeInWelcome = !request.externalTree,
                )
            subgroup(branch)
        }

    override fun handleBranch(
        request: HandleBranchRequest,
        observer: StreamObserver<HandleBranchResponse>,
    ): Unit =
        call(observer) {
            val tx = transactions.remove(request.transactionId) ?: throw IllegalArgumentException("No transaction ${request.transactionId}")
            val group =
                MlsGroup.joinSuccessor(
                    request.welcome.toByteArray(),
                    tx.bundle,
                    predecessor = group(request.stateId),
                    ratchetTree = request.ratchetTree.toByteArray().takeIf { it.isNotEmpty() },
                )
            val id = id()
            groups[id] = group
            HandleBranchResponse
                .newBuilder()
                .setStateId(id)
                .setEpochAuthenticator(group.epochAuthenticator.bytes())
                .build()
        }

    /** A PublicMessage proposal from a sender outside the group, signed without the GroupContext (RFC 9420 §6.1). */
    private fun outsiderProposal(
        info: GroupInfo,
        sender: Sender,
        proposal: Proposal,
        signingKey: ByteArray,
    ): ByteArray {
        val ctx = info.groupContext
        val content = FramedContent(ctx.groupId, ctx.epoch, sender, ByteArray(0), ContentType.PROPOSAL, proposal.toTlsBytes())
        val signature = Framing.sign(signingKey, WireFormat.PUBLIC_MESSAGE, content, null)
        return MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, null, null)).toTlsBytes()
    }

    override fun newMemberAddProposal(
        request: NewMemberAddProposalRequest,
        observer: StreamObserver<NewMemberAddProposalResponse>,
    ): Unit =
        call(observer) {
            val info = groupInfoOf(request.groupInfo.toByteArray())
            val (id, bundle) = newKeyPackage(request.identity.toByteArray())
            val message = outsiderProposal(info, Sender(SenderType.NEW_MEMBER_PROPOSAL), Proposal.Add(bundle.keyPackage), bundle.signaturePrivateKey)
            NewMemberAddProposalResponse
                .newBuilder()
                .setTransactionId(id)
                .setProposal(message.bytes())
                .setInitPriv(bundle.initPrivateKey.bytes())
                .setEncryptionPriv(bundle.encryptionPrivateKey.bytes())
                .setSignaturePriv(bundle.signaturePrivateKey.copyOf(32).bytes())
                .build()
        }

    override fun createExternalSigner(
        request: CreateExternalSignerRequest,
        observer: StreamObserver<CreateExternalSignerResponse>,
    ): Unit =
        call(observer) {
            require(request.cipherSuite == 1) { "Only ciphersuite 1" }
            val kp = Ed25519.generateKeyPair()
            val identity = request.identity.toByteArray()
            val id = id()
            signers[id] = Signer(identity, kp.privateKey, kp.publicKey)
            CreateExternalSignerResponse
                .newBuilder()
                .setSignerId(id)
                .setExternalSender(externalSender(kp.publicKey, identity).bytes())
                .build()
        }

    /** RFC 9420 §12.1.8.1: `struct { SignaturePublicKey signature_key; Credential credential; } ExternalSender`. */
    private fun externalSender(
        publicKey: ByteArray,
        identity: ByteArray,
    ): ByteArray =
        TlsWriter()
            .apply {
                putOpaqueVarInt(publicKey)
                Credential.Basic(identity).encodeTls(this)
            }.toByteArray()

    override fun addExternalSigner(
        request: AddExternalSignerRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit =
        call(observer) {
            proposal(request.stateId) { group ->
                val existing = group.extensions.find { it.extensionType == EXTERNAL_SENDERS }
                val senders = (existing?.let { TlsReader(it.extensionData).readOpaqueVarInt() } ?: ByteArray(0)) + request.externalSender.toByteArray()
                val updated = group.extensions.filter { it.extensionType != EXTERNAL_SENDERS } + Extension(EXTERNAL_SENDERS, TlsWriter().apply { putOpaqueVarInt(senders) }.toByteArray())
                group.proposeGroupContextExtensions(updated)
            }
        }

    override fun externalSignerProposal(
        request: ExternalSignerProposalRequest,
        observer: StreamObserver<ProposalResponse>,
    ): Unit =
        call(observer) {
            val signer = signers[request.signerId] ?: throw IllegalArgumentException("No signer ${request.signerId}")
            val infoBytes = request.groupInfo.toByteArray()
            val info = groupInfoOf(infoBytes)
            val ext = info.groupContext.extensions.find { it.extensionType == EXTERNAL_SENDERS } ?: throw IllegalArgumentException("The group has no external senders")
            val reader = TlsReader(ext.extensionData)
            val keys = reader.readVectorVarInt { r -> r.readOpaqueVarInt().also { Credential.decodeTls(r) } }
            val index = keys.indexOfFirst { it.contentEquals(signer.publicKey) }
            require(index >= 0) { "The signer is not one of the group's external senders" }
            val d = request.description
            val ctx = info.groupContext
            val proposal: Proposal =
                when (val type = d.proposalType.toStringUtf8()) {
                    "add" -> Proposal.Add(keyPackage(d.keyPackage.toByteArray()))
                    "remove" -> {
                        val view = PublicGroup.fromGroupInfo(infoBytes, ratchetTree = request.ratchetTree.toByteArray().takeIf { it.isNotEmpty() })
                        Proposal.Remove(leafOf(view.members(), d.removedId.toByteArray()))
                    }
                    "externalPSK" ->
                        Proposal.Psk(
                            PreSharedKeyId.External(
                                d.pskId.toByteArray(),
                                com.vitorpamplona.mls.crypto.MlsCryptoProvider
                                    .randomBytes(32),
                            ),
                        )
                    "resumptionPSK" ->
                        Proposal.Psk(
                            PreSharedKeyId.Resumption(
                                PreSharedKeyId.USAGE_APPLICATION,
                                ctx.groupId,
                                d.epochId,
                                com.vitorpamplona.mls.crypto.MlsCryptoProvider
                                    .randomBytes(32),
                            ),
                        )
                    "groupContextExtensions" -> Proposal.GroupContextExtensions(d.extensionsList.map { Extension(it.extensionType, it.extensionData.toByteArray()) })
                    "reinit" -> Proposal.ReInit(d.groupId.toByteArray(), 1, d.cipherSuite, d.extensionsList.map { Extension(it.extensionType, it.extensionData.toByteArray()) })
                    else -> throw UnsupportedOperationException("Proposal type $type")
                }
            val message = outsiderProposal(info, Sender(SenderType.EXTERNAL, index), proposal, signer.privateKey)
            ProposalResponse.newBuilder().setProposal(message.bytes()).build()
        }

    override fun free(
        request: FreeRequest,
        observer: StreamObserver<FreeResponse>,
    ): Unit =
        call(observer) {
            groups.remove(request.stateId)
            FreeResponse.getDefaultInstance()
        }

    private companion object {
        const val EXTERNAL_SENDERS = 0x0005

        fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

        fun String.fromHex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
