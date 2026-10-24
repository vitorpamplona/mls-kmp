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
import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.crypto.mac.MacInstance
import com.vitorpamplona.mls.InternalMlsApi
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.crypto.Hpke
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.FramedContent
import com.vitorpamplona.mls.framing.Framing
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.PrivateMessage
import com.vitorpamplona.mls.framing.PrivateMessageCodec
import com.vitorpamplona.mls.framing.PublicMessage
import com.vitorpamplona.mls.framing.Sender
import com.vitorpamplona.mls.framing.SenderType
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.framing.framedContent
import com.vitorpamplona.mls.messages.Commit
import com.vitorpamplona.mls.messages.CommitResult
import com.vitorpamplona.mls.messages.EncryptedGroupSecrets
import com.vitorpamplona.mls.messages.ExternalJoinResult
import com.vitorpamplona.mls.messages.GroupContext
import com.vitorpamplona.mls.messages.GroupInfo
import com.vitorpamplona.mls.messages.GroupSecrets
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.messages.ProposalOrRef
import com.vitorpamplona.mls.messages.ProposalType
import com.vitorpamplona.mls.messages.UpdatePath
import com.vitorpamplona.mls.messages.Welcome
import com.vitorpamplona.mls.platform.Hex
import com.vitorpamplona.mls.platform.TimeUtils
import com.vitorpamplona.mls.schedule.EpochSecrets
import com.vitorpamplona.mls.schedule.KeyNonceGeneration
import com.vitorpamplona.mls.schedule.KeySchedule
import com.vitorpamplona.mls.schedule.SecretTree
import com.vitorpamplona.mls.schedule.SenderRatchetState
import com.vitorpamplona.mls.tree.BinaryTree
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode
import com.vitorpamplona.mls.tree.LeafNodeSource
import com.vitorpamplona.mls.tree.Lifetime
import com.vitorpamplona.mls.tree.RatchetTree
import com.vitorpamplona.mls.tree.TreeKem
import com.vitorpamplona.mls.tree.TreeNode

/**
 * MLS Group state and operations (RFC 9420 Section 8, 12).
 *
 * This is the main entry point for the MLS engine. It manages:
 * - Group membership (ratchet tree)
 * - Epoch transitions (key schedule)
 * - Message encryption/decryption
 * - Proposal/Commit processing
 * - Welcome message creation and processing
 *
 * Usage:
 * ```kotlin
 * // Create a new group
 * val group = MlsGroup.create(identity, signingKey)
 *
 * // Add a member
 * val result = group.addMember(keyPackageBytes)
 * // Send result.commitBytes to the group
 * // Send result.welcomeBytes to the new member
 *
 * // Join a group via Welcome
 * val group = MlsGroup.processWelcome(welcomeBytes, keyPackageBundle)
 *
 * // Encrypt application message
 * val encrypted = group.encrypt(plaintext)
 *
 * // Decrypt application message
 * val decrypted = group.decrypt(encrypted)
 *
 * // Export key for a binding's own outer encryption
 * val key = group.exporterSecret("myapp", "group-event".encodeToByteArray(), 32)
 * ```
 */
private fun constantTimeEquals(
    a: ByteArray,
    b: ByteArray,
): Boolean {
    if (a.size != b.size) return false
    var result = 0
    for (i in a.indices) {
        result = result or (a[i].toInt() xor b[i].toInt())
    }
    return result == 0
}

class MlsGroup private constructor(
    private var groupContext: GroupContext,
    private val tree: RatchetTree,
    private var myLeafIndex: Int,
    private var epochSecrets: EpochSecrets,
    private var secretTree: SecretTree,
    private var initSecret: ByteArray,
    private var signingPrivateKey: ByteArray,
    private var encryptionPrivateKey: ByteArray,
    private var interimTranscriptHash: ByteArray,
    /** Provisioned PSKs, keyed by [PreSharedKeyId.identityKey]. */
    private val pskStore: MutableMap<String, ByteArray> = mutableMapOf(),
    private val pendingProposals: MutableList<PendingProposal> = mutableListOf(),
    /** Receiver data of the last [RETAIN_EPOCHS] epochs, oldest first. See [decryptFormerEpoch]. */
    private val retainedEpochs: ArrayDeque<RetainedEpochReceiverData> = ArrayDeque(),
    private val sentKeys: MutableMap<Int, KeyNonceGeneration> = mutableMapOf(),
    /** Staged keys from proposeSigningKeyRotation — only promoted on successful commit */
    private var pendingSigningKey: ByteArray? = null,
    private var pendingEncryptionKey: ByteArray? = null,
    /**
     * HPKE private keys for the PARENT nodes on our own direct path, keyed by
     * node index.
     *
     * RFC 9420 §7.6 does not say "the committer encrypts to your leaf" — it
     * says the committer encrypts one path secret per node in the copath
     * resolution, and you decrypt at whichever of those nodes you hold a key
     * for. A merged subtree resolves to its PARENT, so as soon as a group has
     * three members the commits addressed to us stop naming our leaf at all.
     *
     * Only keys that are the private half of the key the tree currently holds
     * at that node are kept (see [prunePathKeys]).
     */
    private val pathPrivateKeys: MutableMap<Int, ByteArray> = mutableMapOf(),
    /**
     * The application's authorization rules. See [MlsGroupPolicy]: RFC 9420
     * itself places no limit on who may commit what, so the default allows
     * everything the protocol allows and a binding supplies its own.
     */
    private val policy: MlsGroupPolicy = MlsGroupPolicy.Permissive,
    /** `resumption_psk` of this group's former epochs, by epoch (RFC 9420 §8.6). */
    private val resumptionPsks: MutableMap<Long, ByteArray> = mutableMapOf(),
    /**
     * Keys behind Update proposals we sent by reference, by the new leaf's
     * encryption key in hex: another member's commit may apply one, and then
     * our leaf holds keys only we can supply.
     */
    private val pendingUpdateKeys: MutableMap<String, PendingUpdateKeys> = mutableMapOf(),
) {
    /**
     * Unix seconds the RFC 9420 lifetime checks on incoming LeafNodes compare against.
     *
     * [InternalMlsApi] so only tests move it: they replay fixed interop vectors
     * (ts-mls KeyPackages carrying a two-week lifetime), and must check them inside the window
     * they were minted for rather than against whatever day the suite happens to run.
     */
    @InternalMlsApi
    var clock: () -> Long = TimeUtils::now

    val groupId: ByteArray get() = groupContext.groupId
    val epoch: Long get() = groupContext.epoch
    val leafIndex: Int get() = myLeafIndex
    val extensions: List<com.vitorpamplona.mls.tree.Extension> get() = groupContext.extensions

    /**
     * True while our own leaf is still live in the tree.
     *
     * After `processCommit` applies a Remove proposal that targets us, the
     * group is intentionally kept in the manager so callers can inspect the
     * final tree state — but our leaf is null and `leafCount` may have
     * shrunk past `myLeafIndex`. Either condition means we can't propose,
     * commit, encrypt, or decrypt any further; surface that here so callers
     * get a clean answer instead of poking at private tree internals.
     */
    fun isLocalMember(): Boolean = myLeafIndex < tree.leafCount && tree.getLeaf(myLeafIndex) != null

    /**
     * The read-only projection this group hands to its [MlsGroupPolicy].
     *
     * Public because a binding's own checks want the same view the engine
     * gives the policy — Marmot's "only admins may change group extensions"
     * gate runs in `MlsGroupManager`, before any commit is staged.
     */
    fun view(): GroupView =
        GroupView(
            extensions = groupContext.extensions,
            leafCount = tree.leafCount,
            myLeafIndex = myLeafIndex,
            identityAt = { memberIdentityHex(it) },
            capabilitiesAt = { tree.getLeaf(it)?.capabilities },
        )

    /**
     * Read-only snapshot of the staged-proposal pool. Exposed at module
     * scope so tests can inspect what `proposeAdd` / `proposeRemove` /
     * `buildSelfRemoveProposalMessage` etc. actually stage (notably the
     * `authenticatedContentBytes` we capture for ProposalRef matching).
     */
    @InternalMlsApi
    fun pendingProposalsSnapshot(): List<PendingProposal> = pendingProposals.toList()

    /**
     * Whether any proposal is staged and waiting for a Commit.
     *
     * Public where [pendingProposalsSnapshot] is internal: a caller outside
     * this module has no business reading the proposals, but it does need to
     * know there is work to commit. A standalone `SelfRemove` from a departing
     * member sits here until an authorized member commits it — and until then
     * the leaver is still in the tree and still reading the group.
     */
    fun hasPendingProposals(): Boolean = pendingProposals.isNotEmpty()

    /**
     * The GroupContext extension list as it stands. Test-only: callers
     * that want the dictionary should use [appDataDictionary], which
     * cannot distinguish an absent extension from an empty one — a
     * distinction the wire format does make.
     */
    @InternalMlsApi
    fun groupContextExtensionsSnapshot(): List<Extension> = groupContext.extensions.toList()

    private fun allMembersSupportExtension(extensionType: Int): Boolean = (0 until tree.leafCount).all { i -> tree.getLeaf(i)?.let { extensionType in it.capabilities.extensions } ?: true }

    /**
     * Encode the current ratchet tree the same way it's serialized into
     * the GroupInfo's `ratchet_tree` extension on a Welcome — a freshly-
     * decoded copy is what a joiner sees, so this is the right input for
     * exercising [verifyTreeParentHashesForJoin] in tests.
     */
    @InternalMlsApi
    fun exportTreeBytes(): ByteArray {
        val w = TlsWriter()
        tree.encodeTls(w)
        return w.toByteArray()
    }

    // --- Member identity ---

    /** Raw BasicCredential identity bytes of the member at the given leaf, or null. */
    fun memberIdentity(leafIndex: Int): ByteArray? = (tree.getLeaf(leafIndex)?.credential as? Credential.Basic)?.identity

    /**
     * Lowercase hex OF THE CREDENTIAL BYTES at [leafIndex], or null.
     *
     * This hex-encodes whatever the credential holds, which is the account key
     * only for a binding that stores it as raw bytes — Marmot does. A binding
     * that stores an already-encoded identity gets the hex of that encoding:
     * cordn writes 64 ASCII characters of hex, so this returns 128 characters
     * of nothing useful. Such a binding should read the credential itself
     * (`CordnCredential.identityOrNull`) rather than call this.
     *
     * Kept as-is because it is what Marmot means everywhere it is used, and
     * because a function that guessed which encoding a credential used would
     * be worse than one that says plainly what it does.
     */
    fun memberIdentityHex(leafIndex: Int): String? = memberIdentity(leafIndex)?.let { Hex.encode(it) }

    /** Lowercase hex of the local member's BasicCredential identity, or null. */
    fun myIdentityHex(): String? = memberIdentityHex(myLeafIndex)

    /**
     * Account identities holding at least one current member leaf, as hex.
     *
     * A set of ACCOUNTS, not leaves: one account may hold several leaves (one
     * per device), and every binding that asks this question means the account.
     */
    fun currentMemberIdentities(): Set<String> = (0 until tree.leafCount).mapNotNullTo(mutableSetOf()) { memberIdentityHex(it) }

    // --- State Persistence ---

    /**
     * Capture the current group state as a serializable snapshot.
     *
     * The returned [MlsGroupState] contains all secret key material and
     * MUST be stored in encrypted local storage. Call this after every
     * epoch transition (commit, processCommit, processWelcome) to ensure
     * the group can be restored after an app restart.
     */
    fun saveState(): MlsGroupState {
        val treeWriter = TlsWriter()
        tree.encodeTls(treeWriter)

        return MlsGroupState(
            groupContext = groupContext,
            treeBytes = treeWriter.toByteArray(),
            myLeafIndex = myLeafIndex,
            epochSecrets = epochSecrets,
            initSecret = initSecret,
            signingPrivateKey = signingPrivateKey,
            encryptionPrivateKey = encryptionPrivateKey,
            interimTranscriptHash = interimTranscriptHash,
            encryptionSecret = epochSecrets.encryptionSecret,
            // Preserve the SecretTree ratchet positions so a restore doesn't
            // rewind our own generation counter to 0 and reuse an AEAD
            // key+nonce within this epoch (RFC 9420 §9).
            senderRatchetStates = secretTree.exportSenderStates(),
            pathPrivateKeys = pathPrivateKeys.toMap(),
            // A staged proposal is an obligation, not a message: a departing
            // member's SelfRemove sits here until someone commits it, and a
            // restart that forgot it would leave the leaver in the tree with
            // the group's keys and nobody holding the proposal to evict them.
            pendingProposals = pendingProposals.toList(),
            skippedApplicationSecrets = secretTree.exportSkippedApplicationSecrets(),
            skippedHandshakeSecrets = secretTree.exportSkippedHandshakeSecrets(),
            retainedEpochs = retainedEpochs.toList(),
            nodeSecrets = secretTree.exportNodeSecrets(),
            resumptionPsks = resumptionPsks.toMap(),
            pendingUpdateKeys = pendingUpdateKeys.values.toList(),
            reInitPending = reInitPending,
        )
    }

    /**
     * Where our own sender ratchet has got to, for the small per-send record.
     *
     * Null before this leaf has sent anything at the current epoch: there is no
     * position yet, and the full state already says so.
     */
    fun exportOwnSenderRatchet(): OwnSenderRatchet? {
        val state = secretTree.exportSenderStates()[myLeafIndex] ?: return null
        return OwnSenderRatchet(
            epoch = epoch,
            leafIndex = myLeafIndex,
            treeBinder = OwnSenderRatchet.binderFor(epochSecrets.encryptionSecret),
            handshakeSecret = state.handshakeSecret,
            handshakeGeneration = state.handshakeGeneration,
            applicationSecret = state.applicationSecret,
            applicationGeneration = state.applicationGeneration,
        )
    }

    /**
     * Apply a per-send ratchet record saved after the full state it accompanies.
     *
     * Refuses anything that is not demonstrably about this exact position. A
     * different leaf, a different epoch, or a different SecretTree at the same
     * epoch — which convergence produces when it swaps one epoch-N state for a
     * rival one after a fork — all mean the record describes a ratchet that no
     * longer exists. A chain already at or past the recorded generation means
     * the state was the fresher of the two.
     *
     * When it does apply, each chain independently takes whichever side is
     * further along. That is what makes this safe to do at all — the operation
     * can only skip generations FORWARD. Skipping forward wastes key material;
     * going backwards would re-emit a generation already used, which reuses an
     * AEAD key+nonce pair and is the failure this record exists to prevent.
     *
     * @return true when the position moved.
     */
    fun restoreOwnSenderRatchet(record: OwnSenderRatchet): Boolean {
        if (record.epoch != epoch || record.leafIndex != myLeafIndex) return false
        if (!record.treeBinder.contentEquals(OwnSenderRatchet.binderFor(epochSecrets.encryptionSecret))) return false

        val current = secretTree.exportSenderStates()[myLeafIndex]
        if (current == null) {
            secretTree.importSenderStates(
                mapOf(
                    myLeafIndex to
                        SenderRatchetState(
                            handshakeSecret = record.handshakeSecret,
                            handshakeGeneration = record.handshakeGeneration,
                            applicationSecret = record.applicationSecret,
                            applicationGeneration = record.applicationGeneration,
                        ),
                ),
            )
            return true
        }

        val handshakeAhead = record.handshakeGeneration > current.handshakeGeneration
        val applicationAhead = record.applicationGeneration > current.applicationGeneration
        if (!handshakeAhead && !applicationAhead) return false

        secretTree.importSenderStates(
            mapOf(
                myLeafIndex to
                    SenderRatchetState(
                        handshakeSecret = if (handshakeAhead) record.handshakeSecret else current.handshakeSecret,
                        handshakeGeneration = if (handshakeAhead) record.handshakeGeneration else current.handshakeGeneration,
                        applicationSecret = if (applicationAhead) record.applicationSecret else current.applicationSecret,
                        applicationGeneration = if (applicationAhead) record.applicationGeneration else current.applicationGeneration,
                    ),
            ),
        )
        return true
    }

    /**
     * Drop every direct-path private key that is no longer the private half of
     * the key the tree holds at that node: the node was blanked (an Update or
     * Remove), replaced (someone else's UpdatePath), or is gone (truncation).
     *
     * A stale key can never decrypt anything addressed to the node, and RFC
     * 9420 §7.5 requires deleting replaced key material, so after every change
     * to the tree this is the only rule that decides what we keep.
     */
    private fun prunePathKeys() {
        val iterator = pathPrivateKeys.entries.iterator()
        while (iterator.hasNext()) {
            val (node, key) = iterator.next()
            if (node >= BinaryTree.nodeCount(maxOf(tree.leafCount, 1)) || !TreeKem.holdsKeyFor(tree, node, key)) iterator.remove()
        }
    }

    /** The private key we hold for [nodeIndex] in the current tree, or null. */
    private fun privateKeyFor(nodeIndex: Int): ByteArray? = if (nodeIndex == BinaryTree.leafToNode(myLeafIndex)) encryptionPrivateKey else pathPrivateKeys[nodeIndex]

    // --- Atomic state changes ---

    /** Everything a commit (ours or a peer's) may change, captured so it can be restored. */
    private class StateSnapshot(
        val tree: RatchetTree.Snapshot,
        val groupContext: GroupContext,
        val myLeafIndex: Int,
        val epochSecrets: EpochSecrets,
        val secretTree: SecretTree,
        val initSecret: ByteArray,
        val signingPrivateKey: ByteArray,
        val encryptionPrivateKey: ByteArray,
        val interimTranscriptHash: ByteArray,
        val pendingProposals: List<PendingProposal>,
        val retainedEpochs: List<RetainedEpochReceiverData>,
        val sentKeys: Map<Int, KeyNonceGeneration>,
        val pendingSigningKey: ByteArray?,
        val pendingEncryptionKey: ByteArray?,
        val pathPrivateKeys: Map<Int, ByteArray>,
        val pendingLeafAdvertisement: Pair<Capabilities, List<Extension>>?,
        val reInitPending: Proposal.ReInit?,
        val resumptionPsks: Map<Long, ByteArray>,
        val pendingUpdateKeys: Map<String, PendingUpdateKeys>,
    )

    private fun captureState(): StateSnapshot =
        StateSnapshot(
            tree = tree.snapshot(),
            groupContext = groupContext,
            myLeafIndex = myLeafIndex,
            epochSecrets = epochSecrets,
            secretTree = secretTree,
            initSecret = initSecret,
            signingPrivateKey = signingPrivateKey,
            encryptionPrivateKey = encryptionPrivateKey,
            interimTranscriptHash = interimTranscriptHash,
            pendingProposals = pendingProposals.toList(),
            retainedEpochs = retainedEpochs.toList(),
            sentKeys = sentKeys.toMap(),
            pendingSigningKey = pendingSigningKey,
            pendingEncryptionKey = pendingEncryptionKey,
            pathPrivateKeys = pathPrivateKeys.toMap(),
            pendingLeafAdvertisement = pendingLeafAdvertisement,
            reInitPending = reInitPending,
            resumptionPsks = resumptionPsks.toMap(),
            pendingUpdateKeys = pendingUpdateKeys.toMap(),
        )

    private fun restoreState(s: StateSnapshot) {
        tree.restoreFrom(s.tree)
        groupContext = s.groupContext
        myLeafIndex = s.myLeafIndex
        epochSecrets = s.epochSecrets
        secretTree = s.secretTree
        initSecret = s.initSecret
        signingPrivateKey = s.signingPrivateKey
        encryptionPrivateKey = s.encryptionPrivateKey
        interimTranscriptHash = s.interimTranscriptHash
        pendingProposals.clear()
        pendingProposals.addAll(s.pendingProposals)
        retainedEpochs.clear()
        retainedEpochs.addAll(s.retainedEpochs)
        sentKeys.clear()
        sentKeys.putAll(s.sentKeys)
        pendingSigningKey = s.pendingSigningKey
        pendingEncryptionKey = s.pendingEncryptionKey
        pathPrivateKeys.clear()
        pathPrivateKeys.putAll(s.pathPrivateKeys)
        pendingLeafAdvertisement = s.pendingLeafAdvertisement
        reInitPending = s.reInitPending
        resumptionPsks.clear()
        resumptionPsks.putAll(s.resumptionPsks)
        pendingUpdateKeys.clear()
        pendingUpdateKeys.putAll(s.pendingUpdateKeys)
    }

    /**
     * Runs [block] and, if it throws, puts every piece of group state back the
     * way it was: a commit that fails half-way must not leave the tree one
     * epoch ahead of the key schedule.
     */
    private inline fun <T> atomically(block: () -> T): T {
        val before = captureState()
        try {
            return block()
        } catch (t: Throwable) {
            restoreState(before)
            throw t
        }
    }

    /** The current epoch's receiver data. Taken before a commit changes anything, kept once it has applied. */
    private fun captureRetainedEpoch(): RetainedEpochReceiverData {
        val w = TlsWriter()
        tree.encodeTls(w)
        return RetainedEpochReceiverData(
            epoch = epoch,
            senderDataSecret = epochSecrets.senderDataSecret,
            encryptionSecret = epochSecrets.encryptionSecret,
            exporterSecret = epochSecrets.exporterSecret,
            resumptionPsk = epochSecrets.resumptionPsk,
            groupContext = groupContext,
            treeBytes = w.toByteArray(),
            senderRatchetStates = secretTree.exportSenderStates(),
            skippedApplicationSecrets = secretTree.exportSkippedApplicationSecrets(),
            nodeSecrets = secretTree.exportNodeSecrets(),
        )
    }

    private fun pushRetainedEpoch(retained: RetainedEpochReceiverData) {
        retainedEpochs.removeAll { it.epoch == retained.epoch }
        retainedEpochs.addLast(retained)
        while (retainedEpochs.size > RETAIN_EPOCHS) retainedEpochs.removeFirst()
    }

    /** Receiver data of the retained former epochs, oldest first. */
    fun retainedEpochs(): List<RetainedEpochReceiverData> = retainedEpochs.toList()

    /**
     * Extract retained epoch secrets for late-message decryption.
     *
     * Call this BEFORE an epoch transition to capture the outgoing epoch's
     * decryption secrets. These are kept in a bounded window by [MlsGroupManager].
     */
    fun retainedSecrets(): RetainedEpochSecrets =
        RetainedEpochSecrets(
            epoch = epoch,
            senderDataSecret = epochSecrets.senderDataSecret,
            encryptionSecret = epochSecrets.encryptionSecret,
            leafCount = tree.leafCount,
            exporterSecret = epochSecrets.exporterSecret,
        )

    val memberCount: Int
        get() {
            var count = 0
            for (i in 0 until tree.leafCount) {
                if (tree.getLeaf(i) != null) count++
            }
            return count
        }

    /**
     * The ReInit proposal of the last commit, once one has been committed.
     *
     * RFC 9420 §11.2: from then on this group MUST NOT be used to send
     * messages; [encrypt] and [commit] refuse, and the members move to the new
     * group the committer creates (joined with a resumption PSK of usage
     * `reinit`, see [proposeResumptionPsk]).
     */
    var reInitPending: Proposal.ReInit? = null
        private set

    /** The epoch authenticator (RFC 9420 §8.7), for out-of-band comparison between members. */
    val epochAuthenticator: ByteArray get() = epochSecrets.epochAuthenticator.copyOf()

    /**
     * Register an external pre-shared key (RFC 9420 §8.4) under [pskId], for
     * PreSharedKey proposals and Welcomes that name it.
     */
    fun registerPsk(
        pskId: ByteArray,
        psk: ByteArray,
    ) {
        pskStore[PreSharedKeyId.External(pskId, ByteArray(0)).identityKey()] = psk
    }

    /**
     * Register the `resumption_psk` of epoch [epoch] of ANOTHER group
     * [groupId] (a ReInit or branch predecessor). This group's own former
     * epochs are remembered automatically.
     */
    fun registerResumptionPsk(
        groupId: ByteArray,
        epoch: Long,
        psk: ByteArray,
    ) {
        pskStore[PreSharedKeyId.Resumption(PreSharedKeyId.USAGE_APPLICATION, groupId, epoch, ByteArray(0)).identityKey()] = psk
    }

    /** The `resumption_psk` of the current epoch, which a ReInit or branch successor group names. */
    val resumptionPsk: ByteArray get() = epochSecrets.resumptionPsk.copyOf()

    /** The secret value of [id], or null when this group cannot supply it. */
    private fun resolvePsk(id: PreSharedKeyId): ByteArray? =
        when (id) {
            is PreSharedKeyId.External -> {
                pskStore[id.identityKey()]
            }

            is PreSharedKeyId.Resumption -> {
                if (id.pskGroupId.contentEquals(groupId)) {
                    if (id.pskEpoch == epoch) epochSecrets.resumptionPsk else resumptionPsks[id.pskEpoch]
                } else {
                    pskStore[PreSharedKeyId.Resumption(PreSharedKeyId.USAGE_APPLICATION, id.pskGroupId, id.pskEpoch, ByteArray(0)).identityKey()]
                }
            }
        }

    private fun requirePsk(id: PreSharedKeyId): ByteArray = resolvePsk(id) ?: throw IllegalStateException("PSK not available: ${id.identityKey()}")

    /** Remember the outgoing epoch's resumption PSK before the key schedule moves on. */
    private fun rememberResumptionPsk() {
        resumptionPsks[epoch] = epochSecrets.resumptionPsk
        while (resumptionPsks.size > RESUMPTION_PSK_EPOCHS) resumptionPsks.remove(resumptionPsks.keys.min())
    }

    /**
     * Get the list of members (leaf index -> LeafNode).
     */
    fun members(): List<Pair<Int, LeafNode>> {
        val result = mutableListOf<Pair<Int, LeafNode>>()
        for (i in 0 until tree.leafCount) {
            val leaf = tree.getLeaf(i)
            if (leaf != null) {
                result.add(i to leaf)
            }
        }
        return result
    }

    // --- Key Package Generation ---

    /**
     * Create a new KeyPackage for publishing (MIP-00).
     * Used by others to add this user to groups.
     */
    fun createKeyPackage(
        identity: ByteArray,
        signingKey: ByteArray,
        /**
         * The leaf signature keypair to use, when the caller had to generate it
         * up front.
         *
         * A current-profile leaf must carry an account identity proof over its
         * OWN signature key, and that proof is produced by an account signer
         * that may be remote. So the caller generates the keypair, signs the
         * proof against its public half, and hands both back here — the proof
         * cannot be computed after the fact by code that only sees the leaf.
         */
        leafSignatureKeyPair: Ed25519KeyPair? = null,
        leafExtensions: List<Extension> = emptyList(),
        capabilities: Capabilities = policy.defaultLeafCapabilities,
        keyPackageExtensions: List<Extension> = emptyList(),
        /** The leaf's lifetime. Null uses the Marmot window (84 days, backdated an hour for clock skew). */
        lifetime: Lifetime? = null,
    ): KeyPackageBundle {
        val initKp = X25519.generateKeyPair()
        val encKp = X25519.generateKeyPair()
        val sigKp = leafSignatureKeyPair ?: Ed25519.generateKeyPair()

        val leafNode =
            buildLeafNode(
                encryptionKey = encKp.publicKey,
                signatureKey = sigKp.publicKey,
                identity = identity,
                source = LeafNodeSource.KEY_PACKAGE,
                signingKey = sigKp.privateKey,
                capabilities = capabilities,
                leafExtensions = leafExtensions,
                lifetime = lifetime,
            )

        val unsigned =
            MlsKeyPackage(
                initKey = initKp.publicKey,
                leafNode = leafNode,
                extensions = keyPackageExtensions,
                signature = ByteArray(0),
            )
        val kp =
            unsigned.copy(
                signature = MlsCryptoProvider.signWithLabel(sigKp.privateKey, "KeyPackageTBS", unsigned.encodeTbs()),
            )

        return KeyPackageBundle(kp, initKp.privateKey, encKp.privateKey, sigKp.privateKey)
    }

    // --- Proposal Creation ---

    /**
     * Create an Add proposal for a new member.
     */
    fun proposeAdd(keyPackageBytes: ByteArray): Proposal.Add {
        val reader = TlsReader(keyPackageBytes)
        val kp = MlsKeyPackage.decodeTls(reader)
        reader.requireFullyConsumed("KeyPackage")
        // RFC 9420 §10.1 + §7.3: refuse a KeyPackage every receiver would refuse.
        GroupValidation.validateKeyPackage(kp, groupContext, tree, policy, clock())
        val proposal = Proposal.Add(kp)
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /**
     * Create a Remove proposal.
     */
    fun proposeRemove(targetLeafIndex: Int): Proposal.Remove {
        require(targetLeafIndex != myLeafIndex) { "Use SelfRemove to remove yourself, not Remove" }
        require(targetLeafIndex in 0 until tree.leafCount && tree.getLeaf(targetLeafIndex) != null) {
            "Cannot remove blank leaf at index $targetLeafIndex"
        }
        val proposal = Proposal.Remove(targetLeafIndex)
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /**
     * Create a SelfRemove proposal.
     *
     * Gated by [MlsGroupPolicy.authorizeSelfRemove], because a binding may
     * restrict who can leave unilaterally — Marmot makes an admin self-demote
     * through a GroupContextExtensions proposal first. Catching it here rather
     * than on arrival turns a commit every peer would refuse into a local
     * error.
     */
    fun proposeSelfRemove(): Proposal.SelfRemove {
        policy.authorizeSelfRemove(view())
        val proposal = Proposal.SelfRemove()
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /**
     * Create an Update proposal to rotate the signing key within the group.
     *
     * Per MIP-00, members SHOULD perform a self-update within 24 hours
     * of joining a group. This replaces the leaf node with fresh key material,
     * improving forward secrecy.
     *
     * The new signing key pair is generated internally and takes effect
     * after the next Commit.
     *
     * @return the Update proposal (already queued for the next commit)
     */
    fun proposeSigningKeyRotation(): Proposal.Update {
        val newSigKp = Ed25519.generateKeyPair()
        val newEncKp = X25519.generateKeyPair()

        val currentLeaf = tree.getLeaf(myLeafIndex)
        val identity =
            (currentLeaf?.credential as? Credential.Basic)?.identity
                ?: ByteArray(0)

        // An Update replaces our leaf with fresh key material and nothing
        // else. Capabilities and leaf extensions (the account identity proof
        // among them) describe the member, not the keys, so they carry over.
        val newLeafNode =
            buildLeafNode(
                encryptionKey = newEncKp.publicKey,
                signatureKey = newSigKp.publicKey,
                identity = identity,
                source = LeafNodeSource.UPDATE,
                signingKey = newSigKp.privateKey,
                groupId = groupId,
                leafIndex = myLeafIndex,
                capabilities = currentLeaf?.capabilities ?: policy.defaultLeafCapabilities,
                leafExtensions = currentLeaf?.extensions ?: emptyList(),
            )

        val proposal = Proposal.Update(newLeafNode)
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))

        // Stage the new keys. Our own commit folds the rotation into its
        // UpdatePath (RFC 9420 §12.2 forbids committing our own Update), and a
        // peer's commit that applies this Update by reference needs the keys
        // looked up by the new leaf's encryption key.
        pendingSigningKey = newSigKp.privateKey
        pendingEncryptionKey = newEncKp.privateKey
        pendingUpdateKeys[Hex.encode(newEncKp.publicKey)] = PendingUpdateKeys(newEncKp.publicKey, newEncKp.privateKey, newSigKp.privateKey)

        return proposal
    }

    /**
     * What our own leaf should advertise from the next commit on, replacing the
     * capabilities and leaf extensions that a commit's UpdatePath otherwise
     * carries over from our current leaf. Cleared by that commit.
     */
    private var pendingLeafAdvertisement: Pair<Capabilities, List<Extension>>? = null

    /**
     * Make the next [commit] replace our leaf with one advertising [capabilities]
     * and [leafExtensions] (keys are still rotated as usual). This is how a
     * member refreshes a stale leaf, for example to start advertising an app
     * component it gained support for after it joined: a LeafNode's
     * advertisement changes only through an Update or the UpdatePath of its own
     * Commit. Pass the extensions to keep, not only the changed one: whatever is
     * not passed is no longer on the leaf.
     */
    fun advertiseInNextCommit(
        capabilities: Capabilities,
        leafExtensions: List<Extension>,
    ) {
        // Refused here, before anything changes: [commit] would only find out after it has
        // rotated our keys and rewritten the tree, which it cannot undo.
        val required = requiredAppComponents()
        val previous = tree.getLeaf(myLeafIndex)
        val mustKeep = previous?.let { leaf -> advertisedComponents(leaf).filter { it in required } } ?: required.toList()
        val offered = AppDataDictionary.fromExtensions(leafExtensions)?.let { ComponentsList.supportedOrRequired(it) }.orEmpty()
        val dropped = mustKeep.filterNot { it in offered }
        require(dropped.isEmpty()) {
            "The advertisement drops required app components " + dropped.joinToString { "0x" + it.toString(16).padStart(4, '0') }
        }
        pendingLeafAdvertisement = capabilities to leafExtensions
    }

    /**
     * Create a GroupContextExtensions proposal to update the group's extensions.
     * Used for changing group metadata (name, description, etc.) via MIP-01.
     */
    fun proposeGroupContextExtensions(extensions: List<Extension>): Proposal.GroupContextExtensions {
        val proposal = Proposal.GroupContextExtensions(extensions)
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /** The GroupContext `app_data_dictionary`, empty when the group carries none. */
    fun appDataDictionary(): AppDataDictionary = AppDataDictionary.fromExtensionsOrEmpty(groupContext.extensions)

    /**
     * Propose setting one GroupContext app component to [data].
     *
     * Marmot components define their update payload as a full replacement
     * state, so [data] is the component's new value, not a diff.
     *
     * This is the MLS mechanism only. Marmot's own authorization — most
     * component changes are admin-gated, and the resulting state still has to
     * satisfy every component's validation rules — is layered on top and is
     * not enforced here.
     */
    fun proposeAppDataUpdate(
        componentId: Int,
        data: ByteArray,
    ): Proposal.AppDataUpdate {
        val proposal = Proposal.AppDataUpdate.update(componentId, data)
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /** Propose dropping one GroupContext app component entirely. */
    fun proposeAppDataRemoval(componentId: Int): Proposal.AppDataUpdate {
        val proposal = Proposal.AppDataUpdate.remove(componentId)
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /**
     * Create a PSK proposal to include a pre-shared key in the next epoch.
     * The PSK must be registered via registerPsk() before committing.
     */
    fun proposePsk(
        pskId: ByteArray,
        pskNonce: ByteArray = MlsCryptoProvider.randomBytes(MlsCryptoProvider.HASH_OUTPUT_LENGTH),
    ): Proposal.Psk {
        val proposal = Proposal.Psk(PreSharedKeyId.External(pskId, pskNonce))
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /**
     * Propose folding the `resumption_psk` of epoch [pskEpoch] of group
     * [pskGroupId] into the next epoch (RFC 9420 §8.6). A regular commit
     * only takes usage `application`; `reinit` and `branch` belong to the
     * first commit of a successor group.
     */
    fun proposeResumptionPsk(
        pskEpoch: Long,
        pskGroupId: ByteArray = groupId,
        usage: Int = PreSharedKeyId.USAGE_APPLICATION,
        pskNonce: ByteArray = MlsCryptoProvider.randomBytes(MlsCryptoProvider.HASH_OUTPUT_LENGTH),
    ): Proposal.Psk {
        val proposal = Proposal.Psk(PreSharedKeyId.Resumption(usage, pskGroupId, pskEpoch, pskNonce))
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    /**
     * Create a ReInit proposal to reinitialize the group with new parameters.
     * After the commit containing this proposal is processed, the group enters
     * a reinitialization state and a new group must be created.
     */
    fun proposeReInit(
        newGroupId: ByteArray = MlsCryptoProvider.randomBytes(32),
        newVersion: Int = 1,
        newCipherSuite: Int = 1,
        newExtensions: List<Extension> = emptyList(),
    ): Proposal.ReInit {
        val proposal = Proposal.ReInit(newGroupId, newVersion, newCipherSuite, newExtensions)
        pendingProposals.add(PendingProposal(proposal, myLeafIndex))
        return proposal
    }

    // --- Commit ---

    /** A commit built by [stageCommit] that has not been merged or cleared yet. */
    private class StagedCommit(
        val fromEpoch: Long,
        val result: CommitResult,
        val after: StateSnapshot,
    )

    private var pendingCommit: StagedCommit? = null

    /** Whether [stageCommit] built a commit that is waiting for [mergePendingCommit] or [clearPendingCommit]. */
    val hasPendingCommit: Boolean get() = pendingCommit != null

    /**
     * Create a Commit of every pending proposal and apply it at once.
     *
     * Equivalent to [stageCommit] followed by [mergePendingCommit]: use those
     * two when the delivery service may refuse the commit (another member's
     * commit won the epoch), so the group can stay where it was.
     *
     * @param authenticatedData the commit's `authenticated_data`.
     * @param wireFormat [WireFormat.PUBLIC_MESSAGE] (default) or
     *   [WireFormat.PRIVATE_MESSAGE] for [CommitResult.framedCommitBytes].
     * @param includeRatchetTreeInWelcome whether the Welcome's GroupInfo
     *   carries the `ratchet_tree` extension; without it joiners need the
     *   tree delivered out of band (see [processWelcome]).
     * @param paddingLength zero bytes to pad a PrivateMessage commit with.
     */
    fun commit(
        authenticatedData: ByteArray = ByteArray(0),
        wireFormat: WireFormat = WireFormat.PUBLIC_MESSAGE,
        includeRatchetTreeInWelcome: Boolean = true,
        paddingLength: Int = 0,
    ): CommitResult {
        val result = stageCommit(authenticatedData, wireFormat, includeRatchetTreeInWelcome, paddingLength)
        mergePendingCommit()
        return result
    }

    /**
     * Build a Commit of every pending proposal WITHOUT applying it (RFC 9420
     * §12.4.1, §14).
     *
     * The group stays at its current epoch, still reading and sending there.
     * Once the delivery service confirms the commit, [mergePendingCommit]
     * moves the group to the new epoch; if another commit wins instead,
     * process that one (which discards this) or call [clearPendingCommit].
     * Receiving our own staged commit back (an echo of
     * [CommitResult.framedCommitBytes]) merges it.
     *
     * Nothing changes if building the commit fails.
     */
    fun stageCommit(
        authenticatedData: ByteArray = ByteArray(0),
        wireFormat: WireFormat = WireFormat.PUBLIC_MESSAGE,
        includeRatchetTreeInWelcome: Boolean = true,
        paddingLength: Int = 0,
    ): CommitResult {
        check(pendingCommit == null) { "A staged commit is pending: merge or clear it first" }
        val before = captureState()
        try {
            val result = buildCommit(authenticatedData, wireFormat, includeRatchetTreeInWelcome, paddingLength)
            val after = captureState()
            restoreState(before)
            pendingCommit = StagedCommit(before.groupContext.epoch, result, after)
            return result
        } catch (t: Throwable) {
            restoreState(before)
            throw t
        }
    }

    /** Move to the epoch the staged commit creates. */
    fun mergePendingCommit() {
        val staged = checkNotNull(pendingCommit) { "No staged commit to merge" }
        check(epoch == staged.fromEpoch) { "The staged commit was built at epoch ${staged.fromEpoch}, the group is at $epoch" }
        // The epoch we leave is retained as it stands NOW, not as it stood when
        // the commit was staged: messages read since then advanced its ratchets.
        val leaving = captureRetainedEpoch()
        val retainedSoFar = retainedEpochs.toList()
        restoreState(staged.after)
        retainedEpochs.clear()
        retainedEpochs.addAll(retainedSoFar)
        pushRetainedEpoch(leaving)
        pendingCommit = null
    }

    /** Forget the staged commit; the group stays at its current epoch. */
    fun clearPendingCommit() {
        pendingCommit = null
    }

    private fun buildCommit(
        authenticatedData: ByteArray,
        wireFormat: WireFormat,
        includeRatchetTreeInWelcome: Boolean,
        paddingLength: Int,
    ): CommitResult {
        require(wireFormat == WireFormat.PUBLIC_MESSAGE || wireFormat == WireFormat.PRIVATE_MESSAGE) {
            "A commit is sent as a PublicMessage or a PrivateMessage, not $wireFormat"
        }
        check(isLocalMember()) { "Not a member of this group" }
        check(reInitPending == null) { "The group was reinitialized and must not be used to send (RFC 9420 §11.2)" }

        val retainedForThisEpoch = captureRetainedEpoch()

        // Publishers that outer-encrypt a commit do it under the epoch the
        // commit is sent in, so existing members can open it. See
        // CommitResult.preCommitExporterSecret.
        val preCommitExporterSecret =
            policy.commitExporter?.let { exporterSecret(it.label, it.context, it.length) } ?: ByteArray(0)

        // The commit is signed, MACed and (as a PrivateMessage) encrypted under
        // the epoch it is sent in. GroupContextExtensions mutate the context as
        // they apply, so capture it first.
        val preContext = groupContext
        val preContextBytes = preContext.toTlsBytes()
        val preSecrets = epochSecrets
        val preSecretTree = secretTree
        val preSigningKey = signingPrivateKey

        val proposals = selectProposalsForCommit()

        // The application's gate on who may commit what. RFC 9420 has none of
        // its own, so a group with the default policy accepts any valid set.
        policy.authorizeCommit(view(), proposals, myLeafIndex)

        // Inline only what WE authored. A proposal from anyone else goes in by
        // REFERENCE: an inline proposal is attributed to the committer, so
        // inlining someone's SelfRemove would remove the committer instead.
        val proposalOrRefs =
            proposals.map { pending ->
                if (pending.isFrom(myLeafIndex)) {
                    ProposalOrRef.Inline(pending.proposal)
                } else {
                    ProposalOrRef.Reference(Framing.proposalRef(pending.authenticatedContentBytes ?: pending.proposal.toTlsBytes()))
                }
            }

        val applied = applyProposalList(proposals, committer = myLeafIndex)
        val pskSecret = KeySchedule.pskSecret(applied.psks.map { it to requirePsk(it) })

        // RFC 9420 §12.4.1 requires a path for an empty commit and for Update,
        // Remove and GroupContextExtensions proposals; one is always allowed.
        // We send one for anything but a SelfRemove-only commit (forward
        // secrecy is the point of committing), and whenever our own leaf has
        // something to say: a signing-key rotation or a new advertisement.
        val needsPath =
            applied.pathRequired ||
                pendingLeafAdvertisement != null ||
                pendingSigningKey != null ||
                proposals.any { it.proposal !is Proposal.SelfRemove }

        var commitSecret = ByteArray(MlsCryptoProvider.HASH_OUTPUT_LENGTH)
        var generated: TreeKem.GeneratedPath? = null
        val updatePath: UpdatePath? =
            if (needsPath) {
                val previousLeaf = checkNotNull(tree.getLeaf(myLeafIndex)) { "Our leaf is blank" }
                val gen = TreeKem.generate(tree, myLeafIndex)
                val leafParentHash = TreeKem.mergePathKeys(tree, myLeafIndex, gen.nodeKeys.map { it.second })

                // RFC 9420 §7.5: the UpdatePath leaf REPLACES ours. It is the
                // same member, so everything that is not key material carries
                // over — credential, capabilities, leaf extensions — unless an
                // advertisement was queued. A signing-key rotation takes effect
                // here, since our own Update proposal cannot be committed.
                val effectiveSigningKey = pendingSigningKey ?: signingPrivateKey
                val newEncKp = X25519.generateKeyPair()
                val newLeaf =
                    buildLeafNode(
                        encryptionKey = newEncKp.publicKey,
                        signatureKey = Ed25519.publicFromPrivate(effectiveSigningKey),
                        identity = ByteArray(0),
                        credential = previousLeaf.credential,
                        source = LeafNodeSource.COMMIT,
                        signingKey = effectiveSigningKey,
                        groupId = groupId,
                        leafIndex = myLeafIndex,
                        parentHash = leafParentHash,
                        capabilities = pendingLeafAdvertisement?.first ?: previousLeaf.capabilities,
                        leafExtensions = pendingLeafAdvertisement?.second ?: previousLeaf.extensions,
                    )
                GroupValidation.validateLeafNode(newLeaf, LeafNodeSource.COMMIT, groupId, myLeafIndex, tree, myLeafIndex, groupContext.extensions, policy, now = null)
                tree.setLeaf(myLeafIndex, newLeaf)
                // Receivers hold our replacement leaf to the app-component rule;
                // refusing here keeps us from merging a commit every peer rejects.
                enforceRequiredAppComponents(requiredAppComponents(), emptySet(), mapOf(myLeafIndex to previousLeaf))

                encryptionPrivateKey = newEncKp.privateKey
                pathPrivateKeys.clear()
                pathPrivateKeys.putAll(gen.privateKeysByNode())

                // RFC 9420 §12.4.2: path secrets are encrypted under the
                // provisional GroupContext — new epoch, new tree hash, new
                // extensions, the OLD confirmed transcript hash.
                val provisional = groupContext.copy(epoch = preContext.epoch + 1, treeHash = tree.treeHash()).toTlsBytes()
                val nodes = TreeKem.encryptPathSecrets(tree, myLeafIndex, gen, applied.addedLeaves.map { it.first }.toSet(), provisional)
                commitSecret = gen.commitSecret
                generated = gen
                UpdatePath(newLeaf, nodes)
            } else {
                null
            }
        prunePathKeys()

        val commitBytes = Commit(proposalOrRefs, updatePath).toTlsBytes()
        val content =
            FramedContent(
                groupId = preContext.groupId,
                epoch = preContext.epoch,
                sender = Sender(SenderType.MEMBER, myLeafIndex),
                authenticatedData = authenticatedData,
                contentType = ContentType.COMMIT,
                body = commitBytes,
            )
        // The signature is part of the transcript hash, so sign first.
        val signature = Framing.sign(preSigningKey, wireFormat, content, preContextBytes)
        val confirmedTranscriptHash =
            MlsCryptoProvider.hash(interimTranscriptHash + Framing.confirmedTranscriptHashInput(wireFormat, content, signature))

        rememberResumptionPsk()
        groupContext =
            groupContext.copy(
                epoch = preContext.epoch + 1,
                treeHash = tree.treeHash(),
                confirmedTranscriptHash = confirmedTranscriptHash,
            )
        epochSecrets = KeySchedule(groupContext.toTlsBytes()).deriveEpochSecrets(commitSecret, initSecret, pskSecret)
        initSecret = epochSecrets.initSecret
        secretTree = SecretTree(epochSecrets.encryptionSecret, tree.leafCount)
        pushRetainedEpoch(retainedForThisEpoch)

        val confirmationTag = computeConfirmationTag(epochSecrets.confirmationKey, confirmedTranscriptHash)
        interimTranscriptHash = interimTranscriptHashOf(confirmedTranscriptHash, confirmationTag)

        val framedCommitBytes =
            when (wireFormat) {
                WireFormat.PRIVATE_MESSAGE -> {
                    val keyNonce = preSecretTree.nextHandshakeKeyNonce(myLeafIndex)
                    MlsMessage
                        .fromPrivateMessage(
                            PrivateMessageCodec.seal(content, signature, confirmationTag, keyNonce, preSecrets.senderDataSecret, paddingLength),
                        ).toTlsBytes()
                }

                else -> {
                    val membershipTag = Framing.membershipTag(preSecrets.membershipKey, content, preContextBytes, signature, confirmationTag)
                    MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, confirmationTag, membershipTag)).toTlsBytes()
                }
            }

        val welcomeBytes =
            if (applied.addedLeaves.isNotEmpty()) {
                buildWelcome(applied.addedLeaves, generated, applied.psks, includeRatchetTreeInWelcome)
            } else {
                null
            }

        pendingSigningKey?.let { signingPrivateKey = it }
        pendingSigningKey = null
        pendingEncryptionKey = null
        pendingLeafAdvertisement = null
        pendingUpdateKeys.clear()
        pendingProposals.clear()
        sentKeys.clear()
        applied.reInit?.let { reInitPending = it }

        return CommitResult(
            commitBytes = commitBytes,
            welcomeBytes = welcomeBytes,
            groupInfoBytes = null,
            framedCommitBytes = framedCommitBytes,
            preCommitExporterSecret = preCommitExporterSecret,
        )
    }

    /**
     * The pending proposals a commit of ours can carry, chosen the way RFC 9420
     * §12.2 asks a committer to when the pool holds conflicting ones: a Remove
     * beats an Update of the same leaf, the newest Update of a leaf wins, other
     * proposals beat a ReInit, the last GroupContextExtensions wins, and the
     * first of several identical PSKs or Adds of one client is kept.
     *
     * Our own Updates are left out — the UpdatePath carries the rotation — as
     * are proposals that would remove us: a committer cannot commit its own
     * removal.
     */
    private fun selectProposalsForCommit(): List<PendingProposal> {
        check(pendingProposals.none { it.isFrom(myLeafIndex) && it.proposal is Proposal.SelfRemove }) {
            "A member cannot commit its own SelfRemove: send it with buildSelfRemoveProposalMessage for another member to commit"
        }
        val candidates =
            pendingProposals.filterNot { p ->
                (p.isFrom(myLeafIndex) && (p.proposal is Proposal.Update || p.proposal is Proposal.SelfRemove)) ||
                    (p.proposal is Proposal.Remove && p.proposal.removedLeafIndex == myLeafIndex)
            }

        val removed = mutableSetOf<Int>()
        candidates.forEach { p -> removedLeafOf(p)?.let { removed.add(it) } }

        val lastUpdateFor = mutableMapOf<Int, PendingProposal>()
        candidates.forEach { p -> if (p.proposal is Proposal.Update) lastUpdateFor[p.senderLeafIndex] = p }
        val lastGce = candidates.lastOrNull { it.proposal is Proposal.GroupContextExtensions }

        val removedSeen = mutableSetOf<Int>()
        val pskSeen = mutableSetOf<String>()
        val addKeysSeen = mutableSetOf<String>()
        val memberKeys =
            (0 until tree.leafCount)
                .filter { it !in removed }
                .mapNotNull { tree.getLeaf(it)?.signatureKey?.let(Hex::encode) }
                .toSet()

        val selected =
            candidates.filter { p ->
                when (val q = p.proposal) {
                    is Proposal.Update -> p.senderLeafIndex !in removed && lastUpdateFor[p.senderLeafIndex] === p
                    is Proposal.Remove -> removedSeen.add(q.removedLeafIndex)
                    is Proposal.SelfRemove -> removedSeen.add(p.senderLeafIndex)
                    is Proposal.GroupContextExtensions -> p === lastGce
                    is Proposal.Psk -> pskSeen.add(q.psk.identityKey())
                    is Proposal.Add -> Hex.encode(q.keyPackage.leafNode.signatureKey).let { it !in memberKeys && addKeysSeen.add(it) }
                    else -> true
                }
            }

        val reInits = selected.filter { it.proposal is Proposal.ReInit }
        return when {
            reInits.isEmpty() -> selected
            selected.size > reInits.size -> selected - reInits.toSet()
            else -> listOf(reInits.last())
        }
    }

    /** The leaf a Remove or SelfRemove takes out, or null for any other proposal. */
    private fun removedLeafOf(p: PendingProposal): Int? =
        when (val q = p.proposal) {
            is Proposal.Remove -> q.removedLeafIndex
            is Proposal.SelfRemove -> p.senderLeafIndex
            else -> null
        }

    /** What applying a commit's proposal list produced. */
    private class AppliedProposals(
        /** New leaves and the KeyPackages that filled them, in proposal order. */
        val addedLeaves: List<Pair<Int, MlsKeyPackage>>,
        /** PreSharedKey IDs in proposal order — the order `psk_secret` uses. */
        val psks: List<PreSharedKeyId>,
        val externalInit: Proposal.ExternalInit?,
        val reInit: Proposal.ReInit?,
        /** The leaf an external commit's Remove took out (a resync), before it was blanked. */
        val resyncedLeaf: LeafNode?,
        /** RFC 9420 §12.4.2: whether the commit MUST carry an UpdatePath. */
        val pathRequired: Boolean,
    )

    /**
     * RFC 9420 §12.2 + §12.3: validate a commit's proposal list and apply it to
     * the tree and GroupContext. Shared by the committer and every receiver,
     * so both run exactly the same rules.
     *
     * @param committer the committer's leaf, or null for an external commit.
     */
    private fun applyProposalList(
        proposals: List<PendingProposal>,
        committer: Int?,
    ): AppliedProposals {
        validateProposalList(proposals, committer)

        val requiredComponentsBefore = requiredAppComponents()
        val replacedLeaves = mutableMapOf<Int, LeafNode?>()

        // §12.3 order: GroupContextExtensions, Update, Remove, Add. App-data
        // updates edit the dictionary a GroupContextExtensions just installed.
        val gce = proposals.firstNotNullOfOrNull { it.proposal as? Proposal.GroupContextExtensions }
        gce?.let { groupContext = groupContext.copy(extensions = it.extensions) }
        applyAppDataUpdateProposals(proposals.mapNotNull { it.proposal as? Proposal.AppDataUpdate })

        for (p in proposals) {
            val update = p.proposal as? Proposal.Update ?: continue
            val leafIndex = p.senderLeafIndex
            val previous = checkNotNull(tree.getLeaf(leafIndex))
            GroupValidation.validateLeafNode(update.leafNode, LeafNodeSource.UPDATE, groupId, leafIndex, tree, leafIndex, groupContext.extensions, policy, now = null)
            require(!update.leafNode.encryptionKey.contentEquals(previous.encryptionKey)) {
                "Update proposal reuses leaf $leafIndex's encryption key"
            }
            replacedLeaves[leafIndex] = previous
            tree.updateLeaf(leafIndex, update.leafNode)
            if (leafIndex == myLeafIndex) adoptUpdateKeys(update.leafNode)
        }

        var resyncedLeaf: LeafNode? = null
        for (p in proposals) {
            val removed = removedLeafOf(p) ?: continue
            if (committer == null) resyncedLeaf = tree.getLeaf(removed)
            tree.removeLeaf(removed)
        }

        val added =
            proposals.mapNotNull { it.proposal as? Proposal.Add }.map { add ->
                // Validated against the tree as it stands after the Removes, so
                // re-adding a client this commit removes is allowed (§12.2).
                GroupValidation.validateKeyPackage(add.keyPackage, groupContext, tree, policy, clock())
                tree.addLeaf(add.keyPackage.leafNode) to add.keyPackage
            }

        enforceRequiredCapabilities()
        // RFC 9420 §13.4: an extension in use by the group MUST be supported by
        // all members — judged over the membership after this commit. The RFC's
        // default types cannot be listed in capabilities and are exempt, as are
        // the types the binding declares.
        if (gce != null) {
            for (ext in groupContext.extensions) {
                require(
                    ext.extensionType in DEFAULT_EXTENSION_TYPES ||
                        ext.extensionType in policy.knownExtensionTypes ||
                        allMembersSupportExtension(ext.extensionType),
                ) { "Unsupported extension type: ${ext.extensionType}" }
            }
        }
        enforceRequiredAppComponents(requiredComponentsBefore, added.map { it.first }.toSet(), replacedLeaves)

        return AppliedProposals(
            addedLeaves = added,
            psks = proposals.mapNotNull { (it.proposal as? Proposal.Psk)?.psk },
            externalInit = proposals.firstNotNullOfOrNull { it.proposal as? Proposal.ExternalInit },
            reInit = proposals.firstNotNullOfOrNull { it.proposal as? Proposal.ReInit },
            resyncedLeaf = resyncedLeaf,
            pathRequired =
                proposals.isEmpty() ||
                    proposals.any {
                        it.proposal is Proposal.Update ||
                            it.proposal is Proposal.Remove ||
                            it.proposal is Proposal.ExternalInit ||
                            it.proposal is Proposal.GroupContextExtensions
                    },
        )
    }

    /**
     * RFC 9420 §12.2 Proposal List Validation (the parts that do not need the
     * tree mutated first; leaf and KeyPackage validity are checked as each
     * proposal applies, in [applyProposalList]).
     */
    private fun validateProposalList(
        proposals: List<PendingProposal>,
        committer: Int?,
    ) {
        if (committer == null) {
            require(proposals.count { it.proposal is Proposal.ExternalInit } == 1) { "An external commit carries exactly one ExternalInit" }
            require(proposals.count { it.proposal is Proposal.Remove } <= 1) { "An external commit removes at most one leaf" }
            require(proposals.all { it.proposal is Proposal.ExternalInit || it.proposal is Proposal.Remove || it.proposal is Proposal.Psk }) {
                "An external commit may carry only ExternalInit, Remove and PreSharedKey proposals"
            }
        }

        val touchedLeaves = mutableSetOf<Int>()
        val pskIds = mutableSetOf<String>()
        var gceCount = 0
        for (p in proposals) {
            when (val q = p.proposal) {
                is Proposal.Add -> {
                    Unit
                }

                is Proposal.Update -> {
                    require(p.senderType == SenderType.MEMBER && isLiveLeaf(p.senderLeafIndex)) { "Update proposal from a non-member" }
                    require(p.senderLeafIndex != committer) { "A commit must not carry the committer's own Update proposal" }
                    require(touchedLeaves.add(p.senderLeafIndex)) { "Multiple Update/Remove proposals for leaf ${p.senderLeafIndex}" }
                }

                is Proposal.Remove -> {
                    require(isLiveLeaf(q.removedLeafIndex)) {
                        if (q.removedLeafIndex >= tree.leafCount) {
                            "Remove target leaf index ${q.removedLeafIndex} out of range"
                        } else {
                            "Cannot remove blank leaf at index ${q.removedLeafIndex}"
                        }
                    }
                    require(q.removedLeafIndex != committer) { "A commit must not remove its committer; use SelfRemove to leave" }
                    require(touchedLeaves.add(q.removedLeafIndex)) { "Multiple Update/Remove proposals for leaf ${q.removedLeafIndex}" }
                }

                is Proposal.SelfRemove -> {
                    require(p.senderType == SenderType.MEMBER && isLiveLeaf(p.senderLeafIndex)) { "SelfRemove from a non-member" }
                    require(p.senderLeafIndex != committer) { "A committer cannot commit its own SelfRemove" }
                    require(touchedLeaves.add(p.senderLeafIndex)) { "Multiple Update/Remove proposals for leaf ${p.senderLeafIndex}" }
                }

                is Proposal.Psk -> {
                    require(pskIds.add(q.psk.identityKey())) { "Multiple PreSharedKey proposals for ${q.psk.identityKey()}" }
                    require(q.psk.pskNonce.size == MlsCryptoProvider.HASH_OUTPUT_LENGTH) { "psk_nonce must be KDF.Nh bytes" }
                    val psk = q.psk
                    if (psk is PreSharedKeyId.Resumption) {
                        require(psk.usage == PreSharedKeyId.USAGE_APPLICATION) { "A regular commit only takes resumption PSKs of usage application" }
                    }
                    requireNotNull(resolvePsk(q.psk)) { "PSK not available: ${q.psk.identityKey()}" }
                }

                is Proposal.ReInit -> {
                    require(proposals.size == 1) { "A ReInit proposal must be committed alone" }
                    require(q.version >= groupContext.version) { "ReInit to an older protocol version" }
                }

                is Proposal.GroupContextExtensions -> {
                    gceCount++
                }

                is Proposal.ExternalInit -> {
                    require(committer == null) { "Only an external commit may carry ExternalInit" }
                }

                is Proposal.AppDataUpdate -> {
                    Unit
                }
            }
        }
        require(gceCount <= 1) { "Multiple GroupContextExtensions proposals" }

        // A non-default proposal type must be supported by every member that
        // processes the commit — the ones it neither adds nor removes.
        val removed = proposals.mapNotNull { removedLeafOf(it) }.toSet()
        for (type in proposals.map { it.proposal.proposalType.value }.toSet()) {
            if (type in GroupValidation.DEFAULT_PROPOSAL_TYPES) continue
            for (i in 0 until tree.leafCount) {
                if (i in removed) continue
                val leaf = tree.getLeaf(i) ?: continue
                require(type in leaf.capabilities.proposals) {
                    "Member leaf $i does not support proposal type 0x${type.toString(16).padStart(4, '0')}"
                }
            }
        }
    }

    private fun isLiveLeaf(leafIndex: Int): Boolean = leafIndex in 0 until tree.leafCount && tree.getLeaf(leafIndex) != null

    /** Someone else's commit applied our Update by reference: switch to the keys behind it. */
    private fun adoptUpdateKeys(leaf: LeafNode) {
        val keys =
            checkNotNull(pendingUpdateKeys[Hex.encode(leaf.encryptionKey)]) {
                "A commit applies an Update to our leaf whose keys we do not hold"
            }
        encryptionPrivateKey = keys.encryptionPrivateKey
        signingPrivateKey = keys.signaturePrivateKey
        if (pendingSigningKey.contentEqualsOrNull(keys.signaturePrivateKey)) {
            pendingSigningKey = null
            pendingEncryptionKey = null
        }
    }

    private fun ByteArray?.contentEqualsOrNull(other: ByteArray): Boolean = this != null && contentEquals(other)

    // --- Message Encryption ---

    /**
     * Encrypt an application message as a PrivateMessage (RFC 9420 §6.3).
     *
     * [authenticatedData] is sent in the clear as the message's
     * `authenticated_data` (RFC 9420 §6.3.2). It is bound to the message by the
     * AEAD and the signature, and returned by [decrypt].
     */
    fun encrypt(
        plaintext: ByteArray,
        /**
         * MLS `authenticated_data`: authenticated but NOT encrypted.
         *
         * The AEAD covers it, so a recipient knows the sender wrote it and the
         * delivery service cannot alter it — but the delivery service can read
         * it, which is the whole trade. RFC 9420 §6 leaves the contents to the
         * application.
         *
         * cordn puts the sender's account pubkey here and rejects any
         * application message that arrives with this field empty, because that
         * is what binds an unsigned envelope to an MLS sender. Marmot leaves it
         * empty and carries the same binding elsewhere. Empty is the default
         * because a binding that does not use the field should not be paying a
         * metadata cost for it.
         */
        authenticatedData: ByteArray = ByteArray(0),
        /** Zero bytes appended inside the ciphertext to hide the message length (RFC 9420 §16.3). */
        paddingLength: Int = 0,
    ): ByteArray {
        check(reInitPending == null) { "The group was reinitialized and must not be used to send (RFC 9420 §11.2)" }
        trimSentKeys()
        val keyNonce = secretTree.nextApplicationKeyNonce(myLeafIndex)
        sentKeys[keyNonce.generation] = keyNonce
        val content = ownContent(ContentType.APPLICATION, plaintext, authenticatedData)
        val signature = Framing.sign(signingPrivateKey, WireFormat.PRIVATE_MESSAGE, content, groupContext.toTlsBytes())
        val message = PrivateMessageCodec.seal(content, signature, null, keyNonce, epochSecrets.senderDataSecret, paddingLength)
        return MlsMessage.fromPrivateMessage(message).toTlsBytes()
    }

    private fun trimSentKeys() {
        if (sentKeys.size > MAX_SENT_KEYS) {
            sentKeys.keys
                .sorted()
                .take(sentKeys.size - MAX_SENT_KEYS)
                .forEach { sentKeys.remove(it) }
        }
    }

    private fun ownContent(
        contentType: ContentType,
        body: ByteArray,
        authenticatedData: ByteArray,
    ) = FramedContent(groupId, epoch, Sender(SenderType.MEMBER, myLeafIndex), authenticatedData, contentType, body)

    /**
     * Send [proposal] on its own, by reference (RFC 9420 §12.1), framed as a
     * PublicMessage or a PrivateMessage.
     *
     * The proposal joins our pending pool carrying the AuthenticatedContent it
     * was sent in — what a ProposalRef hashes — so a commit by any member that
     * references it resolves here too. A proposal already staged by one of the
     * `propose*` functions is the one sent, not a second copy.
     *
     * @return the MLSMessage bytes to deliver to the group.
     */
    fun proposalMessage(
        proposal: Proposal,
        wireFormat: WireFormat = WireFormat.PUBLIC_MESSAGE,
        authenticatedData: ByteArray = ByteArray(0),
        paddingLength: Int = 0,
    ): ByteArray {
        require(wireFormat == WireFormat.PUBLIC_MESSAGE || wireFormat == WireFormat.PRIVATE_MESSAGE) {
            "A proposal is sent as a PublicMessage or a PrivateMessage, not $wireFormat"
        }
        require(proposal !is Proposal.ExternalInit) { "ExternalInit only travels inside an external commit" }
        check(isLocalMember()) { "Not a member of this group" }
        check(reInitPending == null) { "The group was reinitialized and must not be used to send (RFC 9420 §11.2)" }

        val contextBytes = groupContext.toTlsBytes()
        val content = ownContent(ContentType.PROPOSAL, proposal.toTlsBytes(), authenticatedData)
        val signature = Framing.sign(signingPrivateKey, wireFormat, content, contextBytes)
        val messageBytes =
            when (wireFormat) {
                WireFormat.PRIVATE_MESSAGE -> {
                    val keyNonce = secretTree.nextHandshakeKeyNonce(myLeafIndex)
                    MlsMessage
                        .fromPrivateMessage(PrivateMessageCodec.seal(content, signature, null, keyNonce, epochSecrets.senderDataSecret, paddingLength))
                        .toTlsBytes()
                }

                else -> {
                    val membershipTag = Framing.membershipTag(epochSecrets.membershipKey, content, contextBytes, signature, null)
                    MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, null, membershipTag)).toTlsBytes()
                }
            }

        val pending =
            PendingProposal(
                proposal = proposal,
                senderLeafIndex = myLeafIndex,
                authenticatedContentBytes = Framing.authenticatedContent(wireFormat, content, signature),
            )
        val staged = pendingProposals.indexOfFirst { it.proposal === proposal && it.isFrom(myLeafIndex) }
        if (staged >= 0) pendingProposals[staged] = pending else pendingProposals.add(pending)
        if (sentProposalMessages.size >= MAX_SENT_PROPOSAL_MESSAGES) sentProposalMessages.clear()
        sentProposalMessages[Hex.encode(MlsCryptoProvider.hash(messageBytes))] = SentProposal(pending, authenticatedData)
        return messageBytes
    }

    /** A proposal we sent, remembered by its message bytes so the delivery service's echo is recognised. */
    private class SentProposal(
        val pending: PendingProposal,
        val authenticatedData: ByteArray,
    )

    /**
     * Our own proposal messages of this epoch, by hash. We cannot decrypt our
     * own handshake PrivateMessage again (its ratchet key is spent), so an
     * echo is recognised by its bytes, the way a staged commit's is.
     */
    private val sentProposalMessages = mutableMapOf<String, SentProposal>()

    /** The pool entry [messageBytes] staged when we sent it, if it is our own proposal still pending. */
    private fun ownProposalEcho(messageBytes: ByteArray): SentProposal? {
        val sent = sentProposalMessages[Hex.encode(MlsCryptoProvider.hash(messageBytes))] ?: return null
        return sent.takeIf { s -> pendingProposals.any { it === s.pending } }
    }

    /**
     * Encrypt a standalone Proposal as a PrivateMessage. Same as
     * [proposalMessage] with [WireFormat.PRIVATE_MESSAGE].
     */
    @InternalMlsApi
    fun encryptProposalAsPrivateMessage(proposal: Proposal): ByteArray = proposalMessage(proposal, WireFormat.PRIVATE_MESSAGE)

    /**
     * Decrypt an application message from a PrivateMessage.
     * Returns null if decryption fails (e.g., corrupted message, wrong epoch).
     */
    fun decryptOrNull(messageBytes: ByteArray): DecryptedMessage? =
        try {
            decrypt(messageBytes)
        } catch (_: Exception) {
            null
        }

    /**
     * Sender-data decryption, ratchet key lookup and content AEAD for a
     * PrivateMessage against the given epoch material (RFC 9420 §6.3).
     * Shared by [decrypt] (current epoch) and [decryptFormerEpoch].
     */
    private fun openPrivateMessage(
        privMsg: PrivateMessage,
        senderDataSecret: ByteArray,
        tree: RatchetTree,
        secretTree: SecretTree,
        allowOwnSentKeys: Boolean,
    ): PrivateMessageCodec.Opened {
        val senderData = PrivateMessageCodec.openSenderData(privMsg, senderDataSecret)
        val senderLeafIndex = senderData.leafIndex

        // RFC 9420 §6.3.2: the sender must be a member of the group.
        require(senderLeafIndex in 0 until tree.leafCount) {
            "Sender leaf index $senderLeafIndex out of range [0, ${tree.leafCount})"
        }
        require(tree.getLeaf(senderLeafIndex) != null) {
            "Sender leaf is blank at index $senderLeafIndex (not a group member)"
        }

        // Application content uses the application ratchet; proposals and
        // commits the handshake ratchet (RFC 9420 §9).
        val keyNonce =
            if (allowOwnSentKeys && privMsg.contentType == ContentType.APPLICATION && senderLeafIndex == myLeafIndex && sentKeys.containsKey(senderData.generation)) {
                sentKeys.remove(senderData.generation)!!
            } else {
                when (privMsg.contentType) {
                    ContentType.APPLICATION -> secretTree.applicationKeyNonceForGeneration(senderLeafIndex, senderData.generation)
                    ContentType.COMMIT, ContentType.PROPOSAL -> secretTree.handshakeKeyNonceForGeneration(senderLeafIndex, senderData.generation)
                }
            }
        return PrivateMessageCodec.openContent(privMsg, senderData, keyNonce)
    }

    /** Signature-checks an opened APPLICATION PrivateMessage against the given tree/context. */
    private fun applicationFromOpened(
        opened: PrivateMessageCodec.Opened,
        tree: RatchetTree,
        groupContext: GroupContext,
    ): DecryptedMessage {
        val content = opened.content
        val senderLeaf =
            requireNotNull(tree.getLeaf(content.sender.leafIndex)) {
                "Sender leaf is blank at index ${content.sender.leafIndex}"
            }
        require(Framing.verify(senderLeaf.signatureKey, WireFormat.PRIVATE_MESSAGE, content, groupContext.toTlsBytes(), opened.signature)) {
            "FramedContentTBS signature verification failed"
        }
        return DecryptedMessage(
            senderLeafIndex = content.sender.leafIndex,
            contentType = content.contentType,
            content = content.body,
            epoch = content.epoch,
            authenticatedData = content.authenticatedData,
        )
    }

    /**
     * Opens an APPLICATION message sealed in a retained former epoch: one from
     * a member that had not yet seen the latest commit (RFC 9420 §15.2 asks
     * receivers to keep recent epochs' keys for exactly this).
     *
     * Same checks as [decrypt] against that epoch's tree and GroupContext,
     * signature included, and the epoch's ratchet is written back so a
     * generation opens only once. Handshake messages from a former epoch are
     * refused, as is an epoch no longer retained.
     */
    fun decryptFormerEpoch(messageBytes: ByteArray): DecryptedMessage {
        val mlsMsg = MlsMessage.decodeTls(TlsReader(messageBytes))
        require(mlsMsg.wireFormat == WireFormat.PRIVATE_MESSAGE) { "Expected PrivateMessage" }
        val privMsg = decodePrivateMessage(mlsMsg)
        require(privMsg.epoch < epoch) { "Message epoch ${privMsg.epoch} is not a former epoch (current $epoch)" }
        require(privMsg.contentType == ContentType.APPLICATION) { "Only application messages can be read from a former epoch" }
        require(privMsg.groupId.contentEquals(groupId)) { "Message group ID doesn't match current group" }

        val index = retainedEpochs.indexOfFirst { it.epoch == privMsg.epoch }
        require(index >= 0) {
            "Message epoch ${privMsg.epoch} is no longer retained (oldest kept: ${retainedEpochs.firstOrNull()?.epoch ?: "none"})"
        }
        val retained = retainedEpochs[index]
        val formerTree = RatchetTree.decodeTls(TlsReader(retained.treeBytes))
        val formerSecrets = SecretTree(retained.encryptionSecret, formerTree.leafCount)
        formerSecrets.importSenderStates(retained.senderRatchetStates)
        formerSecrets.importSkippedSecrets(retained.skippedApplicationSecrets, emptyMap())
        if (retained.nodeSecrets.isNotEmpty()) formerSecrets.importNodeSecrets(retained.nodeSecrets)

        val opened = openPrivateMessage(privMsg, retained.senderDataSecret, formerTree, formerSecrets, allowOwnSentKeys = false)
        val decrypted = applicationFromOpened(opened, formerTree, retained.groupContext)
        retainedEpochs[index] =
            retained.copy(
                senderRatchetStates = formerSecrets.exportSenderStates(),
                skippedApplicationSecrets = formerSecrets.exportSkippedApplicationSecrets(),
                nodeSecrets = formerSecrets.exportNodeSecrets(),
            )
        return decrypted
    }

    /** Exporter secrets of the retained former epochs, by epoch, for keys an application derives per epoch. */
    fun formerExporterSecrets(): Map<Long, ByteArray> = retainedEpochs.associate { it.epoch to it.exporterSecret }

    private fun decodePrivateMessage(mlsMsg: MlsMessage): PrivateMessage {
        val reader = TlsReader(mlsMsg.payload)
        return PrivateMessage.decodeTls(reader).also { reader.requireFullyConsumed("PrivateMessage") }
    }

    private fun decodePublicMessage(mlsMsg: MlsMessage): PublicMessage {
        val reader = TlsReader(mlsMsg.payload)
        return PublicMessage.decodeTls(reader).also { reader.requireFullyConsumed("PublicMessage") }
    }

    /**
     * Decrypt a PrivateMessage (RFC 9420 §6.3) of any content type.
     *
     * An application message is returned; a proposal is validated and staged
     * for a later commit; a commit is applied, advancing the epoch. In all
     * three cases [DecryptedMessage.content] holds the plaintext body.
     *
     * @throws IllegalArgumentException if the message format is invalid or decryption fails
     */
    fun decrypt(messageBytes: ByteArray): DecryptedMessage = decryptAndStage(messageBytes).first

    /** [decrypt], plus the pool entry a proposal was staged as. */
    private fun decryptAndStage(messageBytes: ByteArray): Pair<DecryptedMessage, PendingProposal?> {
        val mlsMsg = MlsMessage.decodeTls(TlsReader(messageBytes))
        require(mlsMsg.wireFormat == WireFormat.PRIVATE_MESSAGE) { "Expected PrivateMessage" }
        val privMsg = decodePrivateMessage(mlsMsg)

        mergeIfOwnStagedCommit(messageBytes)?.let { staged ->
            return DecryptedMessage(myLeafIndex, ContentType.COMMIT, staged.result.commitBytes, staged.fromEpoch) to null
        }
        ownProposalEcho(messageBytes)?.let { sent ->
            return DecryptedMessage(myLeafIndex, ContentType.PROPOSAL, sent.pending.proposal.toTlsBytes(), epoch, sent.authenticatedData) to sent.pending
        }

        // Verify epoch and group ID match current state (RFC 9420 Section 6.1)
        require(privMsg.epoch == epoch) {
            "Message epoch ${privMsg.epoch} doesn't match current epoch $epoch"
        }
        require(privMsg.groupId.contentEquals(groupId)) {
            "Message group ID doesn't match current group"
        }

        val opened = openPrivateMessage(privMsg, epochSecrets.senderDataSecret, tree, secretTree, allowOwnSentKeys = true)
        val content = opened.content
        return when (content.contentType) {
            ContentType.APPLICATION -> {
                applicationFromOpened(opened, tree, groupContext) to null
            }

            ContentType.PROPOSAL -> {
                val senderLeaf = checkNotNull(tree.getLeaf(content.sender.leafIndex))
                require(Framing.verify(senderLeaf.signatureKey, WireFormat.PRIVATE_MESSAGE, content, groupContext.toTlsBytes(), opened.signature)) {
                    "FramedContentTBS signature verification failed on PrivateMessage proposal"
                }
                val pending = receiveProposal(content, WireFormat.PRIVATE_MESSAGE, opened.signature)
                DecryptedMessage(content.sender.leafIndex, content.contentType, content.body, content.epoch, content.authenticatedData) to pending
            }

            ContentType.COMMIT -> {
                atomically { applyCommit(content, WireFormat.PRIVATE_MESSAGE, opened.signature, requireNotNull(opened.confirmationTag)) }
                DecryptedMessage(content.sender.leafIndex, content.contentType, content.body, content.epoch, content.authenticatedData) to null
            }
        }
    }

    /**
     * Process any MLSMessage addressed to this group (RFC 9420 §6): a
     * PublicMessage or PrivateMessage carrying an application message, a
     * proposal or a commit.
     *
     * Proposals are authenticated, validated and staged in the pending pool;
     * commits are applied atomically — on any failure the group is left
     * exactly as it was. An echo of our own staged commit merges it.
     */
    fun processMessage(messageBytes: ByteArray): ProcessedMessage {
        val mlsMsg = MlsMessage.decodeTls(TlsReader(messageBytes))
        if (mergeIfOwnStagedCommit(messageBytes) != null) {
            return ProcessedMessage.AppliedCommit(Sender(SenderType.MEMBER, myLeafIndex), epoch, removedSelf = false)
        }
        ownProposalEcho(messageBytes)?.let { sent ->
            return ProcessedMessage.StagedProposal(sent.pending.proposal, Sender(SenderType.MEMBER, myLeafIndex), Framing.proposalRef(sent.pending.authenticatedContentBytes!!))
        }
        return when (mlsMsg.wireFormat) {
            WireFormat.PRIVATE_MESSAGE -> {
                val (decrypted, pending) = decryptAndStage(messageBytes)
                when (decrypted.contentType) {
                    ContentType.APPLICATION -> {
                        ProcessedMessage.Application(decrypted)
                    }

                    ContentType.PROPOSAL -> {
                        val staged = checkNotNull(pending)
                        ProcessedMessage.StagedProposal(staged.proposal, Sender(SenderType.MEMBER, decrypted.senderLeafIndex), Framing.proposalRef(staged.authenticatedContentBytes!!))
                    }

                    ContentType.COMMIT -> {
                        ProcessedMessage.AppliedCommit(Sender(SenderType.MEMBER, decrypted.senderLeafIndex), epoch, removedSelf = !isLocalMember())
                    }
                }
            }

            WireFormat.PUBLIC_MESSAGE -> {
                val pubMsg = decodePublicMessage(mlsMsg)
                when (pubMsg.contentType) {
                    ContentType.APPLICATION -> {
                        throw IllegalArgumentException("Application messages MUST be sent as PrivateMessage (RFC 9420 §6.2)")
                    }

                    ContentType.PROPOSAL -> {
                        val pending = receivePublicProposal(pubMsg)
                        ProcessedMessage.StagedProposal(pending.proposal, pubMsg.sender, Framing.proposalRef(pending.authenticatedContentBytes!!))
                    }

                    ContentType.COMMIT -> {
                        processPublicCommit(pubMsg)
                        ProcessedMessage.AppliedCommit(pubMsg.sender, epoch, removedSelf = !isLocalMember())
                    }
                }
            }

            else -> {
                throw IllegalArgumentException("${mlsMsg.wireFormat} is not a message for an existing group")
            }
        }
    }

    /** When [messageBytes] is our own staged commit coming back, merge it and return what was merged. */
    private fun mergeIfOwnStagedCommit(messageBytes: ByteArray): StagedCommit? {
        val staged = pendingCommit ?: return null
        if (!staged.result.framedCommitBytes.contentEquals(messageBytes)) return null
        mergePendingCommit()
        return staged
    }

    // --- Commit Processing ---

    /**
     * Process a fully-framed `MlsMessage(PublicMessage(Commit))`, such as
     * [CommitResult.framedCommitBytes] or [ExternalJoinResult.framedCommitBytes].
     * Verifies the RFC 9420 §6.2 membership_tag of a member's commit, then
     * applies it atomically. An echo of our own staged commit merges it.
     */
    fun processFramedCommit(framedCommitBytes: ByteArray) {
        val mlsMessage = MlsMessage.decodeTls(TlsReader(framedCommitBytes))
        require(mlsMessage.wireFormat == WireFormat.PUBLIC_MESSAGE) {
            "processFramedCommit expects a PublicMessage envelope, got ${mlsMessage.wireFormat}"
        }
        if (mergeIfOwnStagedCommit(framedCommitBytes) != null) return
        val pubMsg = decodePublicMessage(mlsMessage)
        require(pubMsg.contentType == ContentType.COMMIT) {
            "Framed commit must contain ContentType.COMMIT, got ${pubMsg.contentType}"
        }
        processPublicCommit(pubMsg)
    }

    private fun processPublicCommit(pubMsg: PublicMessage) {
        val tag = requireNotNull(pubMsg.confirmationTag) { "PublicMessage commit missing confirmation_tag" }
        require(pubMsg.groupId.contentEquals(groupId)) { "Commit group ID doesn't match current group" }
        require(pubMsg.epoch == epoch) { "Commit epoch ${pubMsg.epoch} doesn't match current epoch $epoch" }
        // RFC 9420 §6.2: a member's PublicMessage carries a membership_tag; an
        // external commit's sender is not a member yet and carries none.
        if (pubMsg.sender.senderType == SenderType.MEMBER) {
            require(verifyPublicMessageCommitMembershipTag(pubMsg)) {
                "Invalid membership_tag on PublicMessage commit"
            }
        }
        atomically { applyCommit(pubMsg.framedContent(), WireFormat.PUBLIC_MESSAGE, pubMsg.signature, tag) }
    }

    /**
     * Process a received Commit given its parts, advancing the epoch.
     *
     * Prefer [processFramedCommit] or [processMessage], which take the framed
     * message and check everything its envelope carries.
     *
     * @param commitBytes TLS-serialized Commit
     * @param senderLeafIndex the committer's leaf index (ignored for an
     *   external commit, which carries an ExternalInit and has no leaf yet)
     * @param confirmationTag the FramedContentAuthData confirmation_tag
     * @param signature FramedContentAuthData.signature
     * @param wireFormat the wire format the commit arrived in
     * @param authenticatedData the commit's `authenticated_data`
     */
    fun processCommit(
        commitBytes: ByteArray,
        senderLeafIndex: Int,
        confirmationTag: ByteArray,
        signature: ByteArray = ByteArray(0),
        wireFormat: WireFormat = WireFormat.PUBLIC_MESSAGE,
        authenticatedData: ByteArray = ByteArray(0),
    ) {
        val commit = Commit.decodeTls(TlsReader(commitBytes))
        val isExternal = commit.proposals.any { it is ProposalOrRef.Inline && it.proposal is Proposal.ExternalInit }
        val sender = if (isExternal) Sender(SenderType.NEW_MEMBER_COMMIT) else Sender(SenderType.MEMBER, senderLeafIndex)
        val content = FramedContent(groupId, epoch, sender, authenticatedData, ContentType.COMMIT, commitBytes)
        atomically { applyCommit(content, wireFormat, signature, confirmationTag) }
    }

    /**
     * RFC 9420 §12.4.2 "Processing a Commit", for a commit already unwrapped
     * from its envelope. Not atomic on its own: every caller wraps it in
     * [atomically].
     */
    private fun applyCommit(
        content: FramedContent,
        wireFormat: WireFormat,
        signature: ByteArray,
        confirmationTag: ByteArray,
    ) {
        require(content.contentType == ContentType.COMMIT) { "Expected a commit, got ${content.contentType}" }
        require(content.groupId.contentEquals(groupId)) { "Commit group ID doesn't match current group" }
        require(content.epoch == epoch) { "Commit epoch ${content.epoch} doesn't match current epoch $epoch" }
        require(confirmationTag.isNotEmpty()) { "Confirmation tag missing on commit" }
        val commit = content.commit()
        val preContextBytes = groupContext.toTlsBytes()
        val retainedForThisEpoch = captureRetainedEpoch()

        // Authenticate the committer (RFC 9420 §6.1). A member signs with its
        // leaf key; an external joiner with the key of the leaf in its path
        // (§12.4.3.2) — it has no other.
        val committer: Int? =
            when (content.sender.senderType) {
                SenderType.MEMBER -> {
                    val index = content.sender.leafIndex
                    require(index in 0 until tree.leafCount) { "Invalid sender leaf index: $index" }
                    val leaf = requireNotNull(tree.getLeaf(index)) { "Sender leaf is blank at index $index" }
                    require(signature.isNotEmpty()) { "FramedContentTBS signature missing on commit from leaf $index" }
                    require(Framing.verify(leaf.signatureKey, wireFormat, content, preContextBytes, signature)) {
                        "Invalid FramedContentTBS signature on commit from leaf $index"
                    }
                    index
                }

                SenderType.NEW_MEMBER_COMMIT -> {
                    require(wireFormat == WireFormat.PUBLIC_MESSAGE) { "An external commit is a PublicMessage" }
                    val path = requireNotNull(commit.updatePath) { "An external commit MUST carry an UpdatePath" }
                    require(Framing.verify(path.leafNode.signatureKey, wireFormat, content, preContextBytes, signature)) {
                        "Invalid FramedContentTBS signature on external commit"
                    }
                    null
                }

                else -> {
                    throw IllegalArgumentException("A ${content.sender.senderType} sender cannot commit")
                }
            }

        // Resolve references against the pending pool BEFORE applying
        // anything, so the policy sees the proposals with their real senders.
        val resolved =
            commit.proposals.map { proposalOrRef ->
                when (proposalOrRef) {
                    is ProposalOrRef.Inline -> {
                        if (committer != null) {
                            PendingProposal(proposalOrRef.proposal, committer)
                        } else {
                            PendingProposal(proposalOrRef.proposal, 0, senderType = SenderType.NEW_MEMBER_COMMIT)
                        }
                    }

                    is ProposalOrRef.Reference -> {
                        require(committer != null) { "An external commit cannot reference proposals (RFC 9420 §12.4.3.2)" }
                        requireNotNull(findPendingProposal(proposalOrRef.proposalRef)) {
                            "Commit references unknown proposal (ref not found in pending proposals)"
                        }
                    }
                }
            }

        // The application's gate on inbound commits, mirroring what commit()
        // enforces locally: authorization has to run on both ends.
        if (committer != null) policy.authorizeCommit(view(), resolved, committer)

        val applied = applyProposalList(resolved, committer)
        val pskSecret = KeySchedule.pskSecret(applied.psks.map { it to requirePsk(it) })
        // The external init secret comes from THIS epoch's external key pair.
        val externalInitSecret = applied.externalInit?.let { deriveExternalInitSecret(it.kemOutput) }

        // A commit that removes us still changed the tree; keep that state so
        // the caller can see we are out, but there is no key schedule we can
        // follow — the path was not encrypted to us.
        if (!isLocalMember()) {
            pendingProposals.clear()
            sentKeys.clear()
            pendingCommit = null
            return
        }

        val updatePath = commit.updatePath
        require(updatePath != null || !applied.pathRequired) { "Commit is missing its required UpdatePath (RFC 9420 §12.4.2)" }

        var commitSecret = ByteArray(MlsCryptoProvider.HASH_OUTPUT_LENGTH)
        if (updatePath != null) {
            val senderLeafIndex: Int
            if (committer == null) {
                // The joiner takes the leftmost blank leaf, or extends the tree.
                senderLeafIndex = (0 until tree.leafCount).firstOrNull { tree.getLeaf(it) == null } ?: tree.leafCount
                GroupValidation.validateLeafNode(updatePath.leafNode, LeafNodeSource.COMMIT, groupId, senderLeafIndex, tree, null, groupContext.extensions, policy, now = null)
                // A resync replaces a member's earlier leaf, and must be the same member.
                applied.resyncedLeaf?.let { old ->
                    require(old.credential == updatePath.leafNode.credential) { "A resync must keep the removed leaf's credential" }
                }
                requireFreshPathKeys(updatePath)
                check(tree.addLeaf(updatePath.leafNode) == senderLeafIndex)
                enforceRequiredAppComponents(requiredAppComponents(), emptySet(), mapOf(senderLeafIndex to null))
            } else {
                senderLeafIndex = committer
                val previous = checkNotNull(tree.getLeaf(committer))
                GroupValidation.validateLeafNode(updatePath.leafNode, LeafNodeSource.COMMIT, groupId, committer, tree, committer, groupContext.extensions, policy, now = null)
                require(!updatePath.leafNode.encryptionKey.contentEquals(previous.encryptionKey)) {
                    "UpdatePath leaf reuses the committer's encryption key"
                }
                requireFreshPathKeys(updatePath)
                tree.setLeaf(committer, updatePath.leafNode)
                // The committer's replacement leaf may not drop a component the group requires.
                enforceRequiredAppComponents(requiredAppComponents(), emptySet(), mapOf(committer to previous))
            }

            val expectedLeafParentHash = TreeKem.mergePathKeys(tree, senderLeafIndex, updatePath.nodes.map { it.encryptionKey })
            require((updatePath.leafNode.parentHash ?: ByteArray(0)).contentEquals(expectedLeafParentHash)) {
                "Parent hash verification failed for UpdatePath"
            }
            prunePathKeys()

            val provisional = groupContext.copy(epoch = epoch + 1, treeHash = tree.treeHash()).toTlsBytes()
            val decrypted =
                TreeKem.decryptPathSecrets(
                    tree = tree,
                    senderLeafIndex = senderLeafIndex,
                    myLeafIndex = myLeafIndex,
                    updatePath = updatePath,
                    excludedLeaves = applied.addedLeaves.map { it.first }.toSet(),
                    groupContext = provisional,
                    privateKeyFor = ::privateKeyFor,
                )
            pathPrivateKeys.putAll(decrypted.nodePrivateKeys)
            commitSecret = decrypted.commitSecret
        }
        prunePathKeys()

        val confirmedTranscriptHash =
            MlsCryptoProvider.hash(interimTranscriptHash + Framing.confirmedTranscriptHashInput(wireFormat, content, signature))

        rememberResumptionPsk()
        groupContext =
            groupContext.copy(
                epoch = epoch + 1,
                treeHash = tree.treeHash(),
                confirmedTranscriptHash = confirmedTranscriptHash,
            )
        epochSecrets = KeySchedule(groupContext.toTlsBytes()).deriveEpochSecrets(commitSecret, externalInitSecret ?: initSecret, pskSecret)
        initSecret = epochSecrets.initSecret

        // The last line of defense: a committer with a valid signing key but a
        // forged tree or key schedule cannot produce this tag.
        val expectedTag = computeConfirmationTag(epochSecrets.confirmationKey, confirmedTranscriptHash)
        require(constantTimeEquals(confirmationTag, expectedTag)) {
            "Confirmation tag verification failed"
        }
        interimTranscriptHash = interimTranscriptHashOf(confirmedTranscriptHash, expectedTag)
        secretTree = SecretTree(epochSecrets.encryptionSecret, tree.leafCount)
        pushRetainedEpoch(retainedForThisEpoch)

        applied.reInit?.let { reInitPending = it }
        pendingProposals.clear()
        pendingUpdateKeys.clear()
        sentKeys.clear()
        pendingCommit = null
    }

    /**
     * RFC 9420 §12.4.2: none of the public keys in an UpdatePath may already
     * appear anywhere in the tree, and they must differ from each other.
     */
    private fun requireFreshPathKeys(updatePath: UpdatePath) {
        val inTree = mutableSetOf<String>()
        for (node in 0 until BinaryTree.nodeCount(maxOf(tree.leafCount, 1))) {
            when (val n = tree.getNode(node)) {
                is TreeNode.Leaf -> inTree.add(Hex.encode(n.leafNode.encryptionKey))
                is TreeNode.Parent -> inTree.add(Hex.encode(n.parentNode.encryptionKey))
                null -> Unit
            }
        }
        val keys = listOf(updatePath.leafNode.encryptionKey) + updatePath.nodes.map { it.encryptionKey }
        val seen = mutableSetOf<String>()
        for (key in keys) {
            val hex = Hex.encode(key)
            require(hex !in inTree) { "UpdatePath reuses a public key already in the tree" }
            require(seen.add(hex)) { "UpdatePath repeats a public key" }
        }
    }

    private fun findPendingProposal(ref: ByteArray): PendingProposal? =
        pendingProposals.find { pending ->
            Framing.proposalRef(pending.authenticatedContentBytes ?: pending.proposal.toTlsBytes()).contentEquals(ref)
        }

    // --- Proposal Reception ---

    /**
     * Authenticate and stage a standalone proposal that arrived as a
     * PublicMessage (RFC 9420 §6.2, §12.1).
     *
     * Accepts proposals from members (membership_tag and signature checked),
     * from the group's `external_senders` and from a new member proposing its
     * own Add. Each is validated as RFC 9420 §12.1 describes and offered to
     * [MlsGroupPolicy.authorizeProposal] before it joins the pending pool.
     */
    fun receivePublicMessageProposal(pubMsg: PublicMessage) {
        require(pubMsg.contentType == ContentType.PROPOSAL) {
            "Expected PublicMessage with content_type == PROPOSAL, got ${pubMsg.contentType}"
        }
        receivePublicProposal(pubMsg)
    }

    private fun receivePublicProposal(pubMsg: PublicMessage): PendingProposal {
        require(pubMsg.epoch == groupContext.epoch) {
            "Proposal epoch ${pubMsg.epoch} doesn't match current epoch ${groupContext.epoch}"
        }
        require(pubMsg.groupId.contentEquals(groupContext.groupId)) {
            "Proposal group_id doesn't match current group"
        }
        val content = pubMsg.framedContent()
        val contextBytes = groupContext.toTlsBytes()
        when (pubMsg.sender.senderType) {
            SenderType.MEMBER -> {
                val senderLeafIndex = pubMsg.sender.leafIndex
                require(senderLeafIndex in 0 until tree.leafCount) { "Sender leaf index $senderLeafIndex out of range" }
                val senderLeaf = requireNotNull(tree.getLeaf(senderLeafIndex)) { "Sender leaf is blank at index $senderLeafIndex" }
                require(Framing.verify(senderLeaf.signatureKey, WireFormat.PUBLIC_MESSAGE, content, contextBytes, pubMsg.signature)) {
                    "Invalid FramedContentTBS signature on PublicMessage proposal from leaf $senderLeafIndex"
                }
                val membershipTag =
                    requireNotNull(pubMsg.membershipTag) {
                        "PublicMessage proposal from leaf $senderLeafIndex is missing membership_tag"
                    }
                require(constantTimeEquals(Framing.membershipTag(epochSecrets.membershipKey, content, contextBytes, pubMsg.signature, null), membershipTag)) {
                    "Invalid membership_tag on PublicMessage proposal from leaf $senderLeafIndex"
                }
            }

            SenderType.EXTERNAL -> {
                val externalSenders = externalSenders()
                val index = pubMsg.sender.leafIndex
                require(index in externalSenders.indices) { "Unknown external sender $index" }
                require(Framing.verify(externalSenders[index].signatureKey, WireFormat.PUBLIC_MESSAGE, content, null, pubMsg.signature)) {
                    "Invalid FramedContentTBS signature on proposal from external sender $index"
                }
            }

            SenderType.NEW_MEMBER_PROPOSAL -> {
                val add = content.proposal() as? Proposal.Add ?: throw IllegalArgumentException("A new_member_proposal sender may only propose its own Add")
                require(Framing.verify(add.keyPackage.leafNode.signatureKey, WireFormat.PUBLIC_MESSAGE, content, null, pubMsg.signature)) {
                    "Invalid FramedContentTBS signature on new member's Add proposal"
                }
            }

            SenderType.NEW_MEMBER_COMMIT -> {
                throw IllegalArgumentException("A new_member_commit sender cannot send a proposal")
            }
        }
        return receiveProposal(content, WireFormat.PUBLIC_MESSAGE, pubMsg.signature)
    }

    /**
     * Validate an authenticated standalone proposal (RFC 9420 §12.1) and add
     * it to the pending pool, keyed for ProposalRef lookup by the exact
     * AuthenticatedContent it arrived in (§5.2).
     */
    private fun receiveProposal(
        content: FramedContent,
        wireFormat: WireFormat,
        signature: ByteArray,
    ): PendingProposal {
        val proposal = content.proposal()
        val sender = content.sender
        when (sender.senderType) {
            SenderType.MEMBER -> {
                require(proposal !is Proposal.ExternalInit) { "ExternalInit is never sent on its own" }
            }

            SenderType.EXTERNAL -> {
                // RFC 9420 §12.1.8: external senders may propose these only.
                require(
                    proposal is Proposal.Add ||
                        proposal is Proposal.Remove ||
                        proposal is Proposal.Psk ||
                        proposal is Proposal.ReInit ||
                        proposal is Proposal.GroupContextExtensions,
                ) { "An external sender cannot propose ${proposal.proposalType}" }
            }

            SenderType.NEW_MEMBER_PROPOSAL -> {
                require(proposal is Proposal.Add) { "A new_member_proposal sender may only propose its own Add" }
            }

            SenderType.NEW_MEMBER_COMMIT -> {
                throw IllegalArgumentException("A new_member_commit sender cannot send a proposal")
            }
        }

        // RFC 9420 §12.1: the proposal on its own must be valid against this epoch.
        when (proposal) {
            is Proposal.Add -> {
                GroupValidation.validateKeyPackage(proposal.keyPackage, groupContext, tree, policy, clock())
            }

            is Proposal.Update -> {
                val previous = checkNotNull(tree.getLeaf(sender.leafIndex))
                GroupValidation.validateLeafNode(proposal.leafNode, LeafNodeSource.UPDATE, groupId, sender.leafIndex, tree, sender.leafIndex, groupContext.extensions, policy, now = null)
                require(!proposal.leafNode.encryptionKey.contentEquals(previous.encryptionKey)) { "Update proposal reuses the leaf's encryption key" }
            }

            is Proposal.Remove -> {
                require(isLiveLeaf(proposal.removedLeafIndex)) { "Cannot remove blank leaf at index ${proposal.removedLeafIndex}" }
            }

            is Proposal.Psk -> {
                require(proposal.psk.pskNonce.size == MlsCryptoProvider.HASH_OUTPUT_LENGTH) { "psk_nonce must be KDF.Nh bytes" }
            }

            is Proposal.ReInit -> {
                require(proposal.version >= groupContext.version) { "ReInit to an older protocol version" }
            }

            else -> {
                Unit
            }
        }

        val authenticatedContent = Framing.authenticatedContent(wireFormat, content, signature)
        val pending =
            PendingProposal(
                proposal = proposal,
                senderLeafIndex = sender.leafIndex,
                authenticatedContentBytes = authenticatedContent,
                senderType = sender.senderType,
            )
        policy.authorizeProposal(view(), pending)

        // The same message delivered twice stages once.
        val ref = Framing.proposalRef(authenticatedContent)
        findPendingProposal(ref)?.let { return it }
        pendingProposals.add(pending)
        return pending
    }

    /** RFC 9420 §12.1.8.1 `external_senders`: who outside the group may send proposals to it. */
    private fun externalSenders(): List<ExternalSender> {
        val ext = groupContext.extensions.find { it.extensionType == EXTERNAL_SENDERS_EXTENSION_TYPE } ?: return emptyList()
        val reader = TlsReader(ext.extensionData)
        return reader.readVectorVarInt { r -> ExternalSender(r.readOpaqueVarInt(), Credential.decodeTls(r)) }.also {
            reader.requireFullyConsumed("external_senders")
        }
    }

    /** One entry of the `external_senders` GroupContext extension. */
    class ExternalSender(
        val signatureKey: ByteArray,
        val credential: Credential,
    )
    // --- Exporter ---

    /**
     * MLS-Exporter function for deriving application-specific keys.
     *
     * Marmot, for instance, derives the outer ChaCha20-Poly1305 key for its
     * GroupEvents with label "marmot" and context "group-event" — see
     * [MlsGroupPolicy.commitExporter], which is how the engine reaches it
     * without naming any one binding.
     */
    fun exporterSecret(
        label: String,
        context: ByteArray,
        length: Int,
    ): ByteArray = KeySchedule.mlsExporter(epochSecrets.exporterSecret, label, context, length)

    // --- External Join Support (RFC 9420 Section 8.3, 12.4.3.2) ---

    /**
     * Get the group's external public key for external commits.
     * Non-members use this to join the group via external commit.
     *
     * external_priv, external_pub = KEM.DeriveKeyPair(external_secret)
     */
    fun externalPub(): ByteArray {
        val kp = Hpke.deriveKeyPair(epochSecrets.externalSecret)
        return kp.publicKey
    }

    /**
     * Get the GroupInfo for publishing (needed by external joiners).
     * Includes the ratchet tree and the `external_pub` extension.
     */
    fun groupInfo(): GroupInfo = signedGroupInfo(includeRatchetTree = true, includeExternalPub = true)

    /**
     * This epoch's GroupInfo as an MLSMessage (wire format `mls_group_info`),
     * the form other implementations publish for external joins.
     *
     * @param includeRatchetTree false when joiners get the tree out of band.
     */
    fun groupInfoMessage(includeRatchetTree: Boolean = true): ByteArray = MlsMessage(wireFormat = WireFormat.GROUP_INFO, payload = signedGroupInfo(includeRatchetTree, includeExternalPub = true).toTlsBytes()).toTlsBytes()

    /**
     * RFC 9420 §12.4.3: GroupInfo signed by us, whose confirmation_tag is the
     * one the commit that created this epoch carried.
     */
    private fun signedGroupInfo(
        includeRatchetTree: Boolean,
        includeExternalPub: Boolean,
    ): GroupInfo {
        val extensions = mutableListOf<Extension>()
        if (includeRatchetTree) extensions.add(Extension(RATCHET_TREE_EXTENSION_TYPE, exportTreeBytesInternal()))
        if (includeExternalPub) extensions.add(Extension(EXTERNAL_PUB_EXTENSION_TYPE, externalPub()))
        val unsigned =
            GroupInfo(
                groupContext = groupContext,
                extensions = extensions,
                confirmationTag = computeConfirmationTag(epochSecrets.confirmationKey, groupContext.confirmedTranscriptHash),
                signer = myLeafIndex,
                signature = ByteArray(0),
            )
        return unsigned.copy(signature = MlsCryptoProvider.signWithLabel(signingPrivateKey, "GroupInfoTBS", unsigned.encodeTbs()))
    }

    private fun exportTreeBytesInternal(): ByteArray {
        val w = TlsWriter()
        tree.encodeTls(w)
        return w.toByteArray()
    }

    /**
     * Derive the external init_secret from an ExternalInit proposal's kem_output.
     * Used by existing members when processing an external commit.
     */
    internal fun deriveExternalInitSecret(kemOutput: ByteArray): ByteArray {
        val externalKp = Hpke.deriveKeyPair(epochSecrets.externalSecret)
        val context = Hpke.setupBaseRExport(kemOutput, externalKp.privateKey, ByteArray(0))
        return context.export(
            "MLS 1.0 external init secret".encodeToByteArray(),
            MlsCryptoProvider.HASH_OUTPUT_LENGTH,
        )
    }

    /**
     * `psk_secret` (RFC 9420 §8.4) for the PreSharedKey proposals in
     * [proposals], resolved from this group's PSKs. Zeros when there are none.
     */
    @InternalMlsApi
    fun computePskSecret(proposals: List<Proposal>): ByteArray = KeySchedule.pskSecret(proposals.filterIsInstance<Proposal.Psk>().map { it.psk to requirePsk(it.psk) })

    /**
     * Verify the membership_tag on a PublicMessage (RFC 9420 Section 6.2).
     * membership_tag = HMAC(membership_key, AuthenticatedContentTBM)
     * where AuthenticatedContentTBM = AuthenticatedContent with the membership_tag zeroed.
     *
     * @param authenticatedContentBytes the TLS-serialized AuthenticatedContent (without tag)
     * @param membershipTag the received membership_tag to verify
     * @return true if the tag is valid
     */
    fun verifyMembershipTag(
        authenticatedContentBytes: ByteArray,
        membershipTag: ByteArray,
    ): Boolean {
        val mac = MacInstance("HmacSHA256", epochSecrets.membershipKey)
        mac.update(authenticatedContentBytes)
        val expectedTag = mac.doFinal()
        return constantTimeEquals(expectedTag, membershipTag)
    }

    /**
     * Resolve a commit's proposals as THIS state sees them, or null when it
     * references a proposal this state does not hold.
     *
     * Convergence needs this without applying anything: a candidate parent is
     * tried by several competing commits, and judging authorization must not
     * advance the state being judged against.
     */
    fun resolveCommitProposals(pubMsg: PublicMessage): List<PendingProposal>? {
        val commit =
            try {
                Commit.decodeTls(TlsReader(pubMsg.content))
            } catch (_: Exception) {
                return null
            }
        val resolved = mutableListOf<PendingProposal>()
        for (proposalOrRef in commit.proposals) {
            when (proposalOrRef) {
                is ProposalOrRef.Inline ->
                    resolved.add(PendingProposal(proposalOrRef.proposal, pubMsg.sender.leafIndex))

                is ProposalOrRef.Reference -> {
                    val match = findPendingProposal(proposalOrRef.proposalRef) ?: return null
                    resolved.add(match)
                }
            }
        }
        return resolved
    }

    /**
     * Whether [pubMsg]'s committer is authorized to make it against THIS state,
     * without applying anything.
     *
     * Runs the same two gates the apply path runs, so an inbound commit and one
     * we authored are held to one rule rather than two that drift. Authorization
     * is parent-relative: this answer is only meaningful once MLS
     * authentication has already established that this state IS the commit's
     * candidate parent.
     */
    fun isCommitAuthorized(pubMsg: PublicMessage): Boolean {
        val proposals = resolveCommitProposals(pubMsg) ?: return false
        return try {
            policy.authorizeCommit(view(), proposals, pubMsg.sender.leafIndex)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Whether every proposal in [pubMsg] is one its own sender may make without
     * admin authority — a self-Update, or SelfRemove of itself.
     *
     * This is the `ordinary` / `privileged` distinction convergence compares on:
     * a commit is `privileged` exactly when its applicable rule REQUIRES an
     * active admin, so one an ordinary member could also have made stays
     * ordinary even when an admin happened to send it.
     */
    fun isSelfOnlyCommit(pubMsg: PublicMessage): Boolean {
        val proposals = resolveCommitProposals(pubMsg) ?: return false
        if (proposals.isEmpty()) return false
        val committer = pubMsg.sender.leafIndex
        val allSelfRemove =
            proposals.all { it.proposal is Proposal.SelfRemove && it.senderLeafIndex == committer }
        if (allSelfRemove) return true
        return proposals.size == 1 &&
            proposals[0].proposal is Proposal.Update &&
            proposals[0].senderLeafIndex == committer
    }

    /**
     * Verify RFC 9420 §6.2 membership_tag on an inbound PublicMessage Commit.
     * The tag binds the whole `(TBS || FramedContentAuthData)` payload to
     * the sender's epoch — if it's missing or wrong, the sender either
     * isn't a member or the message was tampered with. Returns false for
     * either case; callers should reject the commit before advancing state.
     */
    fun verifyPublicMessageCommitMembershipTag(pubMsg: PublicMessage): Boolean {
        val membershipTag = pubMsg.membershipTag ?: return false
        if (membershipTag.isEmpty()) return false
        val confirmationTag = pubMsg.confirmationTag ?: return false
        if (pubMsg.sender.senderType != SenderType.MEMBER) return false
        val expected = Framing.membershipTag(epochSecrets.membershipKey, pubMsg.framedContent(), groupContext.toTlsBytes(), pubMsg.signature, confirmationTag)
        return constantTimeEquals(expected, membershipTag)
    }

    /**
     * RFC 9420 §12.1.7: a commit is invalid if it leaves the group with a
     * `required_capabilities` extension some member does not satisfy.
     *
     * Run AFTER every proposal in the commit has been applied, which is what
     * makes the spec's parenthetical fall out for free: the tree already
     * includes members added in this commit and excludes members removed by
     * it, so iterating the current leaves is exactly the right set.
     *
     * The failure this prevents is a split group. A GroupContextExtensions
     * proposal that raises the bar above what a sitting member advertises is
     * rejected by every peer that checks and accepted by every peer that does
     * not, and the two halves diverge at the next epoch with nothing pointing
     * at the cause.
     */
    private fun enforceRequiredCapabilities() {
        val required = findRequiredCapabilities(groupContext.extensions) ?: return
        for (i in 0 until tree.leafCount) {
            val leaf = tree.getLeaf(i) ?: continue
            requireCapabilitiesMeetRequirements(leaf.capabilities, required, "Member leaf $i")
        }
    }

    /** The component ids the GroupContext's `app_components` entry requires, or empty when it has none. */
    private fun requiredAppComponents(): Set<Int> = ComponentsList.supportedOrRequired(appDataDictionary()).toSet()

    /**
     * draft-ietf-mls-extensions: every member must support the components the
     * GroupContext's `app_components` entry requires, as advertised by the
     * `app_components` entry in its own LeafNode's `app_data_dictionary`.
     *
     * A leaf a commit adds ([addedLeaves]) must advertise all of them, which
     * keeps an Add of an unsupported KeyPackage out. A leaf it replaces
     * ([replacedLeaves], new index to the leaf it had before) may not stop
     * advertising one its previous leaf did, which keeps a downgrading Update or
     * UpdatePath out; a replacement with no previous leaf counts as added. When
     * the commit grows the required set (an activation), every leaf is checked:
     * a component may be required only once all leaves advertise it.
     *
     * A sitting member whose leaf already lacked a required component (a group
     * that predates this check) can still commit with its old advertisement:
     * rejecting that would fork the group, because the committer merges its own
     * commit while every receiver refuses it.
     *
     * Run AFTER every proposal is applied, like [enforceRequiredCapabilities].
     */
    private fun enforceRequiredAppComponents(
        requiredBefore: Set<Int>,
        addedLeaves: Set<Int>,
        replacedLeaves: Map<Int, LeafNode?>,
    ) {
        val required = requiredAppComponents()
        if (required.isEmpty()) return
        if (!requiredBefore.containsAll(required)) {
            for (i in 0 until tree.leafCount) requireAdvertised(i, required)
            return
        }
        for (i in addedLeaves) requireAdvertised(i, required)
        for ((i, previous) in replacedLeaves) {
            if (previous == null) {
                requireAdvertised(i, required)
            } else {
                val previouslyAdvertised = advertisedComponents(previous)
                requireAdvertised(i, required.filterTo(mutableSetOf()) { it in previouslyAdvertised })
            }
        }
    }

    private fun advertisedComponents(leaf: LeafNode): List<Int> = AppDataDictionary.fromExtensions(leaf.extensions)?.let { ComponentsList.supportedOrRequired(it) }.orEmpty()

    private fun requireAdvertised(
        leafIndex: Int,
        components: Set<Int>,
    ) {
        if (components.isEmpty()) return
        val leaf = tree.getLeaf(leafIndex) ?: return
        val supported = advertisedComponents(leaf)
        val missing = components.filterNot { it in supported }
        require(missing.isEmpty()) {
            "Member leaf $leafIndex does not advertise required app components " +
                missing.joinToString { "0x" + it.toString(16).padStart(4, '0') }
        }
    }

    /**
     * Fold every `AppDataUpdate` proposal in a commit into the GroupContext
     * `app_data_dictionary`.
     *
     * Two ordering rules matter, and both change the resulting GroupContext
     * bytes — and therefore the epoch's key schedule — if we get them wrong:
     *
     *  1. These run AFTER the rest of the proposal list, so a
     *     `GroupContextExtensions` proposal in the same commit is already
     *     applied and we update the dictionary it produced.
     *  2. The dictionary extension is added-or-replaced in place and is never
     *     dropped, even when the last component is removed and the dictionary
     *     ends up empty. An absent extension and an empty one are different
     *     GroupContexts.
     *
     * MLS deliberately leaves the meaning of an update payload to the
     * application — openmls hands the proposals back for the app to resolve —
     * because a component's payload can be an arbitrary diff. Every Marmot
     * component document defines its update as a full replacement state, so
     * here resolution is the identity function. A future component that wanted
     * true diff semantics would have to resolve them before this point.
     */
    private fun applyAppDataUpdateProposals(updates: List<Proposal.AppDataUpdate>) {
        if (updates.isEmpty()) return

        var dictionary = AppDataDictionary.fromExtensionsOrEmpty(groupContext.extensions)
        for (update in updates) {
            dictionary =
                when (val operation = update.operation) {
                    is Proposal.AppDataUpdate.Operation.Update ->
                        dictionary.with(update.componentId, operation.data)

                    Proposal.AppDataUpdate.Operation.Remove ->
                        dictionary.without(update.componentId)
                }
        }

        val extension = dictionary.toExtension()
        val existing = groupContext.extensions.indexOfFirst { it.extensionType == AppDataDictionary.EXTENSION_TYPE }
        val newExtensions =
            if (existing >= 0) {
                groupContext.extensions.toMutableList().also { it[existing] = extension }
            } else {
                groupContext.extensions + extension
            }
        groupContext = groupContext.copy(extensions = newExtensions)
    }

    /**
     * Build the Welcome for the members a commit added (RFC 9420 §12.4.3.1).
     *
     * Each joiner's GroupSecrets carries the path secret at the lowest common
     * ancestor of its leaf and ours when the commit had an UpdatePath —
     * without it the joiner holds no key above its own leaf and cannot decrypt
     * the next commit addressed to its (already merged) subtree — and the
     * PreSharedKeyIDs the commit used, so it can derive the same epoch.
     */
    private fun buildWelcome(
        addedMembers: List<Pair<Int, MlsKeyPackage>>,
        generated: TreeKem.GeneratedPath?,
        psks: List<PreSharedKeyId>,
        includeRatchetTree: Boolean,
    ): ByteArray {
        val groupInfo = signedGroupInfo(includeRatchetTree, includeExternalPub = false)
        val (welcomeKey, welcomeNonce) = welcomeKeyNonce(epochSecrets.welcomeSecret)
        val encryptedGroupInfo = MlsCryptoProvider.aeadEncrypt(welcomeKey, welcomeNonce, ByteArray(0), groupInfo.toTlsBytes())

        val secrets =
            addedMembers.map { (leafIndex, kp) ->
                val groupSecrets =
                    GroupSecrets(
                        joinerSecret = epochSecrets.joinerSecret,
                        pathSecret = generated?.pathSecretFor(tree, myLeafIndex, leafIndex),
                        psks = psks,
                    )
                // The HPKE context is the encrypted_group_info (RFC 9420 §12.4.3.1).
                val sealed = MlsCryptoProvider.encryptWithLabel(kp.initKey, "Welcome", encryptedGroupInfo, groupSecrets.toTlsBytes())
                EncryptedGroupSecrets(kp.reference(), sealed)
            }

        return MlsMessage(
            wireFormat = WireFormat.WELCOME,
            payload = Welcome(cipherSuite = groupContext.cipherSuite, secrets = secrets, encryptedGroupInfo = encryptedGroupInfo).toTlsBytes(),
        ).toTlsBytes()
    }

    companion object {
        private const val MAX_SENT_KEYS = 10_000
        private const val MAX_SENT_PROPOSAL_MESSAGES = 256

        // RFC 9420 §13.3 IANA registry: 0x0002 is ratchet_tree.
        // (0x0001 is application_id — using it here makes Welcomes
        // unreadable to OpenMLS/MDK/whitenoise.)
        private const val RATCHET_TREE_EXTENSION_TYPE = 0x0002

        /** How many former epochs' resumption PSKs a group remembers. */
        private const val RESUMPTION_PSK_EPOCHS = 64

        private fun interimTranscriptHashOf(
            confirmedTranscriptHash: ByteArray,
            confirmationTag: ByteArray,
        ): ByteArray {
            val w = TlsWriter()
            w.putBytes(confirmedTranscriptHash)
            w.putOpaqueVarInt(confirmationTag)
            return MlsCryptoProvider.hash(w.toByteArray())
        }

        /** The AEAD key and nonce that seal a Welcome's GroupInfo. */
        private fun welcomeKeyNonce(welcomeSecret: ByteArray): Pair<ByteArray, ByteArray> =
            MlsCryptoProvider.expandWithLabel(welcomeSecret, "key", ByteArray(0), MlsCryptoProvider.AEAD_KEY_LENGTH) to
                MlsCryptoProvider.expandWithLabel(welcomeSecret, "nonce", ByteArray(0), MlsCryptoProvider.AEAD_NONCE_LENGTH)

        /**
         * Compute confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash).
         * Static version usable from companion object factory methods.
         */
        private fun computeConfirmationTag(
            confirmationKey: ByteArray,
            confirmedTranscriptHash: ByteArray,
        ): ByteArray {
            val mac = MacInstance("HmacSHA256", confirmationKey)
            mac.update(confirmedTranscriptHash)
            return mac.doFinal()
        }

        // RFC 9420 §13.3 IANA registry: 0x0003 is required_capabilities.
        // (0x0002 is ratchet_tree — putting it here makes GroupContext
        // unreadable to OpenMLS/MDK, which type-validates extensions by
        // context.)
        const val REQUIRED_CAPABILITIES_EXTENSION_TYPE = 0x0003

        // RFC 9420 §13.3 IANA registry: 0x0004 is external_pub.
        // (0x0003 is required_capabilities — using it here makes
        // external-join GroupInfos unreadable to OpenMLS/MDK.)
        private const val EXTERNAL_PUB_EXTENSION_TYPE = 0x0004

        // 0x0005, not 0x0004: the two sat on the same value here, which made
        // the pair indistinguishable anywhere they were compared as a set.
        private const val EXTERNAL_SENDERS_EXTENSION_TYPE = 0x0005

        private const val APPLICATION_ID_EXTENSION_TYPE = 0x0001

        /**
         * The extension types RFC 9420 §7.2 calls "default".
         *
         * A capabilities field MUST NOT list them, so they can never satisfy
         * the §13.4 all-members-support rule and have to be exempt from it
         * instead. This is the whole exemption: a type being one the code
         * happens to recognise is not a reason to skip the check, and a
         * binding's own extension types come from [MlsGroupPolicy.knownExtensionTypes].
         */
        private val DEFAULT_EXTENSION_TYPES =
            setOf(
                APPLICATION_ID_EXTENSION_TYPE,
                RATCHET_TREE_EXTENSION_TYPE,
                REQUIRED_CAPABILITIES_EXTENSION_TYPE,
                EXTERNAL_PUB_EXTENSION_TYPE,
                EXTERNAL_SENDERS_EXTENSION_TYPE,
            )

        /** MLS self_remove proposal type (MIP-00 / MIP-03). */
        const val SELF_REMOVE_PROPOSAL_TYPE = 0x000A

        /** MLS extensions draft `app_data_update` proposal type. */
        const val APP_DATA_UPDATE_PROPOSAL_TYPE = 0x0008

        /**
         * How many former epochs [decryptFormerEpoch] can still read. Each one
         * keeps that epoch's decryption secrets, so this is a forward-secrecy
         * trade (RFC 9420 §15.2); 4 matches ts-mls's `retainKeysForEpochs`.
         */
        const val RETAIN_EPOCHS = 4

        /** How far back a fresh KeyPackage LeafNode's `not_before` is set. */
        private const val LIFETIME_SKEW_SECONDS = 3_600L

        /**
         * 84 days. The spec's ceiling is 84 days plus one hour of skew, so this
         * leaves the whole skew allowance as headroom rather than sitting
         * exactly on the limit.
         */
        private const val LIFETIME_SPAN_SECONDS = 84L * 24 * 60 * 60

        /**
         * Parsed view of the RFC 9420 §7.2 `required_capabilities` extension.
         *
         * The on-wire struct is three `uint16<V>` vectors —
         * `extensions / proposals / credentials` — that name the types every
         * member of the group MUST advertise in their leaf [Capabilities].
         */
        @InternalMlsApi
        data class RequiredCapabilities(
            val extensions: List<Int>,
            val proposals: List<Int>,
            val credentials: List<Int>,
        )

        /**
         * Decode the `required_capabilities` extension from the GroupContext
         * extension list, or `null` if the group hasn't installed one (some
         * peers may omit it; treat missing as "no restriction").
         */
        @InternalMlsApi
        fun findRequiredCapabilities(extensions: List<Extension>): RequiredCapabilities? {
            val ext = extensions.find { it.extensionType == REQUIRED_CAPABILITIES_EXTENSION_TYPE } ?: return null
            val r = TlsReader(ext.extensionData)

            fun readUint16List(data: ByteArray): List<Int> {
                val rr = TlsReader(data)
                val list = mutableListOf<Int>()
                while (rr.hasRemaining) list.add(rr.readUint16())
                return list
            }
            val exts = readUint16List(r.readOpaqueVarInt())
            val props = readUint16List(r.readOpaqueVarInt())
            val creds = readUint16List(r.readOpaqueVarInt())
            return RequiredCapabilities(exts, props, creds)
        }

        /**
         * RFC 9420 §7.2 + §12.4.2: every member's leaf [Capabilities] MUST
         * advertise every type listed in the group's `required_capabilities`
         * extension. Adding a member whose KeyPackage doesn't meet the
         * requirement leaves the group in a non-conformant state where
         * peers that DO enforce the requirement will reject any commit that
         * touches that leaf.
         *
         * Throws [IllegalStateException] with a precise diff so debugging
         * an interop break against another implementation is one log line.
         */
        @InternalMlsApi
        fun requireCapabilitiesMeetRequirements(
            caps: Capabilities,
            req: RequiredCapabilities,
            who: String,
        ) {
            val missingExts = req.extensions.filter { it !in caps.extensions }
            val missingProps = req.proposals.filter { it !in caps.proposals }
            val missingCreds = req.credentials.filter { it !in caps.credentials }
            if (missingExts.isNotEmpty() || missingProps.isNotEmpty() || missingCreds.isNotEmpty()) {
                throw IllegalStateException(
                    "$who capabilities don't meet required_capabilities: " +
                        "missing extensions=$missingExts proposals=$missingProps credentials=$missingCreds",
                )
            }
        }

        /** RFC 9420 §7.9.2 ParentHashInput TLS encoding. */
        internal fun encodeParentHashInput(
            encryptionKey: ByteArray,
            parentHash: ByteArray,
            originalSiblingTreeHash: ByteArray,
        ): ByteArray = TreeKem.encodeParentHashInput(encryptionKey, parentHash, originalSiblingTreeHash)

        /**
         * RFC 9420 §7.9.2 "Verifying Parent Hashes", over the STATIC tree a
         * joiner reconstructs from a Welcome's GroupInfo.
         *
         * Without it a malicious or misconfigured GroupInfo signer could ship
         * a tree whose stored parent_hash values do not match its shape; peers
         * that DO validate would reject every commit produced from it, and the
         * joiner would not notice until an epoch silently rolled back.
         * Returns `null` on success, or a human-readable failure reason.
         *
         * The rule is per PARENT node, not per leaf: for each non-blank parent
         * P, EXACTLY ONE of its two subtrees must contain a node whose
         * `parent_hash` equals `ParentHash(P, other_subtree)`. That node is the
         * child the committer descended through when it set P; the other
         * subtree supplies the sibling hash.
         *
         * We used to re-derive every COMMIT-source leaf's `parent_hash`
         * top-down from the CURRENT tree and demand a match. That is a much
         * stronger claim than the RFC makes, and a false one: a later commit
         * refreshes ancestors and a later Add changes the tree's shape, so a
         * leaf set two epochs ago legitimately no longer re-derives. It
         * rejected every tree where the inviter was not the last committer —
         * in practice, every group invitation sent by anyone but the creator.
         *
         * Both sibling hashes and both resolutions exclude P's
         * `unmerged_leaves`: those are precisely the leaves added after P was
         * populated, so removing them reconstructs the tree as P's author saw
         * it.
         */
        @InternalMlsApi
        fun verifyTreeParentHashesForJoin(tree: RatchetTree): String? {
            if (tree.leafCount == 0) return null
            for (parentIdx in tree.parentNodeIndices()) {
                val key = tree.parentEncryptionKeyOf(parentIdx) ?: continue
                val storedParentHash = tree.parentHashOf(parentIdx) ?: ByteArray(0)
                val excluded = tree.unmergedLeavesOf(parentIdx)
                val leftIdx = BinaryTree.left(parentIdx)
                val rightIdx = BinaryTree.right(parentIdx)

                fun hashWithSibling(siblingIdx: Int) =
                    MlsCryptoProvider.hash(
                        encodeParentHashInput(
                            encryptionKey = key,
                            parentHash = storedParentHash,
                            originalSiblingTreeHash = tree.originalTreeHash(siblingIdx, excluded),
                        ),
                    )

                val expectedInLeft = hashWithSibling(rightIdx)
                val expectedInRight = hashWithSibling(leftIdx)

                val foundLeft =
                    tree.resolutionExcluding(leftIdx, excluded).any {
                        tree.parentHashOf(it)?.contentEquals(expectedInLeft) == true
                    }
                val foundRight =
                    tree.resolutionExcluding(rightIdx, excluded).any {
                        tree.parentHashOf(it)?.contentEquals(expectedInRight) == true
                    }

                if (foundLeft == foundRight) {
                    return "parent node $parentIdx is not parent-hash valid " +
                        "(matched left=$foundLeft right=$foundRight)"
                }
            }
            return null
        }

        /**
         * Create a new MLS group with a single member (the creator).
         */
        fun create(
            identity: ByteArray,
            signingKey: ByteArray? = null,
            initialExtensions: List<Extension> = emptyList(),
            /**
             * LeafNode extensions for the creator's own leaf. A current-profile
             * group MUST put its `app_data_dictionary` here, carrying the
             * account identity proof — the proof is leaf-only and can never be
             * added later by a proposal.
             */
            leafExtensions: List<Extension> = emptyList(),
            /**
             * The application's rules for this group. Also supplies the
             * defaults below, so one argument selects a whole profile.
             */
            policy: MlsGroupPolicy = MlsGroupPolicy.Permissive,
            capabilities: Capabilities = policy.defaultLeafCapabilities,
            /**
             * The `required_capabilities` extension for epoch 0. Null means
             * the group carries none, which is the RFC 9420 default; a Marmot
             * current-profile group passes
             * `MarmotCapabilities.currentProfileRequired` (in Quartz).
             */
            requiredCapabilities: Extension? = policy.defaultRequiredCapabilities,
            /**
             * The RFC 9420 `group_id` for the new group. Null generates a
             * random 32-byte one, which is the right default: §8.1 only
             * requires it to be unique, and a random id tells a receiver
             * nothing.
             *
             * A binding may need to choose it. cordn's reference client sets
             * `group_id = utf8(gid)` so that a joiner can recover the delivery
             * id from a Welcome, which otherwise carries no way to learn it —
             * see `CordnGroupManager`. Anything a binding puts here is visible
             * to whoever handles the ciphertext, so it must carry nothing the
             * group would not publish.
             */
            groupId: ByteArray? = null,
        ): MlsGroup {
            val sigKp =
                signingKey?.let { key ->
                    val pub = Ed25519.publicFromPrivate(key)
                    Ed25519KeyPair(key, pub)
                } ?: Ed25519.generateKeyPair()

            val encKp = X25519.generateKeyPair()
            val newGroupId = groupId ?: MlsCryptoProvider.randomBytes(32)

            val leafNode =
                buildLeafNode(
                    encryptionKey = encKp.publicKey,
                    signatureKey = sigKp.publicKey,
                    identity = identity,
                    source = LeafNodeSource.KEY_PACKAGE,
                    signingKey = sigKp.privateKey,
                    capabilities = capabilities,
                    leafExtensions = leafExtensions,
                )

            val tree = RatchetTree(1)
            tree.setLeaf(0, leafNode)

            val treeHash = tree.treeHash()
            // Start with required_capabilities, when the profile has any, plus
            // whatever the caller wants baked into epoch 0 — typically the
            // binding's own group-metadata extension, so a later joiner can read
            // it without first decrypting a pre-membership bootstrap commit.
            val baseExtensions = listOfNotNull(requiredCapabilities)
            val groupContext =
                GroupContext(
                    groupId = newGroupId,
                    epoch = 0,
                    treeHash = treeHash,
                    confirmedTranscriptHash = ByteArray(0),
                    extensions = baseExtensions + initialExtensions,
                )

            // Initial key schedule with zero secrets
            val initSecret = ByteArray(MlsCryptoProvider.HASH_OUTPUT_LENGTH)
            val commitSecret = ByteArray(MlsCryptoProvider.HASH_OUTPUT_LENGTH)

            val keySchedule = KeySchedule(groupContext.toTlsBytes())
            val epochSecrets = keySchedule.deriveEpochSecrets(commitSecret, initSecret)

            val secretTree = SecretTree(epochSecrets.encryptionSecret, 1)

            return MlsGroup(
                groupContext = groupContext,
                tree = tree,
                myLeafIndex = 0,
                epochSecrets = epochSecrets,
                secretTree = secretTree,
                initSecret = epochSecrets.initSecret,
                signingPrivateKey = sigKp.privateKey,
                encryptionPrivateKey = encKp.privateKey,
                interimTranscriptHash = ByteArray(0),
                policy = policy,
            )
        }

        /**
         * Join a group by processing a Welcome message (RFC 9420 §12.4.3.1).
         *
         * @param welcomeBytes the MLSMessage-wrapped Welcome
         * @param bundle the KeyPackageBundle that was used to create the invitation
         * @param ratchetTree the group's ratchet tree (`optional<Node> ratchet_tree<V>`),
         *   for a Welcome whose GroupInfo does not carry the `ratchet_tree`
         *   extension because the application delivers the tree out of band
         * @param psks resolves each PreSharedKeyID the Welcome names to its
         *   secret: external PSKs the application provisioned, or the resumption
         *   PSK of a predecessor group (ReInit, branch)
         */
        fun processWelcome(
            welcomeBytes: ByteArray,
            bundle: KeyPackageBundle,
            policy: MlsGroupPolicy = MlsGroupPolicy.Permissive,
            ratchetTree: ByteArray? = null,
            psks: (PreSharedKeyId) -> ByteArray? = { null },
        ): MlsGroup {
            val mlsMsg = MlsMessage.decodeTls(TlsReader(welcomeBytes))
            require(mlsMsg.wireFormat == WireFormat.WELCOME) { "Expected Welcome message" }
            val welcomeReader = TlsReader(mlsMsg.payload)
            val welcome = Welcome.decodeTls(welcomeReader)
            welcomeReader.requireFullyConsumed("Welcome")

            require(welcome.cipherSuite == bundle.keyPackage.cipherSuite) {
                "Welcome ciphersuite ${welcome.cipherSuite} doesn't match KeyPackage ciphersuite ${bundle.keyPackage.cipherSuite}"
            }

            val myRef = bundle.keyPackage.reference()
            val mySecrets =
                welcome.secrets.find { it.newMember.contentEquals(myRef) }
                    ?: throw IllegalArgumentException("Welcome does not contain secrets for our KeyPackage")

            // The HPKE context is the encrypted_group_info field of the Welcome.
            val gsBytes =
                MlsCryptoProvider.decryptWithLabel(
                    bundle.initPrivateKey,
                    "Welcome",
                    welcome.encryptedGroupInfo,
                    mySecrets.encryptedGroupSecrets.kemOutput,
                    mySecrets.encryptedGroupSecrets.ciphertext,
                )
            val gsReader = TlsReader(gsBytes)
            val groupSecrets = GroupSecrets.decodeTls(gsReader)
            gsReader.requireFullyConsumed("GroupSecrets")

            // RFC 9420 §8.4: the PSKs the commit folded in, in the same order.
            val pskSecret =
                KeySchedule.pskSecret(
                    groupSecrets.psks.map { id ->
                        id to (psks(id) ?: throw IllegalStateException("PSK not available: ${id.identityKey()}"))
                    },
                )
            val memberSecret = MlsCryptoProvider.hkdfExtract(groupSecrets.joinerSecret, pskSecret)
            val (welcomeKey, welcomeNonce) = welcomeKeyNonce(MlsCryptoProvider.deriveSecret(memberSecret, "welcome"))
            val groupInfoBytes = MlsCryptoProvider.aeadDecrypt(welcomeKey, welcomeNonce, ByteArray(0), welcome.encryptedGroupInfo)
            val giReader = TlsReader(groupInfoBytes)
            val groupInfo = GroupInfo.decodeTls(giReader)
            giReader.requireFullyConsumed("GroupInfo")
            val groupContext = groupInfo.groupContext

            require(groupContext.version == bundle.keyPackage.version && groupContext.cipherSuite == bundle.keyPackage.cipherSuite) {
                "The group's version or ciphersuite doesn't match our KeyPackage"
            }

            val tree = treeFrom(groupInfo, ratchetTree)

            val signerLeaf =
                requireNotNull(tree.getLeaf(groupInfo.signer)) {
                    "Signer leaf is null at index ${groupInfo.signer} — cannot verify GroupInfo signature"
                }
            require(groupInfo.verifySignature(signerLeaf.signatureKey)) { "Invalid GroupInfo signature" }

            // RFC 9420 §12.4.3.1: the tree must hash to the signed tree_hash,
            // be parent-hash valid, and hold only valid leaves and parents.
            GroupValidation.validateTree(tree, groupContext, policy)

            // Our leaf is the one identical to our KeyPackage's.
            val myLeafIndex = (0 until tree.leafCount).firstOrNull { tree.getLeaf(it) == bundle.keyPackage.leafNode }
            requireNotNull(myLeafIndex) { "Joiner's signature key not found in ratchet tree" }

            // A component may impose per-member requirements MLS cannot carry.
            policy.validateJoin(
                GroupView(
                    extensions = groupContext.extensions,
                    leafCount = tree.leafCount,
                    myLeafIndex = myLeafIndex,
                    identityAt = { leaf -> (tree.getLeaf(leaf)?.credential as? Credential.Basic)?.identity?.let { Hex.encode(it) } },
                    capabilitiesAt = { tree.getLeaf(it)?.capabilities },
                ),
            )

            // RFC 9420 §12.4.3.1: a group a resumption PSK of usage reinit or
            // branch starts must be at epoch 1.
            if (groupSecrets.psks.any { it is PreSharedKeyId.Resumption && it.usage != PreSharedKeyId.USAGE_APPLICATION }) {
                require(groupContext.epoch == 1L) { "A ReInit/branch Welcome must start the group at epoch 1" }
            }

            val epochSecrets = KeySchedule(groupContext.toTlsBytes()).fromJoinerSecret(groupSecrets.joinerSecret, pskSecret)

            // The confirmation tag binds the epoch secrets we derived to the
            // signed transcript.
            val confirmationTag = computeConfirmationTag(epochSecrets.confirmationKey, groupContext.confirmedTranscriptHash)
            require(constantTimeEquals(groupInfo.confirmationTag, confirmationTag)) {
                "GroupInfo confirmation_tag does not match joiner-derived confirmation_key"
            }

            val joined =
                MlsGroup(
                    groupContext = groupContext,
                    tree = tree,
                    myLeafIndex = myLeafIndex,
                    epochSecrets = epochSecrets,
                    secretTree = SecretTree(epochSecrets.encryptionSecret, tree.leafCount),
                    initSecret = epochSecrets.initSecret,
                    signingPrivateKey = bundle.signaturePrivateKey,
                    encryptionPrivateKey = bundle.encryptionPrivateKey,
                    interimTranscriptHash = interimTranscriptHashOf(groupContext.confirmedTranscriptHash, confirmationTag),
                    policy = policy,
                )
            // When the commit that added us carried an UpdatePath, its path
            // secret at our common ancestor with the committer gives us the
            // private keys above that ancestor — our subtree is already merged,
            // so the next commit addresses us there.
            groupSecrets.pathSecret?.let { pathSecret ->
                joined.pathPrivateKeys.putAll(TreeKem.keysFromWelcomePathSecret(tree, groupInfo.signer, myLeafIndex, pathSecret))
            }
            return joined
        }

        /** The ratchet tree from a GroupInfo's `ratchet_tree` extension, or the one delivered out of band. */
        private fun treeFrom(
            groupInfo: GroupInfo,
            ratchetTree: ByteArray?,
        ): RatchetTree {
            val bytes =
                groupInfo.extensions.find { it.extensionType == RATCHET_TREE_EXTENSION_TYPE }?.extensionData
                    ?: ratchetTree
                    ?: throw IllegalArgumentException("GroupInfo has no ratchet_tree extension and no tree was supplied")
            val reader = TlsReader(bytes)
            return RatchetTree.decodeTls(reader).also { reader.requireFullyConsumed("ratchet_tree") }
        }

        /** A GroupInfo given bare or wrapped in an MLSMessage (`mls_group_info`). */
        private fun decodeGroupInfo(bytes: ByteArray): GroupInfo {
            val probe = TlsReader(bytes)
            // GroupInfo opens with GroupContext.version and cipher_suite; an
            // MLSMessage with version and wire_format 4. We implement suite 1 only.
            val payload =
                if (bytes.size >= 4 && probe.readUint16() == MlsMessage.MLS_VERSION_10 && probe.readUint16() == WireFormat.GROUP_INFO.value) {
                    MlsMessage.decodeTls(TlsReader(bytes)).payload
                } else {
                    bytes
                }
            val reader = TlsReader(payload)
            return GroupInfo.decodeTls(reader).also { reader.requireFullyConsumed("GroupInfo") }
        }

        /**
         * Join a group via external commit (RFC 9420 §12.4.3.2).
         *
         * The joiner obtains the GroupInfo (with external_pub), creates an
         * ExternalInit proposal with HPKE encapsulation, and produces a signed
         * Commit — sender `new_member_commit` — that existing members process
         * to add the joiner.
         *
         * @param groupInfoBytes the GroupInfo, bare or as an MLSMessage
         * @param identity the joiner's BasicCredential identity
         * @param signingKey optional Ed25519 signing key (generated if null)
         * @param capabilities the joiner leaf's capabilities. A current-profile
         *   join MUST pass [currentProfileLeafCapabilities]; the default only
         *   satisfies a legacy group's `required_capabilities`.
         * @param leafExtensions the joiner leaf's extensions. A current-profile
         *   join MUST pass the `app_data_dictionary` carrying its account
         *   identity proof — leaf extensions cannot be added after the fact.
         * @param ratchetTree the tree, when the GroupInfo does not carry it
         * @param resyncLeafIndex our own earlier leaf to replace (a "resync"
         *   commit); its credential must equal the new one
         * @param psks external or resumption PSKs to fold into the new epoch
         * @param authenticatedData the commit's `authenticated_data`
         * @return the new MlsGroup along with the raw inner commit bytes and a
         *   wire-ready PublicMessage envelope. Existing group members consume
         *   the framed bytes via [MlsGroup.processFramedCommit].
         */
        fun externalJoin(
            groupInfoBytes: ByteArray,
            identity: ByteArray,
            signingKey: ByteArray? = null,
            policy: MlsGroupPolicy = MlsGroupPolicy.Permissive,
            capabilities: Capabilities = policy.defaultLeafCapabilities,
            leafExtensions: List<Extension> = emptyList(),
            ratchetTree: ByteArray? = null,
            resyncLeafIndex: Int? = null,
            psks: List<Pair<PreSharedKeyId, ByteArray>> = emptyList(),
            authenticatedData: ByteArray = ByteArray(0),
        ): ExternalJoinResult {
            val groupInfo = decodeGroupInfo(groupInfoBytes)
            val groupContext = groupInfo.groupContext
            require(groupContext.version == GroupValidation.MLS_VERSION && groupContext.cipherSuite == GroupValidation.CIPHER_SUITE) {
                "Unsupported group version ${groupContext.version} / ciphersuite ${groupContext.cipherSuite}"
            }
            val tree = treeFrom(groupInfo, ratchetTree)

            val signerLeaf =
                requireNotNull(tree.getLeaf(groupInfo.signer)) {
                    "Signer leaf is null at index ${groupInfo.signer} — cannot verify GroupInfo signature"
                }
            require(groupInfo.verifySignature(signerLeaf.signatureKey)) { "Invalid GroupInfo signature in externalJoin" }
            GroupValidation.validateTree(tree, groupContext, policy)

            val externalPub =
                groupInfo.extensions.find { it.extensionType == EXTERNAL_PUB_EXTENSION_TYPE }?.extensionData
                    ?: throw IllegalArgumentException("GroupInfo missing external_pub extension")

            val sigKp =
                signingKey?.let { key -> Ed25519KeyPair(key, Ed25519.publicFromPrivate(key)) } ?: Ed25519.generateKeyPair()

            // RFC 9420 §8.3: the joiner's init_secret comes from an HPKE export
            // to the group's external public key.
            val (kemOutput, exportContext) = Hpke.setupBaseSExport(externalPub, ByteArray(0))
            val externalInitSecret = exportContext.export("MLS 1.0 external init secret".encodeToByteArray(), MlsCryptoProvider.HASH_OUTPUT_LENGTH)

            // The joiner runs the same proposal pipeline as every member, on a
            // group object that holds only what the GroupInfo says — so the
            // rules it applies are the ones the members will apply.
            val unusedSecrets = KeySchedule(groupContext.toTlsBytes()).fromJoinerSecret(ByteArray(MlsCryptoProvider.HASH_OUTPUT_LENGTH))
            val joiner =
                MlsGroup(
                    groupContext = groupContext,
                    tree = tree,
                    myLeafIndex = -1,
                    epochSecrets = unusedSecrets,
                    secretTree = SecretTree(ByteArray(0), tree.leafCount),
                    initSecret = externalInitSecret,
                    signingPrivateKey = sigKp.privateKey,
                    encryptionPrivateKey = ByteArray(0),
                    // RFC 9420 §8.2: interim_transcript_hash_[0] is the empty string;
                    // every later epoch's follows from the GroupInfo's transcript and tag.
                    interimTranscriptHash =
                        if (groupContext.epoch == 0L) ByteArray(0) else interimTranscriptHashOf(groupContext.confirmedTranscriptHash, groupInfo.confirmationTag),
                    policy = policy,
                )
            for ((id, value) in psks) joiner.pskStore[id.identityKey()] = value
            val commitBytes =
                joiner.buildExternalCommit(
                    kemOutput = kemOutput,
                    signingKeyPair = sigKp,
                    credential = Credential.Basic(identity),
                    capabilities = capabilities,
                    leafExtensions = leafExtensions,
                    resyncLeafIndex = resyncLeafIndex,
                    psks = psks.map { it.first },
                    authenticatedData = authenticatedData,
                )
            return ExternalJoinResult(group = joiner, commitBytes = commitBytes.first, framedCommitBytes = commitBytes.second)
        }

        /**
         * Restore a group from a previously saved [MlsGroupState].
         *
         * The SecretTree is reconstructed from the stored encryption_secret,
         * then seeded with the persisted per-sender ratchet positions
         * ([MlsGroupState.senderRatchetStates]). Seeding is what keeps the
         * local member's generation counter monotonic across a restart — a
         * fresh SecretTree would restart every sender at generation 0, so our
         * next send would reuse generation 0's AEAD key+nonce within the same
         * epoch and be rejected by strict receivers (openmls / MDK /
         * Whitenoise) that forbid generation reuse.
         *
         * Receive-only ratchets that weren't persisted (STATE_VERSION 1 blobs,
         * or senders we never decrypted) simply re-derive from generation 0 on
         * first use — safe, because those messages were already processed.
         */
        fun restore(
            state: MlsGroupState,
            policy: MlsGroupPolicy = MlsGroupPolicy.Permissive,
        ): MlsGroup {
            val tree = RatchetTree.decodeTls(TlsReader(state.treeBytes))
            val secretTree = SecretTree(state.encryptionSecret, tree.leafCount)
            secretTree.importSenderStates(state.senderRatchetStates)
            secretTree.importSkippedSecrets(state.skippedApplicationSecrets, state.skippedHandshakeSecrets)
            if (state.nodeSecrets.isNotEmpty()) secretTree.importNodeSecrets(state.nodeSecrets)

            return MlsGroup(
                groupContext = state.groupContext,
                tree = tree,
                myLeafIndex = state.myLeafIndex,
                epochSecrets = state.epochSecrets,
                secretTree = secretTree,
                initSecret = state.initSecret,
                signingPrivateKey = state.signingPrivateKey,
                encryptionPrivateKey = state.encryptionPrivateKey,
                interimTranscriptHash = state.interimTranscriptHash,
                pathPrivateKeys = state.pathPrivateKeys.toMutableMap(),
                pendingProposals = state.pendingProposals.toMutableList(),
                retainedEpochs = ArrayDeque(state.retainedEpochs),
                policy = policy,
                resumptionPsks = state.resumptionPsks.toMutableMap(),
                pendingUpdateKeys = state.pendingUpdateKeys.associateByTo(mutableMapOf()) { Hex.encode(it.encryptionKey) },
            ).also { it.reInitPending = state.reInitPending }
        }

        /**
         * Build a LeafNode with signature.
         */
        private fun buildLeafNode(
            encryptionKey: ByteArray,
            signatureKey: ByteArray,
            identity: ByteArray,
            source: LeafNodeSource,
            signingKey: ByteArray,
            groupId: ByteArray? = null,
            leafIndex: Int? = null,
            parentHash: ByteArray? = null,
            capabilities: Capabilities,
            leafExtensions: List<Extension> = emptyList(),
            lifetime: Lifetime? = null,
            /** The leaf's credential; a BasicCredential of [identity] when null. */
            credential: Credential? = null,
        ): LeafNode {
            val unsigned =
                LeafNode(
                    encryptionKey = encryptionKey,
                    signatureKey = signatureKey,
                    credential = credential ?: Credential.Basic(identity),
                    // Advertise the profile's required capabilities so we can be
                    // added to compliant groups that mark them as required.
                    capabilities = capabilities,
                    leafNodeSource = source,
                    lifetime =
                        if (source == LeafNodeSource.KEY_PACKAGE && lifetime != null) {
                            lifetime
                        } else if (source == LeafNodeSource.KEY_PACKAGE) {
                            // A real, bounded window. `Lifetime(0, Long.MAX_VALUE)`
                            // used to go here, which any receiver enforcing
                            // `foundation/key-packages.md` rejects outright: the
                            // extension must be current AND span at most
                            // 7,261,200s (84 days + an hour of clock skew).
                            // The one-hour backdate gives a peer with a slow
                            // clock a window in which the package is already
                            // valid.
                            val notBefore = TimeUtils.now() - LIFETIME_SKEW_SECONDS
                            Lifetime(notBefore, notBefore + LIFETIME_SPAN_SECONDS)
                        } else {
                            null
                        },
                    parentHash = parentHash,
                    extensions = leafExtensions,
                    signature = ByteArray(0), // Placeholder
                )

            val tbs = unsigned.encodeTbs(groupId, leafIndex)
            val signature = MlsCryptoProvider.signWithLabel(signingKey, "LeafNodeTBS", tbs)

            return unsigned.copy(signature = signature)
        }
    }

    /**
     * The external joiner's half of [externalJoin]: on a group object holding
     * only the GroupInfo's state, apply the external commit's proposals, take
     * the leftmost free leaf, build and encrypt the UpdatePath, sign the commit
     * as `new_member_commit`, and move into the new epoch exactly as the
     * members will.
     *
     * @return the Commit bytes and the framed PublicMessage.
     */
    private fun buildExternalCommit(
        kemOutput: ByteArray,
        signingKeyPair: Ed25519KeyPair,
        credential: Credential,
        capabilities: Capabilities,
        leafExtensions: List<Extension>,
        resyncLeafIndex: Int?,
        psks: List<PreSharedKeyId>,
        authenticatedData: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val preContext = groupContext
        val preContextBytes = preContext.toTlsBytes()

        val inline = mutableListOf<Proposal>(Proposal.ExternalInit(kemOutput))
        resyncLeafIndex?.let { inline.add(Proposal.Remove(it)) }
        psks.forEach { inline.add(Proposal.Psk(it)) }
        val proposals = inline.map { PendingProposal(it, 0, senderType = SenderType.NEW_MEMBER_COMMIT) }

        val applied = applyProposalList(proposals, committer = null)
        val pskSecret = KeySchedule.pskSecret(applied.psks.map { it to requirePsk(it) })

        val encKp = X25519.generateKeyPair()
        val leafIndex = (0 until tree.leafCount).firstOrNull { tree.getLeaf(it) == null } ?: tree.leafCount
        val placeholder =
            buildLeafNode(
                encryptionKey = encKp.publicKey,
                signatureKey = signingKeyPair.publicKey,
                identity = ByteArray(0),
                credential = credential,
                source = LeafNodeSource.COMMIT,
                signingKey = signingKeyPair.privateKey,
                groupId = groupId,
                leafIndex = leafIndex,
                capabilities = capabilities,
                leafExtensions = leafExtensions,
            )
        check(tree.addLeaf(placeholder) == leafIndex)
        myLeafIndex = leafIndex

        val generated = TreeKem.generate(tree, leafIndex)
        val leafParentHash = TreeKem.mergePathKeys(tree, leafIndex, generated.nodeKeys.map { it.second })
        val leaf =
            buildLeafNode(
                encryptionKey = encKp.publicKey,
                signatureKey = signingKeyPair.publicKey,
                identity = ByteArray(0),
                credential = credential,
                source = LeafNodeSource.COMMIT,
                signingKey = signingKeyPair.privateKey,
                groupId = groupId,
                leafIndex = leafIndex,
                parentHash = leafParentHash,
                capabilities = capabilities,
                leafExtensions = leafExtensions,
            )
        tree.setLeaf(leafIndex, leaf)
        GroupValidation.validateLeafNode(leaf, LeafNodeSource.COMMIT, groupId, leafIndex, tree, leafIndex, groupContext.extensions, policy, now = null)
        applied.resyncedLeaf?.let { old -> require(old.credential == credential) { "A resync must keep the removed leaf's credential" } }
        enforceRequiredAppComponents(requiredAppComponents(), emptySet(), mapOf(leafIndex to null))
        encryptionPrivateKey = encKp.privateKey
        pathPrivateKeys.putAll(generated.privateKeysByNode())

        val provisional = groupContext.copy(epoch = preContext.epoch + 1, treeHash = tree.treeHash()).toTlsBytes()
        val nodes = TreeKem.encryptPathSecrets(tree, leafIndex, generated, emptySet(), provisional)
        val commitBytes = Commit(inline.map { ProposalOrRef.Inline(it) }, UpdatePath(leaf, nodes)).toTlsBytes()

        // RFC 9420 §12.4.3.2: signed by the new member, sender new_member_commit,
        // over the GroupContext of the epoch it joins from.
        val content =
            FramedContent(
                groupId = preContext.groupId,
                epoch = preContext.epoch,
                sender = Sender(SenderType.NEW_MEMBER_COMMIT),
                authenticatedData = authenticatedData,
                contentType = ContentType.COMMIT,
                body = commitBytes,
            )
        val signature = Framing.sign(signingKeyPair.privateKey, WireFormat.PUBLIC_MESSAGE, content, preContextBytes)
        val confirmedTranscriptHash =
            MlsCryptoProvider.hash(interimTranscriptHash + Framing.confirmedTranscriptHashInput(WireFormat.PUBLIC_MESSAGE, content, signature))

        groupContext =
            groupContext.copy(
                epoch = preContext.epoch + 1,
                treeHash = tree.treeHash(),
                confirmedTranscriptHash = confirmedTranscriptHash,
            )
        // initSecret was seeded with the external init secret (RFC 9420 §8.3).
        epochSecrets = KeySchedule(groupContext.toTlsBytes()).deriveEpochSecrets(generated.commitSecret, initSecret, pskSecret)
        initSecret = epochSecrets.initSecret
        secretTree = SecretTree(epochSecrets.encryptionSecret, tree.leafCount)
        val confirmationTag = computeConfirmationTag(epochSecrets.confirmationKey, confirmedTranscriptHash)
        interimTranscriptHash = interimTranscriptHashOf(confirmedTranscriptHash, confirmationTag)

        val framed = MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, confirmationTag, membershipTag = null)).toTlsBytes()
        return commitBytes to framed
    }

    /**
     * Add a member to the group by their KeyPackage.
     * Creates and applies a Commit with an Add proposal. The resulting
     * [CommitResult.preCommitExporterSecret] is the key the outer kind:445
     * MUST be encrypted with (RFC 9420 §12.4 + MDK parity).
     */
    fun addMember(keyPackageBytes: ByteArray): CommitResult = addMembers(listOf(keyPackageBytes))

    /**
     * Add several members in ONE commit.
     *
     * Not a convenience wrapper over [addMember] — a commit per Add costs an
     * epoch and a publish round trip each, and every existing member processes
     * each one. The Welcome already carries a separate `EncryptedGroupSecrets`
     * per added member, keyed by KeyPackage reference (RFC 9420 §12.4.3.1), so
     * one commit serves all of them and each joiner finds its own secrets.
     *
     * The reference implementation adds every invitee named at group creation
     * this way, which is why a group it creates with two invitees sits at epoch
     * 1 while ours used to reach epoch 2.
     */
    fun addMembers(keyPackagesBytes: List<ByteArray>): CommitResult {
        require(keyPackagesBytes.isNotEmpty()) { "addMembers needs at least one KeyPackage" }
        keyPackagesBytes.forEach { proposeAdd(it) }
        return commit()
    }

    /**
     * Remove a member from the group.
     * Creates and applies a Commit with a Remove proposal. See [addMember]
     * for the pre-commit exporter key contract on the returned [CommitResult].
     */
    fun removeMember(targetLeafIndex: Int): CommitResult {
        proposeRemove(targetLeafIndex)
        return commit()
    }

    /**
     * Build a standalone SelfRemove proposal framed as a PublicMessage
     * (draft-ietf-mls-extensions), staged in our own pool too.
     *
     * A member leaves by asking: it cannot commit its own removal, so another
     * member commits the proposal by reference. The second return value is
     * the epoch's [MlsGroupPolicy.commitExporter] secret, the key a binding
     * outer-encrypts this message under.
     */
    fun buildSelfRemoveProposalMessage(): Pair<ByteArray, ByteArray> {
        policy.authorizeSelfRemove(view())
        val preCommitExporterSecret =
            policy.commitExporter?.let { exporterSecret(it.label, it.context, it.length) } ?: ByteArray(0)
        return proposalMessage(Proposal.SelfRemove(), WireFormat.PUBLIC_MESSAGE) to preCommitExporterSecret
    }
}

/**
 * A proposal waiting in the pending pool for a commit.
 *
 * [senderLeafIndex] is a leaf index for a member sender and an index into
 * the `external_senders` extension for an external one.
 */
data class PendingProposal(
    val proposal: Proposal,
    val senderLeafIndex: Int,
    /**
     * Encoded `AuthenticatedContent` bytes for the message that delivered
     * this proposal — the input to `MakeProposalRef` per RFC 9420 §5.2.
     * Null when the proposal was created locally and never went through
     * the MLS framing layer; in that case the lookup falls back to the
     * bare `proposal.toTlsBytes()` since local commits inline rather than
     * reference our own pending proposals.
     */
    val authenticatedContentBytes: ByteArray? = null,
    /** Who sent it: a member, an external sender, or a new member proposing its own Add. */
    val senderType: SenderType = SenderType.MEMBER,
) {
    /** Whether the member at [leafIndex] sent this proposal. */
    fun isFrom(leafIndex: Int): Boolean = senderType == SenderType.MEMBER && senderLeafIndex == leafIndex
}

data class DecryptedMessage(
    val senderLeafIndex: Int,
    val contentType: ContentType,
    val content: ByteArray,
    val epoch: Long,
    /**
     * MLS `authenticated_data` as the sender wrote it — authenticated by the
     * AEAD, but readable by anyone who carried the message.
     *
     * Empty when the sender set none. A binding that puts meaning here (cordn
     * binds the sender's account pubkey) must treat empty as a rejection rather
     * than a default, or an attacker simply omits the field.
     */
    val authenticatedData: ByteArray = ByteArray(0),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DecryptedMessage) return false
        return senderLeafIndex == other.senderLeafIndex &&
            content.contentEquals(other.content) &&
            epoch == other.epoch &&
            authenticatedData.contentEquals(other.authenticatedData)
    }

    override fun hashCode(): Int {
        var result = senderLeafIndex
        result = 31 * result + content.contentHashCode()
        result = 31 * result + epoch.hashCode()
        result = 31 * result + authenticatedData.contentHashCode()
        return result
    }
}

/** What [MlsGroup.processMessage] did with a message. */
sealed class ProcessedMessage {
    /** An application message, decrypted and authenticated. */
    class Application(
        val message: DecryptedMessage,
    ) : ProcessedMessage()

    /** A standalone proposal, now waiting in the pending pool under [proposalRef]. */
    class StagedProposal(
        val proposal: Proposal,
        val sender: Sender,
        val proposalRef: ByteArray,
    ) : ProcessedMessage()

    /**
     * A commit, applied: the group is now at [epoch]. [removedSelf] means the
     * commit removed us — the group can no longer be used.
     */
    class AppliedCommit(
        val sender: Sender,
        val epoch: Long,
        val removedSelf: Boolean,
    ) : ProcessedMessage()
}
