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

import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode

/**
 * A group seen from outside: what a delivery service or relay can know about
 * a group without being in it.
 *
 * Built from a signed GroupInfo, it follows the group through the
 * PublicMessages its members send — proposals and commits, including
 * external joins — and checks each one the way a member would: signatures,
 * the RFC 9420 §12.2 proposal-list rules, every new LeafNode, the
 * UpdatePath's parent hashes, and the application's [MlsGroupPolicy]. A
 * message that fails is rejected and the view stays where it was, so the
 * service can refuse to fan out a commit the members would reject.
 *
 * What it cannot check needs the epoch's secrets: the membership tag (it
 * sees one is there), the confirmation tag, whether the PSKs a commit names
 * exist, and anything inside a PrivateMessage. So a member with a valid
 * signing key can get a commit past the view that the other members then
 * refuse; the view trails them from that point and should be rebuilt from a
 * fresh GroupInfo. A group whose policy sends handshakes as PrivateMessages
 * ([WireFormatPolicy.PURE_CIPHERTEXT]) cannot be followed this way at all.
 * Nor can a PublicGroup produce anything: it has no leaf and signs nothing.
 *
 * Not thread-safe, like [MlsGroup]: one thread at a time per view.
 */
class PublicGroup private constructor(
    private val group: MlsGroup,
) {
    val groupId: ByteArray get() = group.groupId.copyOf()

    val epoch: Long get() = group.epoch

    /** The GroupContext extensions. */
    val extensions: List<Extension> get() = group.groupContextExtensionsSnapshot()

    /** The occupied leaves, by leaf index. */
    fun members(): List<Pair<Int, LeafNode>> = group.members()

    /** The ratchet tree, TLS-encoded: what a joiner needs when the GroupInfo leaves it out. */
    fun exportTreeBytes(): ByteArray = group.exportTreeBytes()

    /** Proposals sent by reference this epoch, waiting for a commit. */
    fun pendingProposals(): List<PendingProposal> = group.pendingProposalsSnapshot()

    /**
     * Check and apply a PublicMessage proposal or commit. Throws, leaving the
     * view unchanged, when the message is invalid, is for another group or
     * epoch, or is a PrivateMessage this view cannot read.
     *
     * [ProcessedMessage.AppliedCommit.removedSelf] is always false: the view
     * has no leaf to lose.
     */
    fun processMessage(messageBytes: ByteArray): ProcessedMessage {
        // The header alone says the wire format (version, then wire_format); the
        // engine decodes the rest after its size check.
        require(messageBytes.size >= 4) { "Not an MLSMessage" }
        val wireFormat = ((messageBytes[2].toInt() and 0xFF) shl 8) or (messageBytes[3].toInt() and 0xFF)
        require(wireFormat == WireFormat.PUBLIC_MESSAGE.value) { "A PublicGroup reads PublicMessages only, not wire format $wireFormat" }
        return when (val processed = group.processMessage(messageBytes)) {
            is ProcessedMessage.AppliedCommit -> ProcessedMessage.AppliedCommit(processed.sender, processed.epoch, removedSelf = false, processed.proposals)
            else -> processed
        }
    }

    /**
     * Snapshot for [restore]. It holds no secrets — a PublicGroup has none —
     * but the same [MlsGroupState] format members use.
     */
    fun saveState(): MlsGroupState = group.saveState()

    companion object {
        /**
         * Start following the group [groupInfoBytes] describes (bare or as an
         * MLSMessage). Its signature and its whole tree are checked
         * (RFC 9420 §12.4.3.1); [ratchetTree] supplies the tree when the
         * GroupInfo leaves it out.
         */
        fun fromGroupInfo(
            groupInfoBytes: ByteArray,
            policy: MlsGroupPolicy = MlsGroupPolicy.Permissive,
            ratchetTree: ByteArray? = null,
        ): PublicGroup = PublicGroup(MlsGroup.observe(groupInfoBytes, policy, ratchetTree))

        /** A PublicGroup from [saveState]. Supply the policy it ran under. */
        fun restore(
            state: MlsGroupState,
            policy: MlsGroupPolicy = MlsGroupPolicy.Permissive,
        ): PublicGroup = PublicGroup(MlsGroup.restore(state, policy, observer = true))
    }
}
