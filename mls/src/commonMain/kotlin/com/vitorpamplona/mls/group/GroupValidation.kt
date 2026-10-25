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

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.messages.GroupContext
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.mls.tree.BinaryTree
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode
import com.vitorpamplona.mls.tree.LeafNodeSource
import com.vitorpamplona.mls.tree.RatchetTree
import com.vitorpamplona.mls.tree.TreeNode

/**
 * The RFC 9420 validity rules for LeafNodes (§7.3), KeyPackages (§10.1) and
 * a ratchet tree a joiner receives (§12.4.3.1).
 *
 * Every rule here is checked on both sides of the wire: a committer runs them
 * before sending, a receiver before applying. A rule only one side enforces
 * splits the group the first time it fires.
 */
internal object GroupValidation {
    /** Protocol version mls10. */
    const val MLS_VERSION = 1

    /** The only ciphersuite this engine implements. */
    const val CIPHER_SUITE = 1

    /**
     * Extension types RFC 9420 §7.2 calls default: a capabilities field MUST
     * NOT list them, so a leaf may carry them without listing them.
     */
    val DEFAULT_EXTENSION_TYPES = setOf(0x0001, 0x0002, 0x0003, 0x0004, 0x0005)

    /** Proposal types RFC 9420 §7.2 calls default (add … group_context_extensions). */
    val DEFAULT_PROPOSAL_TYPES = (1..7).toSet()

    /** Where an extension list sits, for the RFC 9420 §17.3 "Message(s)" column. */
    enum class ExtensionContext { GROUP_CONTEXT, LEAF_NODE, GROUP_INFO, KEY_PACKAGE }

    /** The one message type each default extension may appear in (RFC 9420 §17.3). */
    private val DEFAULT_EXTENSION_CONTEXT =
        mapOf(
            0x0001 to ExtensionContext.LEAF_NODE, // application_id
            0x0002 to ExtensionContext.GROUP_INFO, // ratchet_tree
            0x0003 to ExtensionContext.GROUP_CONTEXT, // required_capabilities
            0x0004 to ExtensionContext.GROUP_INFO, // external_pub
            0x0005 to ExtensionContext.GROUP_CONTEXT, // external_senders
        )

    /**
     * An extension list must not repeat a type, a default extension may only
     * appear in the message RFC 9420 §17.3 lists for it, and its data must be
     * the struct the RFC defines. Other implementations parse the default
     * extensions they find, so a malformed one makes the whole message
     * unreadable to them.
     */
    fun validateExtensions(
        extensions: List<Extension>,
        context: ExtensionContext,
    ) {
        val seen = mutableSetOf<Int>()
        for (ext in extensions) {
            require(seen.add(ext.extensionType)) { "Extension type ${ext.extensionType} appears twice" }
            val allowedIn = DEFAULT_EXTENSION_CONTEXT[ext.extensionType] ?: continue
            require(allowedIn == context) { "Extension type ${ext.extensionType} may not appear in a $context" }
            val reader = TlsReader(ext.extensionData)
            when (ext.extensionType) {
                0x0001, 0x0004 -> reader.readOpaqueVarInt()
                0x0002 -> RatchetTree.decodeTls(reader)
                0x0003 -> repeat(3) { reader.readOpaqueVarInt() }
                0x0005 -> reader.readVectorVarInt { r -> r.readOpaqueVarInt().also { Credential.decodeTls(r) } }
            }
            reader.requireFullyConsumed("Extension ${ext.extensionType}")
        }
    }

    /**
     * RFC 9420 §7.3 LeafNode validation.
     *
     * @param expectedSource the source the context requires, or null to accept
     *   any (a leaf found in a received tree).
     * @param groupId and [leafIndex] are the TBS context of an update/commit leaf.
     * @param replacedLeafIndex the leaf this one replaces or occupies, excluded
     *   from the uniqueness and cross-member checks; null for a new leaf.
     * @param now when non-null, the lifetime of a key_package leaf must cover it.
     */
    fun validateLeafNode(
        leaf: LeafNode,
        expectedSource: LeafNodeSource?,
        groupId: ByteArray,
        leafIndex: Int?,
        tree: RatchetTree,
        replacedLeafIndex: Int?,
        groupExtensions: List<Extension>,
        policy: MlsGroupPolicy,
        now: Long?,
        /** False when the caller checks the whole tree's uniqueness and credential support at once. */
        againstMembers: Boolean = true,
    ) {
        policy.validateCredential(leaf.credential, leaf.signatureKey)

        if (expectedSource != null) {
            require(leaf.leafNodeSource == expectedSource) {
                "LeafNode has leaf_node_source ${leaf.leafNodeSource}, expected $expectedSource"
            }
        }

        val tbs =
            if (leaf.leafNodeSource == LeafNodeSource.KEY_PACKAGE) {
                leaf.encodeTbs()
            } else {
                leaf.encodeTbs(groupId, requireNotNull(leafIndex) { "an ${leaf.leafNodeSource} leaf is signed for a leaf index" })
            }
        require(MlsCryptoProvider.verifyWithLabel(leaf.signatureKey, "LeafNodeTBS", tbs, leaf.signature)) {
            "Invalid LeafNode signature"
        }

        val caps = leaf.capabilities
        require(MLS_VERSION in caps.versions) { "LeafNode does not support MLS protocol version 1" }
        require(CIPHER_SUITE in caps.ciphersuites) { "LeafNode does not support ciphersuite 0x0001" }

        MlsGroup.findRequiredCapabilities(groupExtensions)?.let { req ->
            MlsGroup.requireCapabilitiesMeetRequirements(caps, req, "LeafNode")
        }

        // The credential type must be one every member supports, and this leaf
        // must support every credential type other members use.
        require(leaf.credential.credentialType in caps.credentials) {
            "LeafNode does not list its own credential type ${leaf.credential.credentialType} in its capabilities"
        }
        for (i in 0 until tree.leafCount) {
            if (!againstMembers) break
            if (i == replacedLeafIndex) continue
            val other = tree.getLeaf(i) ?: continue
            require(leaf.credential.credentialType in other.capabilities.credentials) {
                "Member leaf $i does not support credential type ${leaf.credential.credentialType}"
            }
            require(other.credential.credentialType in caps.credentials) {
                "LeafNode does not support credential type ${other.credential.credentialType} used by leaf $i"
            }
        }

        if (now != null && leaf.leafNodeSource == LeafNodeSource.KEY_PACKAGE) {
            val lifetime = requireNotNull(leaf.lifetime) { "key_package LeafNode without a lifetime" }
            // not_before / not_after are uint64: compare unsigned, or a lifetime
            // ending at 2^64-1 ("never") reads as -1 and is always expired.
            require(now.toULong() in lifetime.notBefore.toULong()..lifetime.notAfter.toULong()) { "KeyPackage lifetime expired or not yet valid" }
        }

        validateExtensions(leaf.extensions, ExtensionContext.LEAF_NODE)
        for (ext in leaf.extensions) {
            require(ext.extensionType in DEFAULT_EXTENSION_TYPES || ext.extensionType in caps.extensions) {
                "LeafNode carries extension ${ext.extensionType} its capabilities do not list"
            }
        }

        for (i in 0 until tree.leafCount) {
            if (!againstMembers) break
            if (i == replacedLeafIndex) continue
            val other = tree.getLeaf(i) ?: continue
            require(!other.signatureKey.contentEquals(leaf.signatureKey)) { "Duplicate signature key: leaf $i already uses it" }
            require(!other.encryptionKey.contentEquals(leaf.encryptionKey)) { "Duplicate encryption key: leaf $i already uses it" }
        }
    }

    /** RFC 9420 §10.1 KeyPackage validation, plus §7.3 for its leaf. */
    fun validateKeyPackage(
        keyPackage: MlsKeyPackage,
        groupContext: GroupContext,
        tree: RatchetTree,
        policy: MlsGroupPolicy,
        now: Long?,
    ) {
        require(keyPackage.version == groupContext.version) { "KeyPackage version ${keyPackage.version} doesn't match the group's" }
        require(keyPackage.cipherSuite == groupContext.cipherSuite) { "KeyPackage ciphersuite ${keyPackage.cipherSuite} doesn't match the group's" }
        require(keyPackage.verifySignature()) { "Invalid KeyPackage signature" }
        require(!keyPackage.initKey.contentEquals(keyPackage.leafNode.encryptionKey)) {
            "KeyPackage init_key equals its leaf's encryption_key"
        }
        validateExtensions(keyPackage.extensions, ExtensionContext.KEY_PACKAGE)
        validateLeafNode(keyPackage.leafNode, LeafNodeSource.KEY_PACKAGE, groupContext.groupId, null, tree, null, groupContext.extensions, policy, now)
    }

    /**
     * RFC 9420 §12.4.3.1 "Verify the integrity of the ratchet tree" for a tree a
     * joiner was handed: tree hash, parent hashes, every leaf, unmerged leaves
     * and the uniqueness of every node's public key.
     *
     * Leaf lifetimes are not checked: the members of a long-lived group joined
     * with KeyPackages that have long since expired, and the RFC only
     * RECOMMENDS the check on received leaves.
     */
    fun validateTree(
        tree: RatchetTree,
        groupContext: GroupContext,
        policy: MlsGroupPolicy,
    ) {
        require(tree.leafCount > 0) { "ratchet_tree is empty" }
        validateExtensions(groupContext.extensions, ExtensionContext.GROUP_CONTEXT)
        require(tree.treeHash().contentEquals(groupContext.treeHash)) { "GroupInfo tree_hash does not match ratchet_tree" }
        MlsGroup.verifyTreeParentHashesForJoin(tree)?.let { reason ->
            throw IllegalStateException("ratchet_tree fails parent_hash validation: $reason")
        }

        // Each leaf on its own, then what relates leaves to each other in one
        // pass: a large group's tree has thousands of leaves.
        val credentialTypes = mutableSetOf<Int>()
        val signatureKeys = mutableSetOf<String>()
        for (i in 0 until tree.leafCount) {
            val leaf = tree.getLeaf(i) ?: continue
            validateLeafNode(leaf, null, groupContext.groupId, i, tree, i, groupContext.extensions, policy, now = null, againstMembers = false)
            credentialTypes.add(leaf.credential.credentialType)
            require(
                signatureKeys.add(
                    com.vitorpamplona.mls.platform.Hex
                        .encode(leaf.signatureKey),
                ),
            ) { "Duplicate signature key at leaf $i" }
        }
        for (i in 0 until tree.leafCount) {
            val leaf = tree.getLeaf(i) ?: continue
            require(leaf.capabilities.credentials.containsAll(credentialTypes)) {
                "Member leaf $i does not support every credential type in use ($credentialTypes)"
            }
        }

        val seenKeys = mutableSetOf<String>()
        val nodeCount = BinaryTree.nodeCount(tree.leafCount)
        for (nodeIdx in 0 until nodeCount) {
            val key =
                when (val node = tree.getNode(nodeIdx)) {
                    is TreeNode.Leaf -> node.leafNode.encryptionKey
                    is TreeNode.Parent -> node.parentNode.encryptionKey
                    null -> continue
                }
            require(
                seenKeys.add(
                    com.vitorpamplona.mls.platform.Hex
                        .encode(key),
                ),
            ) {
                "Encryption key at node $nodeIdx appears in another node of the tree"
            }
        }

        for (parentIdx in tree.parentNodeIndices()) {
            for (unmerged in tree.unmergedLeavesOf(parentIdx)) {
                require(unmerged in 0 until tree.leafCount && tree.getLeaf(unmerged) != null) {
                    "Parent $parentIdx lists unmerged leaf $unmerged, which is blank"
                }
                val leafNode = BinaryTree.leafToNode(unmerged)
                require(
                    com.vitorpamplona.mls.tree.TreeKem
                        .isInSubtree(parentIdx, leafNode),
                ) {
                    "Parent $parentIdx lists unmerged leaf $unmerged, which is not its descendant"
                }
                for (between in BinaryTree.directPath(unmerged, tree.leafCount)) {
                    if (between == parentIdx) break
                    if (tree.getNode(between) == null) continue
                    require(unmerged in tree.unmergedLeavesOf(between)) {
                        "Node $between between leaf $unmerged and its ancestor $parentIdx does not list it as unmerged"
                    }
                }
            }
        }
    }
}
