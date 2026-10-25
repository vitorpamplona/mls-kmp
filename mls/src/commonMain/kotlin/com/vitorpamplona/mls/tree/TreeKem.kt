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
package com.vitorpamplona.mls.tree

import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.mls.crypto.Hpke
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.messages.UpdatePath

/**
 * TreeKEM (RFC 9420 §7.4–7.6, §7.9) over a [RatchetTree].
 *
 * Everything here walks the sender's FILTERED direct path: the parents
 * whose copath child has a non-empty resolution. One path secret is derived
 * per filtered node (§7.4), the UpdatePath carries one node per filtered
 * node (§7.6), and the parent-hash chain links filtered nodes (§7.9.2). A
 * level that is filtered out takes no part in any of the three, which is
 * what lets two implementations agree whenever a subtree is blank.
 */
object TreeKem {
    /** Fresh key material for a committer's direct path. */
    class GeneratedPath(
        /** The sender's filtered direct path, leaf-ward first. */
        val filteredPath: List<Int>,
        /** path_secret[i] for filteredPath[i]. */
        val pathSecrets: List<ByteArray>,
        /** HPKE key pairs for filteredPath[i]: (private, public). */
        val nodeKeys: List<Pair<ByteArray, ByteArray>>,
        val commitSecret: ByteArray,
    ) {
        fun privateKeysByNode(): Map<Int, ByteArray> = filteredPath.zip(nodeKeys).associate { (node, kp) -> node to kp.first }

        /** The path secret a joiner at [leafIndex] needs: the one at its lowest common ancestor with the sender. */
        fun pathSecretFor(
            tree: RatchetTree,
            senderLeafIndex: Int,
            leafIndex: Int,
        ): ByteArray? {
            val i = filteredPath.indexOfFirst { isInSubtree(copathChild(it, senderLeafIndex), BinaryTree.leafToNode(leafIndex)) }
            return if (i >= 0) pathSecrets[i] else null
        }
    }

    /** Recovered path secrets after decrypting someone else's UpdatePath. */
    class DecryptedPath(
        /** The filtered-path nodes whose private keys we now hold, with those keys. */
        val nodePrivateKeys: Map<Int, ByteArray>,
        val commitSecret: ByteArray,
    )

    fun nodeKeyPair(pathSecret: ByteArray): Pair<ByteArray, ByteArray> {
        val nodeSecret = MlsCryptoProvider.deriveSecret(pathSecret, "node")
        val kp = Hpke.deriveKeyPair(nodeSecret).also { nodeSecret.fill(0) }
        return kp.privateKey to kp.publicKey
    }

    fun nextPathSecret(pathSecret: ByteArray): ByteArray = MlsCryptoProvider.deriveSecret(pathSecret, "path")

    /** The child of [parentNode] that does NOT contain [leafIndex]: the copath node at that level. */
    fun copathChild(
        parentNode: Int,
        leafIndex: Int,
    ): Int = if (BinaryTree.leafToNode(leafIndex) < parentNode) BinaryTree.right(parentNode) else BinaryTree.left(parentNode)

    /** Whether [nodeIndex] is [subtreeRoot] or one of its descendants. */
    fun isInSubtree(
        subtreeRoot: Int,
        nodeIndex: Int,
    ): Boolean {
        val span = (1 shl BinaryTree.level(subtreeRoot)) - 1
        return nodeIndex in (subtreeRoot - span)..(subtreeRoot + span)
    }

    /**
     * Derive the path secrets and node keys for [senderLeafIndex]'s filtered
     * direct path from a random `path_secret[0]` (RFC 9420 §7.4).
     *
     * With an empty filtered path (the sender is alone) the commit secret is
     * the starting secret itself, which is what openmls derives.
     */
    fun generate(
        tree: RatchetTree,
        senderLeafIndex: Int,
        firstPathSecret: ByteArray = MlsCryptoProvider.randomBytes(MlsCryptoProvider.HASH_OUTPUT_LENGTH),
    ): GeneratedPath {
        val (filtered, _) = tree.filteredDirectPath(senderLeafIndex)
        val secrets = mutableListOf<ByteArray>()
        var secret = firstPathSecret
        for (i in filtered.indices) {
            if (i > 0) secret = nextPathSecret(secret)
            secrets.add(secret)
        }
        val commitSecret = if (secrets.isEmpty()) firstPathSecret else nextPathSecret(secrets.last())
        return GeneratedPath(filtered, secrets, secrets.map { nodeKeyPair(it) }, commitSecret)
    }

    /**
     * Merge a sender's new path public keys into the tree (RFC 9420 §7.5):
     * blank the sender's whole direct path, then set each filtered node's
     * key with no unmerged leaves, and compute the parent-hash chain.
     *
     * Leaves the sender's leaf as it is: the caller sets it, because the
     * sender signs its new leaf over the parent hash this returns.
     *
     * @return the parent_hash the sender's leaf must carry.
     */
    fun mergePathKeys(
        tree: RatchetTree,
        senderLeafIndex: Int,
        publicKeys: List<ByteArray>,
    ): ByteArray {
        val (filtered, _) = tree.filteredDirectPath(senderLeafIndex)
        require(publicKeys.size == filtered.size) {
            "UpdatePath node count (${publicKeys.size}) doesn't match filtered direct path length (${filtered.size})"
        }
        for (node in BinaryTree.directPath(senderLeafIndex, tree.leafCount)) tree.setParent(node, null)
        for ((i, node) in filtered.withIndex()) {
            tree.setParent(node, ParentNode(publicKeys[i], ByteArray(0), emptyList()))
        }
        // Root-ward first: each node's parent_hash covers the node above it.
        var aboveHash = ByteArray(0)
        for (i in filtered.indices.reversed()) {
            val node = filtered[i]
            val parent = (tree.getNode(node) as TreeNode.Parent).parentNode
            tree.setParent(node, parent.copy(parentHash = aboveHash))
            aboveHash = parentHashOf(tree, node, senderLeafIndex)
        }
        return aboveHash
    }

    /**
     * ParentHash(P) as seen from the child on [senderLeafIndex]'s side:
     * Hash(ParentHashInput(P.encryption_key, P.parent_hash, tree_hash(sibling))).
     * The sibling is untouched by the path, so its current hash is the original one.
     */
    private fun parentHashOf(
        tree: RatchetTree,
        parentNode: Int,
        senderLeafIndex: Int,
    ): ByteArray {
        val parent = (tree.getNode(parentNode) as TreeNode.Parent).parentNode
        val siblingHash = tree.treeHashNode(copathChild(parentNode, senderLeafIndex))
        return MlsCryptoProvider.hash(encodeParentHashInput(parent.encryptionKey, parent.parentHash, siblingHash))
    }

    fun encodeParentHashInput(
        encryptionKey: ByteArray,
        parentHash: ByteArray,
        originalSiblingTreeHash: ByteArray,
    ): ByteArray {
        val w =
            com.vitorpamplona.mls.codec
                .TlsWriter()
        w.putOpaqueVarInt(encryptionKey)
        w.putOpaqueVarInt(parentHash)
        w.putOpaqueVarInt(originalSiblingTreeHash)
        return w.toByteArray()
    }

    /**
     * The copath resolution each UpdatePath node is encrypted to, with the
     * leaves added by the same commit removed (RFC 9420 §7.5).
     */
    fun copathResolutions(
        tree: RatchetTree,
        senderLeafIndex: Int,
        excludedLeaves: Set<Int>,
    ): List<List<Int>> {
        val (_, filteredCopath) = tree.filteredDirectPath(senderLeafIndex)
        return filteredCopath.map { copath ->
            tree.resolution(copath).filterNot { BinaryTree.isLeaf(it) && BinaryTree.nodeToLeaf(it) in excludedLeaves }
        }
    }

    /** HPKE-encrypt each path secret to its copath resolution under [groupContext] (§7.6). */
    fun encryptPathSecrets(
        tree: RatchetTree,
        senderLeafIndex: Int,
        generated: GeneratedPath,
        excludedLeaves: Set<Int>,
        groupContext: ByteArray,
    ): List<UpdatePathNode> {
        val resolutions = copathResolutions(tree, senderLeafIndex, excludedLeaves)
        return generated.filteredPath.indices.map { i ->
            UpdatePathNode(
                encryptionKey = generated.nodeKeys[i].second,
                encryptedPathSecret =
                    resolutions[i].map { resNode ->
                        MlsCryptoProvider.encryptWithLabel(nodePublicKey(tree, resNode), "UpdatePathNode", groupContext, generated.pathSecrets[i])
                    },
            )
        }
    }

    private fun nodePublicKey(
        tree: RatchetTree,
        nodeIndex: Int,
    ): ByteArray =
        when (val node = requireNotNull(tree.getNode(nodeIndex)) { "resolution node $nodeIndex is blank" }) {
            is TreeNode.Leaf -> node.leafNode.encryptionKey
            is TreeNode.Parent -> node.parentNode.encryptionKey
        }

    /**
     * Decrypt the path secret addressed to [myLeafIndex] in [updatePath] and
     * derive the rest of the chain (RFC 9420 §7.5, "decrypts the path secrets").
     *
     * Call on the tree AFTER [mergePathKeys]; [privateKeyFor] returns our private
     * key for a node in the resolution, or null when we hold none. Verifies that
     * every public key derived from the recovered secrets equals the one the
     * sender published (step 6), so a sender cannot hand different members
     * secrets that disagree with the tree.
     */
    fun decryptPathSecrets(
        tree: RatchetTree,
        senderLeafIndex: Int,
        myLeafIndex: Int,
        updatePath: UpdatePath,
        excludedLeaves: Set<Int>,
        groupContext: ByteArray,
        privateKeyFor: (Int) -> ByteArray?,
    ): DecryptedPath {
        val (filtered, _) = tree.filteredDirectPath(senderLeafIndex)
        val resolutions = copathResolutions(tree, senderLeafIndex, excludedLeaves)
        require(updatePath.nodes.size == filtered.size) {
            "UpdatePath node count (${updatePath.nodes.size}) doesn't match filtered direct path length (${filtered.size})"
        }
        for (i in filtered.indices) {
            require(updatePath.nodes[i].encryptedPathSecret.size == resolutions[i].size) {
                "UpdatePath node $i carries ${updatePath.nodes[i].encryptedPathSecret.size} ciphertexts for a resolution of ${resolutions[i].size}"
            }
        }

        val myNode = BinaryTree.leafToNode(myLeafIndex)
        val ancestor = filtered.indexOfFirst { isInSubtree(copathChild(it, senderLeafIndex), myNode) }
        check(ancestor >= 0) { "No node of the sender's filtered direct path covers leaf $myLeafIndex" }

        val slot = resolutions[ancestor].indexOfFirst { privateKeyFor(it) != null }
        check(slot >= 0) {
            "UpdatePath at common ancestor ${filtered[ancestor]} carries no ciphertext for a key we hold " +
                "(my_leaf=$myLeafIndex, resolution=${resolutions[ancestor]})"
        }
        val ct = updatePath.nodes[ancestor].encryptedPathSecret[slot]
        var secret =
            MlsCryptoProvider.decryptWithLabel(
                privateKeyFor(resolutions[ancestor][slot])!!,
                "UpdatePathNode",
                groupContext,
                ct.kemOutput,
                ct.ciphertext,
            )

        val keys = mutableMapOf<Int, ByteArray>()
        try {
            for (i in ancestor until filtered.size) {
                if (i > ancestor) secret = nextPathSecret(secret).also { secret.fill(0) }
                val (priv, pub) = nodeKeyPair(secret)
                require(pub.contentEquals(updatePath.nodes[i].encryptionKey)) {
                    "UpdatePath public key at node ${filtered[i]} does not match the key derived from its path secret"
                }
                keys[filtered[i]] = priv
            }
            return DecryptedPath(keys, nextPathSecret(secret))
        } finally {
            // Path secrets are spent once their keys exist (RFC 9420 §16.6).
            secret.fill(0)
        }
    }

    /**
     * Derive our keys from a path secret handed over in a Welcome: [pathSecret]
     * belongs to the lowest common ancestor of our leaf and [senderLeafIndex]'s,
     * and ratchets up the sender's filtered path. Each derived public key must
     * match the tree (RFC 9420 §12.4.3.1).
     */
    fun keysFromWelcomePathSecret(
        tree: RatchetTree,
        senderLeafIndex: Int,
        myLeafIndex: Int,
        pathSecret: ByteArray,
    ): Map<Int, ByteArray> {
        val (filtered, _) = tree.filteredDirectPath(senderLeafIndex)
        val myNode = BinaryTree.leafToNode(myLeafIndex)
        val ancestor = filtered.indexOfFirst { isInSubtree(copathChild(it, senderLeafIndex), myNode) }
        require(ancestor >= 0) { "The Welcome's path_secret has no common ancestor on the committer's filtered path" }
        var secret = pathSecret
        val keys = mutableMapOf<Int, ByteArray>()
        for (i in ancestor until filtered.size) {
            if (i > ancestor) secret = nextPathSecret(secret).also { if (secret !== pathSecret) secret.fill(0) }
            val (priv, pub) = nodeKeyPair(secret)
            val treeKey = (tree.getNode(filtered[i]) as? TreeNode.Parent)?.parentNode?.encryptionKey
            require(treeKey != null && treeKey.contentEquals(pub)) {
                "Welcome path_secret derives a key that is not the tree's at node ${filtered[i]}"
            }
            keys[filtered[i]] = priv
        }
        if (secret !== pathSecret) secret.fill(0)
        return keys
    }

    /** Whether [privateKey] is the private half of the key currently at [nodeIndex]. */
    fun holdsKeyFor(
        tree: RatchetTree,
        nodeIndex: Int,
        privateKey: ByteArray,
    ): Boolean {
        val pub = (tree.getNode(nodeIndex) as? TreeNode.Parent)?.parentNode?.encryptionKey ?: return false
        return X25519.publicFromPrivate(privateKey).contentEquals(pub)
    }
}
