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

import com.vitorpamplona.mls.JsonMapper
import com.vitorpamplona.mls.TestResourceLoader
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.hexToByteArray
import com.vitorpamplona.mls.messages.GroupContext
import com.vitorpamplona.mls.messages.UpdatePath
import com.vitorpamplona.mls.toHexKey
import com.vitorpamplona.mls.tree.BinaryTree
import com.vitorpamplona.mls.tree.RatchetTree
import com.vitorpamplona.mls.tree.TreeKem
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Interop tests for TreeKEM (RFC 9420 Section 7.4-7.6) against IETF test vectors
 * from github.com/mlswg/mls-implementations (treekem.json).
 *
 * Verifies ratchet tree deserialization, UpdatePath merging and parent hashes,
 * path secret decryption and commit secrets against known-good outputs from
 * OpenMLS and mls-rs, and that paths this engine generates decrypt for every
 * other member.
 */
class TreeKemInteropTest {
    private val allVectors: List<TreeKemVector> =
        JsonMapper.jsonInstance.decodeFromString<List<TreeKemVector>>(
            TestResourceLoader().loadString("mls/treekem.json"),
        )

    private val vectors: List<TreeKemVector> =
        allVectors.filter { it.cipherSuite == 1 }

    @Test
    fun testRatchetTreeDeserialization() {
        assertTrue(vectors.isNotEmpty(), "No cipher_suite==1 treekem vectors found")

        for ((idx, v) in vectors.withIndex()) {
            val treeBytes = v.ratchetTree.hexToByteArray()
            val tree = RatchetTree.decodeTls(TlsReader(treeBytes))

            assertNotNull(tree, "RatchetTree decode failed at vector $idx")

            // Verify round-trip
            val writer = TlsWriter()
            tree.encodeTls(writer)
            val reEncoded = writer.toByteArray()
            assertEquals(
                v.ratchetTree,
                reEncoded.toHexKey(),
                "RatchetTree round-trip mismatch at vector $idx",
            )
        }
    }

    /** Private keys a vector leaf holds: its leaf key plus every parent it has a path secret for. */
    private fun keysOf(leaf: TreeKemLeafPrivate): Map<Int, ByteArray> =
        leaf.pathSecrets.associate { it.node to TreeKem.nodeKeyPair(it.pathSecret.hexToByteArray()).first } +
            (BinaryTree.leafToNode(leaf.index) to leaf.encryptionPriv.hexToByteArray())

    private fun context(
        v: TreeKemVector,
        treeHash: ByteArray,
    ): ByteArray =
        GroupContext(
            groupId = v.groupId.hexToByteArray(),
            epoch = v.epoch,
            treeHash = treeHash,
            confirmedTranscriptHash = v.confirmedTranscriptHash.hexToByteArray(),
        ).toTlsBytes()

    /**
     * Every vector UpdatePath merges to `tree_hash_after` with a valid
     * parent-hash chain, and every other leaf decrypts its path secret and the
     * commit secret from it (RFC 9420 §7.5).
     */
    @Test
    fun testUpdatePathsMergeAndDecrypt() {
        assertTrue(vectors.isNotEmpty(), "No cipher_suite==1 treekem vectors found")
        var decrypted = 0
        for ((idx, v) in vectors.withIndex()) {
            for ((pathIdx, u) in v.updatePaths.withIndex()) {
                val tree = RatchetTree.decodeTls(TlsReader(v.ratchetTree.hexToByteArray()))
                val path = UpdatePath.decodeTls(TlsReader(u.updatePath.hexToByteArray()))
                tree.setLeaf(u.sender, path.leafNode)
                val leafParentHash = TreeKem.mergePathKeys(tree, u.sender, path.nodes.map { it.encryptionKey })
                assertEquals(path.leafNode.parentHash?.toHexKey(), leafParentHash.toHexKey(), "vector $idx path $pathIdx: leaf parent_hash")
                assertEquals(u.treeHashAfter, tree.treeHash().toHexKey(), "vector $idx path $pathIdx: tree_hash_after")

                val ctx = context(v, tree.treeHash())
                for (leaf in v.leavesPrivate) {
                    if (leaf.index == u.sender) continue
                    val keys = keysOf(leaf)
                    val result = TreeKem.decryptPathSecrets(tree, u.sender, leaf.index, path, emptySet(), ctx) { keys[it] }
                    assertEquals(u.commitSecret, result.commitSecret.toHexKey(), "vector $idx path $pathIdx leaf ${leaf.index}: commit_secret")
                    val expected = u.pathSecrets[leaf.index]
                    if (expected != null) {
                        val lowest = result.nodePrivateKeys.keys.minByOrNull { BinaryTree.level(it) }!!
                        assertEquals(
                            TreeKem.nodeKeyPair(expected.hexToByteArray()).first.toHexKey(),
                            result.nodePrivateKeys.getValue(lowest).toHexKey(),
                            "vector $idx path $pathIdx leaf ${leaf.index}: path_secret",
                        )
                    }
                    decrypted++
                }
            }
        }
        assertTrue(decrypted > 0, "no path was decrypted")
    }

    /**
     * Each private leaf generates a fresh UpdatePath over the vector tree; every
     * other private leaf decrypts it and agrees on the commit secret. This is
     * the sender side of TreeKEM against trees with blank and unmerged nodes.
     */
    @Test
    fun testGeneratedPathsDecryptForEveryOtherLeaf() {
        for ((idx, v) in vectors.withIndex()) {
            for (sender in v.leavesPrivate) {
                val tree = RatchetTree.decodeTls(TlsReader(v.ratchetTree.hexToByteArray()))
                val generated = TreeKem.generate(tree, sender.index)
                TreeKem.mergePathKeys(tree, sender.index, generated.nodeKeys.map { it.second })
                val ctx = context(v, tree.treeHash())
                val nodes = TreeKem.encryptPathSecrets(tree, sender.index, generated, emptySet(), ctx)
                val path = UpdatePath(tree.getLeaf(sender.index)!!, nodes)
                for (receiver in v.leavesPrivate) {
                    if (receiver.index == sender.index) continue
                    val keys = keysOf(receiver)
                    val result = TreeKem.decryptPathSecrets(tree, sender.index, receiver.index, path, emptySet(), ctx) { keys[it] }
                    assertEquals(
                        generated.commitSecret.toHexKey(),
                        result.commitSecret.toHexKey(),
                        "vector $idx: leaf ${receiver.index} decrypting leaf ${sender.index}'s path",
                    )
                }
            }
        }
    }
}
