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
import com.vitorpamplona.mls.tree.BinaryTree
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.LeafNode
import com.vitorpamplona.mls.tree.RatchetTree
import com.vitorpamplona.mls.tree.TreeNode
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFails

/**
 * RFC 9420 §12.4.3.1 on trees no honest member can produce: every member
 * checks every leaf as it arrives, so only a tree fabricated by a malicious
 * GroupInfo signer breaks these. Each tree here passes the tree-hash and
 * parent-hash checks and breaks exactly one rule.
 */
class JoinedTreeValidationTest {
    private fun treeOf(group: MlsGroup) = RatchetTree.decodeTls(TlsReader(group.exportTreeBytes()))

    private fun validate(
        group: MlsGroup,
        tree: RatchetTree,
        treeHash: ByteArray = tree.treeHash(),
    ) = GroupValidation.validateTree(tree, group.saveState().groupContext.copy(treeHash = treeHash), MlsGroupPolicy.Permissive)

    private fun refuses(
        reason: String,
        check: () -> Unit,
    ) = assertContains(assertFails { check() }.message.orEmpty(), reason)

    private fun leaf(
        name: String,
        credential: Credential,
        capabilities: Capabilities,
    ): LeafNode {
        val b = MlsGroup.createKeyPackage(name.encodeToByteArray(), capabilities = capabilities)
        val unsigned = b.keyPackage.leafNode.copy(credential = credential)
        return unsigned.copy(signature = MlsCryptoProvider.signWithLabel(b.signaturePrivateKey, "LeafNodeTBS", unsigned.encodeTbs()))
    }

    /** alice and four others, alice's path from leaf 0 to the root in place. */
    private fun fiveMembers(): MlsGroup {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        alice.addMembers(listOf("bob", "carol", "dave", "erin").map { MlsGroup.createKeyPackage(it.encodeToByteArray()).keyPackage.toTlsBytes() })
        return alice
    }

    private fun RatchetTree.alsoUnmergedAtRoot(leaf: Int) {
        val root = BinaryTree.root(leafCount)
        val node = (getNode(root) as TreeNode.Parent).parentNode
        setParent(root, node.copy(unmergedLeaves = node.unmergedLeaves + leaf))
    }

    @Test
    fun anHonestTreePasses() {
        val alice = fiveMembers()
        validate(alice, treeOf(alice))
    }

    @Test
    fun anEmptyTree() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        refuses("ratchet_tree is empty") { validate(alice, RatchetTree(), treeHash = ByteArray(32)) }
    }

    @Test
    fun aMemberThatDoesNotSupportACredentialInUse() {
        val both = Capabilities(credentials = listOf(Credential.CREDENTIAL_TYPE_BASIC, OTHER_CREDENTIAL))
        val alice = MlsGroup.create("alice".encodeToByteArray(), capabilities = both)
        val tree = treeOf(alice)
        tree.addLeaf(leaf("mallory", Credential.Custom(OTHER_CREDENTIAL, ByteArray(4)), both))
        tree.addLeaf(leaf("trent", Credential.Basic("trent".encodeToByteArray()), Capabilities()))
        refuses("does not support every credential type") { validate(alice, tree) }
    }

    @Test
    fun anUnmergedLeafThatDoesNotExist() {
        val alice = fiveMembers()
        val tree = treeOf(alice).apply { alsoUnmergedAtRoot(99) }
        refuses("which is blank") { validate(alice, tree) }
    }

    @Test
    fun anUnmergedLeafANodeBelowDoesNotList() {
        // bob (leaf 1) unmerged at the root, but not at node 1 between them.
        val alice = fiveMembers()
        val tree = treeOf(alice).apply { alsoUnmergedAtRoot(1) }
        refuses("does not list it as unmerged") { validate(alice, tree) }
    }

    @Test
    fun anUnmergedLeafOutsideItsParent() {
        // carol (leaf 2) unmerged at node 1, which only spans leaves 0 and 1.
        val alice = fiveMembers()
        val tree = treeOf(alice)
        val node = (tree.getNode(1) as TreeNode.Parent).parentNode
        tree.setParent(1, node.copy(unmergedLeaves = node.unmergedLeaves + 2))
        refuses("not its descendant") { validate(alice, tree) }
    }

    @Test
    fun twoLeavesWithOneSignatureKey() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val tree = treeOf(alice)
        val own = tree.getLeaf(0)!!
        val twin =
            own.copy(
                encryptionKey =
                    MlsGroup
                        .createKeyPackage(ByteArray(1))
                        .keyPackage.leafNode.encryptionKey,
                leafNodeSource = com.vitorpamplona.mls.tree.LeafNodeSource.KEY_PACKAGE,
            )
        val key = alice.saveState().signingPrivateKey
        tree.addLeaf(
            twin
                .copy(
                    lifetime =
                        com.vitorpamplona.mls.tree
                            .Lifetime(0, Long.MAX_VALUE),
                    signature = ByteArray(0),
                ).let { it.copy(signature = MlsCryptoProvider.signWithLabel(key, "LeafNodeTBS", it.encodeTbs())) },
        )
        refuses("Duplicate signature key") { validate(alice, tree) }
    }

    @Test
    fun twoNodesWithOneEncryptionKey() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val tree = treeOf(alice)
        val b = MlsGroup.createKeyPackage("mallory".encodeToByteArray())
        val unsigned = b.keyPackage.leafNode.copy(encryptionKey = tree.getLeaf(0)!!.encryptionKey)
        // addLeaf itself refuses a duplicate key, so overwrite an honest leaf.
        val at = tree.addLeaf(b.keyPackage.leafNode)
        tree.setLeaf(at, unsigned.copy(signature = MlsCryptoProvider.signWithLabel(b.signaturePrivateKey, "LeafNodeTBS", unsigned.encodeTbs())))
        refuses("appears in another node") { validate(alice, tree) }
    }

    private companion object {
        const val OTHER_CREDENTIAL = 0xF0F1
    }
}
