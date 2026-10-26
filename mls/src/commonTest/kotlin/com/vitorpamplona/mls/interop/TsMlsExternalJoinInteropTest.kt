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
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.hexToByteArray
import com.vitorpamplona.mls.tree.Credential
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

/**
 * GroupInfos ts-mls published for its own two-member groups, one with the
 * ratchet_tree extension and one with the tree out of band
 * (`tools/tsmls-vector-gen/external-join.mjs`). mls-kmp must join both by
 * external commit. CI's `sending-interop` job then has ts-mls process the
 * commits; this test keeps the receiving half in every run.
 *
 * ts-mls writes external_pub as the bare key rather than the opaque<V> of
 * RFC 9420 §12.4.3.2, so this also pins that we accept that form.
 */
class TsMlsExternalJoinInteropTest {
    @Serializable
    private data class Scenario(
        val description: String,
        @SerialName("group_info") val groupInfo: String,
        @SerialName("ratchet_tree") val ratchetTree: String? = null,
        val epoch: Long,
        @SerialName("bob_leaf_index") val bobLeafIndex: Int,
        @SerialName("epoch_authenticator") val epochAuthenticator: String,
    )

    private val scenarios =
        JsonMapper.jsonInstance.decodeFromString<List<Scenario>>(TestResourceLoader().loadString("mls/tsmls-external-join.json"))

    @Test
    fun joinsTsMlsGroupsByExternalCommit() {
        assertTrue(scenarios.any { it.ratchetTree == null } && scenarios.any { it.ratchetTree != null })
        for (s in scenarios) {
            val carol =
                MlsGroup
                    .externalJoin(
                        groupInfoBytes = s.groupInfo.hexToByteArray(),
                        identity = "carol".encodeToByteArray(),
                        ratchetTree = s.ratchetTree?.hexToByteArray(),
                    ).group
            assertEquals(s.epoch + 1, carol.epoch, s.description)
            assertEquals(listOf("alice", "bob", "carol"), carol.members().map { (it.second.credential as Credential.Basic).identity.decodeToString() }, s.description)
            assertEquals(2, carol.leafIndex, s.description)
            // The joiner can keep going: commit bob's removal in the new epoch.
            carol.removeMember(s.bobLeafIndex)
            assertEquals(listOf(0, 2), carol.members().map { it.first }, s.description)
        }
    }

    @Test
    fun outOfBandTreeIsRequiredWhenTheGroupInfoOmitsIt() {
        val s = scenarios.first { it.ratchetTree != null }
        assertFails { MlsGroup.externalJoin(s.groupInfo.hexToByteArray(), "carol".encodeToByteArray()) }
    }
}
