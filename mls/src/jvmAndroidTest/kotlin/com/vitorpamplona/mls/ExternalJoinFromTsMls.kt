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
package com.vitorpamplona.mls

import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * mls-kmp joins groups ts-mls created, by external commit from the GroupInfo
 * ts-mls published, then keeps talking to them:
 *
 *   node tools/tsmls-vector-gen/external-join.mjs fixture /tmp/extjoin-fixture.json
 *   MLSKMP_EXTJOIN_FIXTURE=/tmp/extjoin-fixture.json MLSKMP_EXTJOIN_RESULT=/tmp/extjoin-result.json \
 *     ./gradlew :mls:jvmTest --tests com.vitorpamplona.mls.ExternalJoinFromTsMls
 *   node tools/tsmls-vector-gen/external-join.mjs verify /tmp/extjoin-fixture.json /tmp/extjoin-result.json
 *
 * Does nothing without the variables.
 */
class ExternalJoinFromTsMls {
    @Serializable
    private data class Scenario(
        val description: String,
        @SerialName("group_info") val groupInfo: String,
        @SerialName("ratchet_tree") val ratchetTree: String? = null,
        val epoch: Long,
        @SerialName("bob_leaf_index") val bobLeafIndex: Int,
    )

    @Serializable
    private data class Result(
        @SerialName("external_commit") val externalCommit: String,
        @SerialName("epoch_authenticator_after_join") val epochAuthenticatorAfterJoin: String,
        @SerialName("application_message") val applicationMessage: String,
        @SerialName("application_plaintext") val applicationPlaintext: String,
        @SerialName("remove_commit") val removeCommit: String,
        @SerialName("epoch_authenticator_after_remove") val epochAuthenticatorAfterRemove: String,
        @SerialName("second_application_message") val secondApplicationMessage: String,
        @SerialName("second_application_plaintext") val secondApplicationPlaintext: String,
    )

    @Test
    fun joinTsMlsGroups() {
        val fixturePath = System.getenv("MLSKMP_EXTJOIN_FIXTURE") ?: return
        val resultPath = System.getenv("MLSKMP_EXTJOIN_RESULT") ?: return
        val json = Json(from = JsonMapper.jsonInstance) { ignoreUnknownKeys = true }
        val scenarios = json.decodeFromString(ListSerializer(Scenario.serializer()), File(fixturePath).readText())
        val results = scenarios.map(::join)
        File(resultPath).writeText(json.encodeToString(ListSerializer(Result.serializer()), results))
    }

    private fun join(s: Scenario): Result {
        val joined =
            MlsGroup.externalJoin(
                groupInfoBytes = s.groupInfo.hexToByteArray(),
                identity = "carol".encodeToByteArray(),
                ratchetTree = s.ratchetTree?.hexToByteArray(),
            )
        val carol = joined.group
        assertEquals(s.epoch + 1, carol.epoch, s.description)
        assertEquals(3, carol.members().size, s.description)
        val afterJoin = carol.epochAuthenticator

        val hello = "hello from mls-kmp, joined by external commit".encodeToByteArray()
        val message = carol.encrypt(hello)

        carol.proposeRemove(s.bobLeafIndex)
        val remove = carol.commit(wireFormat = WireFormat.PRIVATE_MESSAGE)
        assertEquals(2, carol.members().size, s.description)
        assertContentEquals(listOf(0, 2), carol.members().map { it.first }, s.description)

        val bye = "bob is out; alice and carol carry on".encodeToByteArray()
        val second = carol.encrypt(bye)
        return Result(
            externalCommit = joined.framedCommitBytes.toHexKey(),
            epochAuthenticatorAfterJoin = afterJoin.toHexKey(),
            applicationMessage = message.toHexKey(),
            applicationPlaintext = hello.toHexKey(),
            removeCommit = remove.framedCommitBytes.toHexKey(),
            epochAuthenticatorAfterRemove = carol.epochAuthenticator.toHexKey(),
            secondApplicationMessage = second.toHexKey(),
            secondApplicationPlaintext = bye.toHexKey(),
        )
    }
}
