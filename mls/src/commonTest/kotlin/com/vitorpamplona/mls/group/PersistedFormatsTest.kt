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

import com.vitorpamplona.mls.JsonMapper
import com.vitorpamplona.mls.TestResourceLoader
import com.vitorpamplona.mls.hexToByteArray
import com.vitorpamplona.mls.messages.KeyPackageBundleCodec
import com.vitorpamplona.mls.toHexKey
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Persisted formats are API: every device that saved a group or a KeyPackage
 * bundle must still restore it after an upgrade. `persisted-formats.json`
 * holds one frozen saved state per MlsGroupState layout (v1 to v10) and a
 * KeyPackageBundleCodec v1 bundle; each must restore and keep working —
 * read a message, apply a commit, open a Welcome. New versions are added by
 * `PersistedFormatFixtureWriter`; existing entries never change.
 */
class PersistedFormatsTest {
    @Serializable
    private class Fixtures(
        val states: Map<String, String>,
        @SerialName("epoch_authenticator") val epochAuthenticator: String,
        @SerialName("bob_message") val bobMessage: String,
        val plaintext: String,
        @SerialName("bob_commit") val bobCommit: String,
        @SerialName("authenticator_after_commit") val authenticatorAfterCommit: String,
        @SerialName("bundle_v1") val bundleV1: String,
        val welcome: String,
        @SerialName("welcome_authenticator") val welcomeAuthenticator: String,
    )

    private val f = JsonMapper.jsonInstance.decodeFromString<Fixtures>(TestResourceLoader().loadString("mls/persisted-formats.json"))

    @Test
    fun everyStateLayoutStillRestoresAndWorks() {
        assertEquals((1..10).map { it.toString() }.toSet(), f.states.keys, "a fixture per layout")
        for ((version, hex) in f.states) {
            val alice = MlsGroup.restore(MlsGroupState.decodeTls(hex.hexToByteArray()))
            assertEquals(f.epochAuthenticator, alice.epochAuthenticator.toHexKey(), "v$version: epoch")
            val read = assertIs<ProcessedMessage.Application>(alice.processMessage(f.bobMessage.hexToByteArray()), "v$version")
            assertEquals(f.plaintext, read.message.content.decodeToString(), "v$version: message")
            alice.processMessage(f.bobCommit.hexToByteArray())
            assertEquals(f.authenticatorAfterCommit, alice.epochAuthenticator.toHexKey(), "v$version: after the commit")
            assertTrue(alice.isLocalMember(), "v$version")
        }
    }

    @Test
    fun theCurrentLayoutRoundTripsTheNewestFixture() {
        val newest = f.states.getValue("10").hexToByteArray()
        assertEquals(newest.toHexKey(), MlsGroupState.decodeTls(newest).encodeTls().toHexKey(), "decode then encode changed the bytes")
    }

    @Test
    fun aVersion1KeyPackageBundleStillOpensItsWelcome() {
        val bundle = KeyPackageBundleCodec.decode(f.bundleV1.hexToByteArray())
        val joined = MlsGroup.processWelcome(f.welcome.hexToByteArray(), bundle)
        assertEquals(f.welcomeAuthenticator, joined.epochAuthenticator.toHexKey())
    }
}
