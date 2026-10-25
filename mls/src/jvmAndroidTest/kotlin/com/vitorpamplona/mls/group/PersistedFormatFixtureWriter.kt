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

import com.vitorpamplona.mls.messages.KeyPackageBundleCodec
import com.vitorpamplona.mls.toHexKey
import java.io.File
import kotlin.test.Test

/**
 * Writes `mls/persisted-formats.json`, the frozen fixtures
 * `PersistedFormatsTest` restores in every build. Run only to add a format
 * version (then commit the new file); the old entries must never change:
 *
 *   MLSKMP_WRITE_PERSISTED_FIXTURES=mls/src/commonTest/resources/mls/persisted-formats.json \
 *     ./gradlew :mls:jvmTest --rerun --tests com.vitorpamplona.mls.group.PersistedFormatFixtureWriter
 */
class PersistedFormatFixtureWriter {
    @Test
    fun write() {
        val out = System.getenv("MLSKMP_WRITE_PERSISTED_FIXTURES") ?: return
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = MlsGroup.createKeyPackage("bob".encodeToByteArray())
        val c = MlsGroup.createKeyPackage("carol".encodeToByteArray())
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        val bob = MlsGroup.processWelcome(add.welcomeBytes!!, b)
        val carol = MlsGroup.processWelcome(add.welcomeBytes!!, c)
        alice.processMessage(carol.encrypt("warming the ratchet".encodeToByteArray()))
        // A proposal waiting in alice's pool, so the v4+ layouts carry one.
        alice.processMessage(carol.proposalMessage(carol.proposeSigningKeyRotation()))

        val states = (1..10).associate { it.toString() to alice.saveState().encodeTls(it).toHexKey() }
        val message = bob.encrypt("still readable".encodeToByteArray())
        val commit = bob.commit()

        val olga = MlsGroup.create("olga".encodeToByteArray())
        val dave = MlsGroup.createKeyPackage("dave".encodeToByteArray())
        val welcome = olga.addMember(dave.keyPackage.toTlsBytes()).welcomeBytes!!

        val json =
            buildString {
                append("{\n  \"states\": {\n")
                append(states.entries.joinToString(",\n") { (v, hex) -> "    \"$v\": \"$hex\"" })
                append("\n  },\n")
                append("  \"epoch_authenticator\": \"${alice.epochAuthenticator.toHexKey()}\",\n")
                append("  \"bob_message\": \"${message.toHexKey()}\",\n")
                append("  \"plaintext\": \"still readable\",\n")
                append("  \"bob_commit\": \"${commit.framedCommitBytes.toHexKey()}\",\n")
                append("  \"authenticator_after_commit\": \"${bob.epochAuthenticator.toHexKey()}\",\n")
                append("  \"bundle_v1\": \"${KeyPackageBundleCodec.encode(dave).toHexKey()}\",\n")
                append("  \"welcome\": \"${welcome.toHexKey()}\",\n")
                append("  \"welcome_authenticator\": \"${olga.epochAuthenticator.toHexKey()}\"\n")
                append("}\n")
            }
        File(out).writeText(json)
    }
}
