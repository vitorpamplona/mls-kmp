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
package com.vitorpamplona.mls.fuzz

import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupState
import com.vitorpamplona.mls.group.PublicGroup
import com.vitorpamplona.mls.testEnv
import com.vitorpamplona.mls.toHexKey
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Error messages end up in logs and crash reports. None may carry key
 * material: this collects every secret the members hold, sets off a few
 * thousand failures (mutated messages, misuse of the API) and checks that no
 * exception message, cause included, contains any 8-byte run of them, in hex
 * or as a decimal array.
 */
class SecretLeakTest {
    private val seed = testEnv("MLSKMP_FUZZ_SEED")?.toLong() ?: Random.nextLong()

    private fun secretsOf(group: MlsGroup): List<ByteArray> {
        val s = group.saveState()
        val e = s.epochSecrets
        return listOf(
            e.joinerSecret,
            e.welcomeSecret,
            e.epochSecret,
            e.senderDataSecret,
            e.encryptionSecret,
            e.exporterSecret,
            e.externalSecret,
            e.confirmationKey,
            e.membershipKey,
            e.resumptionPsk,
            e.initSecret,
            s.initSecret,
            s.signingPrivateKey,
            s.encryptionPrivateKey,
        ) + s.pathPrivateKeys.values
    }

    private fun needles(secret: ByteArray): List<String> {
        if (secret.size < 8) return emptyList()
        val hex = secret.toHexKey()
        val head = secret.copyOf(8)
        return listOf(hex.substring(0, 16), hex.substring(0, 16).uppercase(), head.joinToString(", "))
    }

    private fun messagesOf(t: Throwable): List<String> = generateSequence(t) { it.cause }.mapNotNull { it.message }.toList()

    @Test
    fun noExceptionMessageCarriesKeyMaterial() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = MlsGroup.createKeyPackage("bob".encodeToByteArray())
        val c = MlsGroup.createKeyPackage("carol".encodeToByteArray())
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        val bob = MlsGroup.processWelcome(add.welcomeBytes!!, b)
        val carol = MlsGroup.processWelcome(add.welcomeBytes!!, c)
        val secrets = listOf(alice, bob, carol).flatMap { secretsOf(it) } + listOf(b.initPrivateKey, b.encryptionPrivateKey, b.signaturePrivateKey)
        val forbidden = secrets.flatMap { needles(it) }.toSet()

        val corpus =
            listOf(
                alice.encrypt("secret talk".encodeToByteArray()),
                alice.proposalMessage(alice.proposeSigningKeyRotation(), WireFormat.PRIVATE_MESSAGE),
                alice.stageCommit(wireFormat = WireFormat.PRIVATE_MESSAGE).framedCommitBytes.also { alice.clearPendingCommit() },
                alice.stageCommit().framedCommitBytes.also { alice.clearPendingCommit() },
                alice.groupInfoMessage(),
                add.welcomeBytes!!,
            )
        val messages = mutableListOf<String>()

        fun attempt(block: () -> Unit) {
            try {
                block()
            } catch (t: Throwable) {
                messages += messagesOf(t)
            }
        }

        val mutator = Mutator(Random(seed))
        repeat(1500) { i ->
            val mutated = mutator.mutate(corpus[i % corpus.size], corpus)
            attempt { bob.processMessage(mutated) }
            attempt { bob.decryptFormerEpoch(mutated) }
            attempt { MlsGroup.processWelcome(mutated, b) }
            attempt { PublicGroup.fromGroupInfo(mutated) }
            attempt { MlsGroup.restore(MlsGroupState.decodeTls(mutated)) }
        }
        // Misuse: the wrong bundle, the wrong group, a replay, an old epoch.
        attempt { MlsGroup.processWelcome(add.welcomeBytes!!, MlsGroup.createKeyPackage("mallory".encodeToByteArray())) }
        attempt { MlsGroup.create("other".encodeToByteArray()).processMessage(corpus[0]) }
        attempt { bob.processMessage(corpus[0]).also { bob.processMessage(corpus[0]) } }
        attempt { carol.decryptFormerEpoch(corpus[0]) }

        assertTrue(messages.size > 1000, "only ${messages.size} failures were provoked")
        val leaks = messages.filter { m -> forbidden.any { m.contains(it) } }
        assertTrue(leaks.isEmpty(), "Exception messages carry key material (seed $seed):\n" + leaks.take(10).joinToString("\n"))
    }
}
