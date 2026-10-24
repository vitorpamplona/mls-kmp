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
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.hexToByteArray
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.platform.Hex
import com.vitorpamplona.mls.toHexKey
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The RFC 9420 passive-client test vectors from
 * github.com/mlswg/mls-implementations, run end to end through [MlsGroup].
 *
 * Each vector hands a client its KeyPackage and private keys and a Welcome
 * from another implementation (OpenMLS, mls-rs, …). The client joins, then
 * processes every epoch's standalone proposals and commit exactly as it
 * would receive them, and must reach the same epoch authenticator as the
 * implementation that generated the vector after every single one.
 *
 * - `passive-client-welcome`: joining, with and without an inline ratchet
 *   tree, with and without PSKs.
 * - `passive-client-handling-commit`: one commit of every shape — each
 *   proposal type inline and by reference, with and without a path, external
 *   commits, PSKs.
 * - `passive-client-random`: a long random run of adds, removes and updates.
 */
class PassiveClientInteropTest {
    private fun load(name: String): List<PassiveClientVector> =
        JsonMapper.jsonInstance
            .decodeFromString<List<PassiveClientVector>>(TestResourceLoader().loadString("mls/$name.json"))
            .filter { it.cipherSuite == 1 }

    /** Runs one vector; returns null when it passes, or what went wrong. */
    private fun run(v: PassiveClientVector): String? {
        val kpMsg = MlsMessage.decodeTls(TlsReader(v.keyPackage.hexToByteArray()))
        check(kpMsg.wireFormat == WireFormat.KEY_PACKAGE)
        val kp = MlsKeyPackage.decodeTls(TlsReader(kpMsg.payload))
        val bundle =
            KeyPackageBundle(
                keyPackage = kp,
                initPrivateKey = v.initPriv.hexToByteArray(),
                encryptionPrivateKey = v.encryptionPriv.hexToByteArray(),
                signaturePrivateKey = v.signaturePriv.hexToByteArray() + kp.leafNode.signatureKey,
            )
        val externalPsks = v.externalPsks.associate { it.pskId.lowercase() to it.psk.hexToByteArray() }

        val group =
            try {
                MlsGroup.processWelcome(
                    welcomeBytes = v.welcome.hexToByteArray(),
                    bundle = bundle,
                    ratchetTree = v.ratchetTree?.hexToByteArray(),
                    psks = { id -> (id as? PreSharedKeyId.External)?.let { externalPsks[Hex.encode(it.pskId)] } },
                )
            } catch (t: Throwable) {
                return "welcome: ${t::class.simpleName}: ${t.message}"
            }
        for (p in v.externalPsks) group.registerPsk(p.pskId.hexToByteArray(), p.psk.hexToByteArray())

        if (group.epochAuthenticator.toHexKey() != v.initialEpochAuthenticator) return "initial epoch_authenticator mismatch"

        for ((i, epoch) in v.epochs.withIndex()) {
            try {
                for (proposal in epoch.proposals) group.processMessage(proposal.hexToByteArray())
                group.processMessage(epoch.commit.hexToByteArray())
            } catch (t: Throwable) {
                return "epoch $i of ${v.epochs.size}: ${t::class.simpleName}: ${t.message}"
            }
            if (group.epochAuthenticator.toHexKey() != epoch.epochAuthenticator) return "epoch $i of ${v.epochs.size}: epoch_authenticator mismatch"
        }
        return null
    }

    private fun runAll(name: String) {
        val vectors = load(name)
        assertTrue(vectors.isNotEmpty(), "No cipher_suite==1 $name vectors")
        val failures = vectors.withIndex().mapNotNull { (i, v) -> run(v)?.let { "$name[$i]: $it" } }
        assertTrue(failures.isEmpty(), "${failures.size} of ${vectors.size} vectors failed:\n" + failures.joinToString("\n"))
    }

    @Test
    fun passiveClientWelcome() = runAll("passive-client-welcome")

    @Test
    fun passiveClientHandlingCommit() = runAll("passive-client-handling-commit")

    @Test
    fun passiveClientRandom() = runAll("passive-client-random")
}
