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

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.PublicMessage
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupState
import com.vitorpamplona.mls.group.PublicGroup
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.testEnv
import com.vitorpamplona.mls.toHexKey
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Mutation fuzzing of every entry point that reads bytes from the network
 * (and of the local stores, which a damaged disk can corrupt).
 *
 * Valid messages of every kind are mutated (bit flips, boundary bytes,
 * truncation, inflated lengths, splices) and fed to their entry point. The
 * engine may only throw [IllegalArgumentException] or [IllegalStateException]
 * — never a crash, an index or arithmetic error, an OOM or a hang — and a
 * group that rejects a message is exactly as it was. A mutated proposal,
 * commit or application message is never accepted: everything in one is
 * signed, MACed or encrypted.
 *
 * Runs a short pass in every build with a fresh seed. `MLSKMP_FUZZ_SEED`
 * replays a run, `MLSKMP_FUZZ_ITERATIONS` lengthens it (the nightly job).
 */
class MessageFuzzTest {
    private val seed = testEnv("MLSKMP_FUZZ_SEED")?.toLong() ?: Random.nextLong()
    private val iterations = testEnv("MLSKMP_FUZZ_ITERATIONS")?.toInt() ?: 120
    private val random = Random(seed)
    private val mutator = Mutator(random)
    private val failures = mutableListOf<String>()

    private fun bundle(name: String) = MlsGroup.createKeyPackage(name.encodeToByteArray())

    private class Corpus(
        val bob: MlsGroup,
        val view: PublicGroup,
        val handshake: List<ByteArray>,
        val application: List<ByteArray>,
        val welcome: ByteArray,
        val welcomeNoTree: ByteArray,
        val tree: ByteArray,
        val welcomeBundle: KeyPackageBundle,
        val treelessBundle: KeyPackageBundle,
        val groupInfo: ByteArray,
        val keyPackage: ByteArray,
        val state: ByteArray,
        val bundleBytes: ByteArray,
    ) {
        val all get() = handshake + application + listOf(welcome, welcomeNoTree, tree, groupInfo, keyPackage)
    }

    /** alice, bob and carol at epoch 1, and one valid message of every kind from alice that bob has not seen. */
    private fun corpus(): Corpus {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = bundle("bob")
        val c = bundle("carol")
        val add = alice.addMembers(listOf(b.keyPackage.toTlsBytes(), c.keyPackage.toTlsBytes()))
        val bob = MlsGroup.processWelcome(add.welcomeBytes!!, b)
        val view = PublicGroup.fromGroupInfo(alice.groupInfoMessage())

        val handshake = mutableListOf<ByteArray>()
        handshake += alice.proposalMessage(alice.proposeSigningKeyRotation(), WireFormat.PUBLIC_MESSAGE)
        handshake += alice.proposalMessage(alice.proposeSigningKeyRotation(), WireFormat.PRIVATE_MESSAGE)
        // Commits are staged, never merged, so bob is still where they apply.
        handshake += alice.stageCommit(wireFormat = WireFormat.PUBLIC_MESSAGE).framedCommitBytes.also { alice.clearPendingCommit() }
        handshake += alice.stageCommit(wireFormat = WireFormat.PRIVATE_MESSAGE).framedCommitBytes.also { alice.clearPendingCommit() }
        handshake += MlsGroup.externalJoin(alice.groupInfoMessage(), "zara".encodeToByteArray()).framedCommitBytes

        val application = listOf(alice.encrypt("hello".encodeToByteArray()), alice.encrypt(ByteArray(300) { it.toByte() }, "aad".encodeToByteArray(), 32))

        // Welcomes from a separate group, so nothing above moves.
        val other = MlsGroup.create("olga".encodeToByteArray())
        val d = bundle("dave")
        val e = bundle("erin")
        val welcome = other.addMembers(listOf(d.keyPackage.toTlsBytes(), e.keyPackage.toTlsBytes())).welcomeBytes!!
        val f = bundle("fred")
        other.proposeAdd(f.keyPackage.toTlsBytes())
        val noTree = other.commit(includeRatchetTreeInWelcome = false).welcomeBytes!!

        return Corpus(
            bob = bob,
            view = view,
            handshake = handshake,
            application = application,
            welcome = welcome,
            welcomeNoTree = noTree,
            tree = other.exportTreeBytes(),
            welcomeBundle = d,
            treelessBundle = f,
            groupInfo = alice.groupInfoMessage(),
            keyPackage = bundle("gina").keyPackage.toTlsBytes(),
            state = bob.saveState().encodeTls(),
            bundleBytes = d.encodeTls(),
        )
    }

    /** Runs [block] on a mutation of each of [inputs]; [mayAccept] says whether a mutated input may legitimately succeed. */
    private fun fuzz(
        target: String,
        inputs: List<ByteArray>,
        corpus: Corpus,
        mayAccept: Boolean,
        fingerprint: () -> String = { "" },
        acceptable: (ByteArray) -> Boolean = { mayAccept },
        block: (ByteArray) -> Unit,
    ) {
        val known = corpus.all
        repeat(iterations) { i ->
            val original = inputs[i % inputs.size]
            val mutated = mutator.mutate(original, known)
            if (known.any { it.contentEquals(mutated) }) return@repeat
            val before = fingerprint()
            val start = TimeSource.Monotonic.markNow()
            val outcome =
                try {
                    block(mutated)
                    null
                } catch (e: IllegalArgumentException) {
                    e
                } catch (e: IllegalStateException) {
                    e
                } catch (t: Throwable) {
                    failures += "$target #$i: ${t::class.simpleName}: ${t.message} on ${mutated.toHexKey().take(400)}"
                    return@repeat
                }
            val took = start.elapsedNow()
            if (took > 5.seconds) failures += "$target #$i: took $took on ${mutated.toHexKey().take(400)}"
            if (outcome == null && !acceptable(mutated)) failures += "$target #$i: a mutated message was ACCEPTED: ${mutated.toHexKey().take(400)}"
            if (outcome != null && fingerprint() != before) failures += "$target #$i: rejected (${outcome.message}) but the state changed"
        }
    }

    private fun sameButTags(
        original: ByteArray,
        mutated: ByteArray,
    ): Boolean {
        fun parse(b: ByteArray) =
            runCatching {
                val m = MlsMessage.decodeTls(TlsReader(b))
                if (m.wireFormat == WireFormat.PUBLIC_MESSAGE) PublicMessage.decodeTls(TlsReader(m.payload)) else null
            }.getOrNull()
        val a = parse(original) ?: return false
        val b = parse(mutated) ?: return false

        fun strip(m: PublicMessage) = m.copy(membershipTag = null, confirmationTag = m.confirmationTag?.let { ByteArray(it.size) }).toTlsBytes()
        return strip(a).contentEquals(strip(b))
    }

    private fun MlsGroup.fingerprint() = epochAuthenticator.toHexKey() + exportTreeBytes().toHexKey() + pendingProposalsSnapshot().size

    private fun PublicGroup.fingerprint() = saveState().encodeTls().toHexKey()

    @Test
    fun everyEntryPointSurvivesMutatedInput() {
        val c = corpus()
        var bob = c.bob
        var view = c.view

        fuzz("MlsGroup.processMessage(handshake)", c.handshake, c, mayAccept = false, { bob.fingerprint() }) { bytes ->
            try {
                bob.processMessage(bytes)
            } finally {
                // An accepted message (reported above) would move bob; start the next one fresh.
                if (bob.fingerprint() != MlsGroup.restore(MlsGroupState.decodeTls(c.state)).fingerprint()) bob = MlsGroup.restore(MlsGroupState.decodeTls(c.state))
            }
        }
        fuzz("MlsGroup.processMessage(application)", c.application, c, mayAccept = false, { bob.fingerprint() }) { bob.processMessage(it) }
        fuzz("MlsGroup.decryptFormerEpoch", c.application, c, mayAccept = false) { bob.decryptFormerEpoch(it) }
        // The view holds no epoch secrets, so a PublicMessage that differs from an
        // original only in its membership or confirmation tag passes it (the
        // documented limit of PublicGroup).
        fuzz("PublicGroup.processMessage", c.handshake, c, mayAccept = false, { view.fingerprint() }, { c.handshake.any { o -> sameButTags(o, it) } }) { bytes ->
            try {
                view.processMessage(bytes)
            } finally {
                if (view.epoch != c.view.epoch) view = PublicGroup.fromGroupInfo(c.groupInfo)
            }
        }
        fuzz("MlsGroup.processWelcome", listOf(c.welcome), c, mayAccept = true) { MlsGroup.processWelcome(it, c.welcomeBundle) }
        fuzz("MlsGroup.processWelcome(ratchetTree)", listOf(c.tree), c, mayAccept = true) { MlsGroup.processWelcome(c.welcomeNoTree, c.treelessBundle, ratchetTree = it) }
        fuzz("MlsGroup.externalJoin", listOf(c.groupInfo), c, mayAccept = true) { MlsGroup.externalJoin(it, "yuri".encodeToByteArray()) }
        fuzz("PublicGroup.fromGroupInfo", listOf(c.groupInfo), c, mayAccept = true) { PublicGroup.fromGroupInfo(it) }
        val adder = MlsGroup.create("ivan".encodeToByteArray())
        fuzz("MlsGroup.proposeAdd(KeyPackage)", listOf(c.keyPackage), c, mayAccept = true) { adder.proposeAdd(it) }
        fuzz("MlsMessage.decodeTls", c.all, c, mayAccept = true) { MlsMessage.decodeTls(TlsReader(it)) }
        fuzz("MlsGroupState.decodeTls + restore", listOf(c.state), c, mayAccept = true) { MlsGroup.restore(MlsGroupState.decodeTls(it)) }
        fuzz("KeyPackageBundle.decodeTls", listOf(c.bundleBytes), c, mayAccept = true) { KeyPackageBundle.decodeTls(it) }

        if (failures.isNotEmpty()) {
            fail("${failures.size} fuzz failures (replay with MLSKMP_FUZZ_SEED=$seed):\n" + failures.take(20).joinToString("\n"))
        }
    }
}
