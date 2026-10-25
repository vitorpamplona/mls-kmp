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

import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.ProcessedMessage
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The threading contract in [MlsGroup]'s documentation, under load: separate
 * groups on separate threads do not interfere (the engine keeps no shared
 * mutable state), and one group shared by many threads behind a lock stays
 * consistent — no key reused, every message read once.
 */
class ConcurrencyStressTest {
    private fun pair(): Pair<MlsGroup, MlsGroup> {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val b = MlsGroup.createKeyPackage("bob".encodeToByteArray())
        return alice to MlsGroup.processWelcome(alice.addMember(b.keyPackage.toTlsBytes()).welcomeBytes!!, b)
    }

    @Test
    fun separateGroupsOnSeparateThreadsDoNotInterfere() {
        val threads = 8
        val pool = Executors.newFixedThreadPool(threads)
        val errors = Collections.synchronizedList(mutableListOf<Throwable>())
        val start = CountDownLatch(1)
        repeat(threads) { t ->
            pool.execute {
                try {
                    start.await()
                    val (alice, bob) = pair()
                    repeat(30) { i ->
                        val commit = (if (i % 2 == 0) alice else bob).commit()
                        (if (i % 2 == 0) bob else alice).processMessage(commit.framedCommitBytes)
                        val text = "thread $t message $i"
                        assertEquals(text, bob.decrypt(alice.encrypt(text.encodeToByteArray())).content.decodeToString())
                        val restored = MlsGroup.restore(alice.saveState())
                        assertTrue(restored.epochAuthenticator.contentEquals(bob.epochAuthenticator))
                    }
                } catch (e: Throwable) {
                    errors += e
                }
            }
        }
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.MINUTES), "threads did not finish")
        assertTrue(errors.isEmpty(), "errors on ${errors.size} threads: ${errors.firstOrNull()?.stackTraceToString()}")
    }

    @Test
    fun oneGroupSharedBehindALockStaysConsistent() {
        val (alice, bob) = pair()
        val aliceLock = Any()
        val bobLock = Any()
        val threads = 8
        // 800 in all: within the default out-of-order tolerance of 1000 skipped keys.
        val perThread = 100
        val pool = Executors.newFixedThreadPool(threads)
        val sent = Collections.synchronizedList(mutableListOf<Pair<String, ByteArray>>())
        val errors = Collections.synchronizedList(mutableListOf<Throwable>())
        repeat(threads) { t ->
            pool.execute {
                try {
                    repeat(perThread) { i ->
                        val text = "t$t-$i"
                        val bytes = synchronized(aliceLock) { alice.encrypt(text.encodeToByteArray()) }
                        sent += text to bytes
                        // Readers race the writers, also behind their group's lock.
                        if (i % 3 == 0) {
                            synchronized(aliceLock) { alice.exporterSecret("x", ByteArray(0), 16) }
                        }
                    }
                } catch (e: Throwable) {
                    errors += e
                }
            }
        }
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.MINUTES))
        assertTrue(errors.isEmpty(), "errors: ${errors.firstOrNull()?.stackTraceToString()}")
        assertEquals(threads * perThread, sent.size)

        // Every message reads back exactly once, from many threads, whatever the order.
        val readers = Executors.newFixedThreadPool(threads)
        val read = Collections.synchronizedList(mutableListOf<String>())
        for ((_, bytes) in sent.shuffled()) {
            readers.execute {
                try {
                    val result = synchronized(bobLock) { bob.processMessage(bytes) }
                    read += (result as ProcessedMessage.Application).message.content.decodeToString()
                } catch (e: Throwable) {
                    errors += e
                }
            }
        }
        readers.shutdown()
        assertTrue(readers.awaitTermination(5, TimeUnit.MINUTES))
        assertTrue(errors.isEmpty(), "errors: ${errors.firstOrNull()?.stackTraceToString()}")
        assertEquals(sent.map { it.first }.sorted(), read.sorted())
        // No two messages were sealed under the same generation.
        assertEquals(sent.size, sent.map { it.second.toHexKey() }.toSet().size)
    }
}
