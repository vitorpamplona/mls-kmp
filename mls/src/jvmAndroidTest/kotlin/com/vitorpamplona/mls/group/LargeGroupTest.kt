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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A group big enough that its ratchet tree, and so its Welcome, is several
 * megabytes. The decoder used to refuse any field over 1 MiB, which made a
 * group of a few thousand members unjoinable; RFC 9420 sets no such limit.
 */
class LargeGroupTest {
    @Test
    fun aGroupWhoseTreeIsLargerThanOneMebibyteStillWorks() {
        val members = 6_000
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val factory = MlsGroup.create("factory".encodeToByteArray())
        val bundles = (0 until members).map { factory.createKeyPackage("member-$it".encodeToByteArray(), ByteArray(0)) }

        val add = alice.addMembers(bundles.map { it.keyPackage.toTlsBytes() })
        assertTrue(alice.exportTreeBytes().size > 1 shl 20, "the tree should be over 1 MiB, was ${alice.exportTreeBytes().size}")
        assertTrue(add.welcomeBytes!!.size > 1 shl 20, "the Welcome should be over 1 MiB, was ${add.welcomeBytes!!.size}")

        val last = MlsGroup.processWelcome(add.welcomeBytes!!, bundles.last())
        assertEquals(members + 1, last.memberCount)
        assertContentEquals(alice.epochAuthenticator, last.epochAuthenticator)

        // A commit from a new member encrypts to thousands of unmerged leaves.
        val commit = last.commit()
        alice.processFramedCommit(commit.framedCommitBytes)
        assertContentEquals(alice.epochAuthenticator, last.epochAuthenticator)

        val big = ByteArray(3 shl 20) { it.toByte() }
        assertContentEquals(big, alice.decrypt(last.encrypt(big)).content, "a 3 MiB application message round-trips")
    }
}
