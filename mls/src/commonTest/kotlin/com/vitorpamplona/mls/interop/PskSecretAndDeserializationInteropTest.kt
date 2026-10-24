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
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.hexToByteArray
import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.schedule.KeySchedule
import com.vitorpamplona.mls.toHexKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The `psk_secret` and `deserialization` vectors from
 * github.com/mlswg/mls-implementations: the RFC 9420 §8.4 PSK chain and the
 * §2.1.2 variable-length integer header.
 */
class PskSecretAndDeserializationInteropTest {
    @Test
    fun testPskSecret() {
        val vectors =
            JsonMapper.jsonInstance
                .decodeFromString<List<PskSecretVector>>(TestResourceLoader().loadString("mls/psk-secret.json"))
                .filter { it.cipherSuite == 1 }
        assertTrue(vectors.isNotEmpty(), "No cipher_suite==1 psk_secret vectors")
        for ((idx, v) in vectors.withIndex()) {
            val psks = v.psks.map { PreSharedKeyId.External(it.pskId.hexToByteArray(), it.pskNonce.hexToByteArray()) to it.psk.hexToByteArray() }
            assertEquals(v.pskSecret, KeySchedule.pskSecret(psks).toHexKey(), "psk_secret mismatch at vector $idx (${v.psks.size} PSKs)")
        }
    }

    @Test
    fun testVarIntHeaders() {
        val vectors =
            JsonMapper.jsonInstance.decodeFromString<List<DeserializationVector>>(TestResourceLoader().loadString("mls/deserialization.json"))
        assertTrue(vectors.isNotEmpty())
        for (v in vectors) {
            val header = v.vlbytesHeader.hexToByteArray()
            assertEquals(v.length, TlsReader(header).readVarInt(), "length for header ${v.vlbytesHeader}")
            // Our encoder writes the same, minimal header.
            val w = TlsWriter()
            w.putVarInt(v.length)
            assertEquals(v.vlbytesHeader, w.toByteArray().toHexKey(), "header for length ${v.length}")
        }
    }

    /** RFC 9420 §2.1.2: a varint using more bytes than needed is malformed. */
    @Test
    fun testNonMinimalVarIntIsRejected() {
        assertFailsWith<IllegalArgumentException> { TlsReader(byteArrayOf(0x40, 0x25)).readVarInt() }
        assertFailsWith<IllegalArgumentException> { TlsReader(byteArrayOf(0x80.toByte(), 0x00, 0x00, 0x25)).readVarInt() }
    }
}
