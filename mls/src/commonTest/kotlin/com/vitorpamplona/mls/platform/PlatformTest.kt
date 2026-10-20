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
package com.vitorpamplona.mls.platform

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse

/**
 * The engine's platform primitives (JCA, CommonCrypto or pure Kotlin, depending on the
 * target) held to the same known answers everywhere.
 */
class PlatformTest {
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.unhex() = ByteArray(length / 2) { substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun hmac(
        key: ByteArray,
        message: ByteArray,
    ): String {
        val mac = MacInstance("HmacSHA256", key)
        mac.update(message)
        return mac.doFinal().hex()
    }

    @Test
    fun sha256KnownAnswers() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256(ByteArray(0)).hex())
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha256("abc".encodeToByteArray()).hex())
    }

    @Test
    fun sha512KnownAnswers() {
        assertEquals(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            sha512("abc".encodeToByteArray()).hex(),
        )
    }

    @Test
    fun hmacRfc4231() {
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            hmac(ByteArray(20) { 0x0b }, "Hi There".encodeToByteArray()),
        )
        // Fed byte by byte, the way the HKDF counter goes in.
        val mac = MacInstance("HmacSHA256", "Jefe".encodeToByteArray())
        "what do ya want for nothing?".encodeToByteArray().forEach { mac.update(it) }
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", mac.doFinal().hex())
    }

    @Test
    fun hmacWithAnEmptyKey() {
        // HKDF-Extract with an empty salt, which the key schedule does.
        assertEquals("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", hmac(ByteArray(0), ByteArray(0)))
    }

    @Test
    fun aesGcmNistCases() {
        // NIST GCM test cases 1 and 2: AES-128, zero key and 96-bit zero IV.
        val gcm = AESGCM(ByteArray(16), ByteArray(12))
        assertEquals("58e2fccefa7e3061367f1d57a4e7455a", gcm.encrypt(ByteArray(0), ByteArray(0)).hex())
        val sealed = gcm.encrypt(ByteArray(16), ByteArray(0))
        assertEquals("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf", sealed.hex())
        assertContentEquals(ByteArray(16), gcm.decrypt(sealed, ByteArray(0)))

        val tampered = sealed.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFails { gcm.decrypt(tampered, ByteArray(0)) }
        assertFails { gcm.decrypt(sealed, "aad".encodeToByteArray()) }
    }

    @Test
    fun randomBytesAreFilled() {
        val a = RandomInstance.bytes(32)
        val b = RandomInstance.bytes(32)
        assertEquals(32, a.size)
        assertFalse(a.contentEquals(b))
        assertFalse(a.all { it == 0.toByte() })
        assertEquals(0, RandomInstance.bytes(0).size)
    }
}
