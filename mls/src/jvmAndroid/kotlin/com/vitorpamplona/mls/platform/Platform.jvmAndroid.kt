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

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal actual fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

internal actual class MacInstance actual constructor(
    algorithm: String,
    key: ByteArray,
) {
    private val mac: Mac =
        Mac.getInstance(algorithm).apply {
            init(RawMacKey(key, algorithm))
        }

    actual fun update(array: ByteArray) = mac.update(array)

    actual fun update(byte: Byte) = mac.update(byte)

    actual fun doFinal(): ByteArray = mac.doFinal()
}

/**
 * [SecretKeySpec] rejects an empty key, but HKDF-Extract with an empty salt (and
 * the all-zero secrets of the MLS key schedule) must HMAC with one: RFC 2104
 * zero-pads it like any short key.
 */
private class RawMacKey(
    private val key: ByteArray,
    private val algo: String,
) : SecretKey {
    override fun getAlgorithm() = algo

    override fun getEncoded() = key.copyOf()

    override fun getFormat() = "RAW"
}

internal actual class AESGCM actual constructor(
    private val keyBytes: ByteArray,
    private val nonce: ByteArray,
) {
    private fun cipher(mode: Int) =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, nonce))
        }

    actual fun encrypt(
        bytesToEncrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray =
        with(cipher(Cipher.ENCRYPT_MODE)) {
            updateAAD(aad)
            doFinal(bytesToEncrypt)
        }

    actual fun decrypt(
        bytesToDecrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray =
        with(cipher(Cipher.DECRYPT_MODE)) {
            updateAAD(aad)
            doFinal(bytesToDecrypt)
        }
}

private val secureRandom = SecureRandom()

internal actual fun secureRandomBytes(output: ByteArray) = secureRandom.nextBytes(output)
