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

/*
 * The few primitives the engine needs from the platform. They used to come from
 * Quartz's utils; they are internal here so this library depends on nothing Nostr.
 * Ciphersuite 0x0001 only needs SHA-256, HMAC-SHA256, AES-128-GCM and a CSPRNG
 * (Ed25519/X25519 and their SHA-512 are pure Kotlin in `crypto/`).
 */

/** SHA-256 of [data]. */
internal expect fun sha256(data: ByteArray): ByteArray

/** Incremental HMAC. Only `HmacSHA256` is supported. */
internal expect class MacInstance(
    algorithm: String,
    key: ByteArray,
) {
    fun update(array: ByteArray)

    fun update(byte: Byte)

    fun doFinal(): ByteArray
}

/** AES-GCM with a 128-bit tag; the key size picks AES-128 or AES-256. */
internal expect class AESGCM(
    keyBytes: ByteArray,
    nonce: ByteArray,
) {
    /** Encrypts with Additional Authenticated Data; returns ciphertext || tag. */
    fun encrypt(
        bytesToEncrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray

    /** Decrypts ciphertext || tag; throws when the tag does not verify. */
    fun decrypt(
        bytesToDecrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray
}

/** Fills [output] from the platform's cryptographically secure random source. */
internal expect fun secureRandomBytes(output: ByteArray)

internal object RandomInstance {
    /** [size] secure random bytes, for keys, nonces and secrets. */
    fun bytes(size: Int): ByteArray = ByteArray(size).also { secureRandomBytes(it) }
}
