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

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.random.CryptographyRandom
import io.github.andreypfau.kotlinx.crypto.HMac
import io.github.andreypfau.kotlinx.crypto.Sha256

internal actual fun sha256(data: ByteArray): ByteArray = Sha256().apply { update(data) }.digest()

internal actual class MacInstance actual constructor(
    algorithm: String,
    key: ByteArray,
) {
    private val hmac =
        when (algorithm) {
            "HmacSHA256" -> HMac(Sha256(), key)
            else -> error("Algorithm $algorithm is not supported.")
        }

    actual fun update(array: ByteArray) {
        hmac.update(array)
    }

    actual fun update(byte: Byte) {
        hmac.update(byte)
    }

    actual fun doFinal(): ByteArray = hmac.digest()
}

private val aesGcm = CryptographyProvider.Default.get(AES.GCM)

@OptIn(DelicateCryptographyApi::class)
internal actual class AESGCM actual constructor(
    keyBytes: ByteArray,
    private val nonce: ByteArray,
) {
    private val key = aesGcm.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, keyBytes)

    actual fun encrypt(
        bytesToEncrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray = key.cipher().encryptWithIvBlocking(nonce, bytesToEncrypt, aad)

    actual fun decrypt(
        bytesToDecrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray = key.cipher().decryptWithIvBlocking(nonce, bytesToDecrypt, aad)
}

internal actual fun secureRandomBytes(output: ByteArray) {
    CryptographyRandom.nextBytes(output)
}
