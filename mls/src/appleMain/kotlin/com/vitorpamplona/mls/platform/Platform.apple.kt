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

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CCHmacContext
import platform.CoreCrypto.CCHmacFinal
import platform.CoreCrypto.CCHmacInit
import platform.CoreCrypto.CCHmacUpdate
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.Cleaner
import kotlin.native.ref.createCleaner

@OptIn(ExperimentalForeignApi::class)
internal actual fun sha256(data: ByteArray): ByteArray {
    val digest = UByteArray(CC_SHA256_DIGEST_LENGTH)
    data.usePinned { inputPinned ->
        digest.usePinned { digestPinned ->
            CC_SHA256(
                // addressOf(0) throws on an empty array; CommonCrypto accepts null for a 0-byte input.
                if (data.isEmpty()) null else inputPinned.addressOf(0),
                data.size.convert(),
                digestPinned.addressOf(0),
            )
        }
    }
    return digest.toByteArray()
}

/** HMAC on CommonCrypto's CCHmac, one message per instance (as the engine uses it). Only `HmacSHA256` is supported. */
@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
internal actual class MacInstance actual constructor(
    algorithm: String,
    key: ByteArray,
) {
    // The context lives on the native heap; the cleaner frees it with this object.
    private val context: CPointer<CCHmacContext> = nativeHeap.alloc<CCHmacContext>().ptr

    @Suppress("unused")
    private val cleaner: Cleaner = createCleaner(context) { nativeHeap.free(it.rawValue) }

    init {
        require(algorithm == "HmacSHA256") { "Algorithm $algorithm is not supported." }
        if (key.isEmpty()) {
            CCHmacInit(context, kCCHmacAlgSHA256, null, 0.convert())
        } else {
            key.usePinned { CCHmacInit(context, kCCHmacAlgSHA256, it.addressOf(0), key.size.convert()) }
        }
    }

    actual fun update(array: ByteArray) {
        if (array.isEmpty()) return
        array.usePinned { CCHmacUpdate(context, it.addressOf(0), array.size.convert()) }
    }

    actual fun update(byte: Byte) = update(byteArrayOf(byte))

    actual fun doFinal(): ByteArray {
        val output = ByteArray(CC_SHA256_DIGEST_LENGTH)
        output.usePinned { CCHmacFinal(context, it.addressOf(0)) }
        return output
    }
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun secureRandomBytes(output: ByteArray) {
    if (output.isEmpty()) return
    val status = SecRandomCopyBytes(kSecRandomDefault, output.size.toULong(), output.refTo(0))
    check(status == 0) { "Failed to generate secure random bytes: $status" }
}
