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

import com.vitorpamplona.mls.platform.mac.Hmac
import com.vitorpamplona.mls.platform.sha2.Sha256Compression
import com.vitorpamplona.mls.platform.sha2.Sha256Digest
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.posix.O_RDONLY
import platform.posix.close
import platform.posix.open
import platform.posix.read

// Straight on the block function: no digest object to allocate and reset.
internal actual fun sha256(data: ByteArray): ByteArray = ByteArray(32).also { Sha256Compression.hash(data, 0, data.size, it) }

internal actual class MacInstance actual constructor(
    algorithm: String,
    key: ByteArray,
) {
    private val hmac =
        when (algorithm) {
            "HmacSHA256" -> Hmac(Sha256Digest(), key)
            else -> error("Algorithm $algorithm is not supported.")
        }

    actual fun update(array: ByteArray) {
        hmac.update(array)
    }

    actual fun update(byte: Byte) {
        hmac.update(byte)
    }

    actual fun doFinal(): ByteArray = hmac.doFinal()
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun secureRandomBytes(output: ByteArray) {
    if (output.isEmpty()) return
    val fd = open("/dev/urandom", O_RDONLY)
    check(fd != -1) { "Failed to open /dev/urandom" }
    try {
        output.usePinned { pinned ->
            var bytesRead = 0
            while (bytesRead < output.size) {
                val result = read(fd, pinned.addressOf(bytesRead), (output.size - bytesRead).convert())
                check(result > 0) { "Failed to read from /dev/urandom" }
                bytesRead += result.toInt()
            }
        }
    } finally {
        close(fd)
    }
}
