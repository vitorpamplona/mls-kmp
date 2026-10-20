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

import com.vitorpamplona.mls.platform.Hex
import kotlinx.serialization.json.Json

/** The JSON settings the interop vectors are decoded with. */
object JsonMapper {
    val jsonInstance =
        Json {
            ignoreUnknownKeys = true
            isLenient = true
        }
}

/** Decodes lower- or upper-case hex; throws on odd length or a non-hex char. */
fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "odd-length hex: $length chars" }
    return ByteArray(length / 2) { i ->
        val hi = this[i * 2].digitToInt(16)
        val lo = this[i * 2 + 1].digitToInt(16)
        ((hi shl 4) or lo).toByte()
    }
}

/** Lower-case hex of these bytes. */
fun ByteArray.toHexKey(): String = Hex.encode(this)
