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
package com.vitorpamplona.mls.tree

import com.vitorpamplona.mls.crypto.MlsCryptoProvider

/**
 * GREASE (RFC 9420 §13.5): reserved values a client advertises at random in
 * its capabilities so that peers which choke on values they don't know are
 * found early, instead of the day a real new type ships.
 *
 * They are only ever ADVERTISED: a GREASE value never appears as a proposal,
 * credential or ciphersuite in use, and a receiver ignores them.
 */
object Grease {
    /** 0x0A0A, 0x1A1A, … 0xEAEA. */
    val VALUES: List<Int> = (0 until 15).map { 0x0A0A + it * 0x1010 }

    fun isGrease(value: Int): Boolean = value in VALUES

    /**
     * [capabilities] with one random GREASE value added to its ciphersuites,
     * extensions, proposals and credentials — unless it already carries some,
     * so a leaf that is rebuilt keeps the values it advertised.
     */
    fun addTo(capabilities: Capabilities): Capabilities {
        if ((capabilities.ciphersuites + capabilities.extensions + capabilities.proposals + capabilities.credentials).any(::isGrease)) return capabilities

        fun pick() = VALUES[(MlsCryptoProvider.randomBytes(1)[0].toInt() and 0xFF) % VALUES.size]
        return capabilities.copy(
            ciphersuites = capabilities.ciphersuites + pick(),
            extensions = capabilities.extensions + pick(),
            proposals = capabilities.proposals + pick(),
            credentials = capabilities.credentials + pick(),
        )
    }
}
