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

import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.group.GroupValidation.ExtensionContext
import com.vitorpamplona.mls.tree.Extension
import kotlin.test.Test
import kotlin.test.assertFailsWith

/** RFC 9420 §17.3: default extensions appear once, in their own message, and parse as their struct. */
class ExtensionValidationTest {
    private val externalPubKey = ByteArray(32) { 7 }

    private fun opaque(data: ByteArray) = TlsWriter().apply { putOpaqueVarInt(data) }.toByteArray()

    private fun externalPub(data: ByteArray) = Extension(0x0004, data)

    @Test
    fun anExtensionMayAppearOnce() {
        val ext = externalPub(opaque(externalPubKey))
        assertFailsWith<IllegalArgumentException> { GroupValidation.validateExtensions(listOf(ext, ext), ExtensionContext.GROUP_INFO) }
        val custom = Extension(0xF0A0, byteArrayOf(1))
        assertFailsWith<IllegalArgumentException> { GroupValidation.validateExtensions(listOf(custom, custom), ExtensionContext.GROUP_CONTEXT) }
    }

    @Test
    fun aDefaultExtensionStaysInItsMessage() {
        val applicationId = Extension(0x0001, opaque("app".encodeToByteArray()))
        GroupValidation.validateExtensions(listOf(applicationId), ExtensionContext.LEAF_NODE)
        assertFailsWith<IllegalArgumentException> { GroupValidation.validateExtensions(listOf(applicationId), ExtensionContext.GROUP_CONTEXT) }
        assertFailsWith<IllegalArgumentException> { GroupValidation.validateExtensions(listOf(externalPub(opaque(externalPubKey))), ExtensionContext.GROUP_CONTEXT) }
    }

    @Test
    fun aDefaultExtensionMustParse() {
        assertFailsWith<IllegalArgumentException> { GroupValidation.validateExtensions(listOf(Extension(0x0001, byteArrayOf(5, 1))), ExtensionContext.LEAF_NODE) }
        assertFailsWith<IllegalArgumentException> { GroupValidation.validateExtensions(listOf(externalPub(opaque(externalPubKey) + 0)), ExtensionContext.GROUP_INFO) }
    }

    @Test
    fun externalPubIsOpaqueButTheBareKeyIsAcceptedToo() {
        GroupValidation.validateExtensions(listOf(externalPub(opaque(externalPubKey))), ExtensionContext.GROUP_INFO)
        // ts-mls and mls-kmp 1.2 write the bare key.
        GroupValidation.validateExtensions(listOf(externalPub(externalPubKey)), ExtensionContext.GROUP_INFO)
        assertFailsWith<IllegalArgumentException> { GroupValidation.validateExtensions(listOf(externalPub(ByteArray(31))), ExtensionContext.GROUP_INFO) }
    }
}
