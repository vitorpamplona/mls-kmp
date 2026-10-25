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

import com.vitorpamplona.mls.framing.WireFormat

/**
 * Which wire format a group's proposals and commits travel in.
 *
 * RFC 9420 §6 lets a member send a proposal or commit as a PublicMessage
 * (readable by the delivery service, which can then track the group — see
 * [PublicGroup]) or as a PrivateMessage (hiding even the handshake from it).
 * A group usually wants one or the other; this records the choice.
 *
 * [outgoing] is the default for [MlsGroup.commit], [MlsGroup.stageCommit] and
 * [MlsGroup.proposalMessage]. [incoming] rejects handshake messages from
 * members in a format it does not accept, and an explicit `wireFormat` that
 * [incoming] would refuse is refused on the way out too, since the other
 * members would reject it. Application messages are always PrivateMessages,
 * and messages from non-members — external commits, proposals from an
 * external sender or a new member — are always PublicMessages, whatever this
 * says.
 */
data class WireFormatPolicy(
    val outgoing: WireFormat,
    val incoming: Incoming,
) {
    init {
        require(outgoing == WireFormat.PUBLIC_MESSAGE || outgoing == WireFormat.PRIVATE_MESSAGE) {
            "Handshake messages are sent as a PublicMessage or a PrivateMessage, not $outgoing"
        }
        require(accepts(outgoing)) { "A policy that sends $outgoing must accept it" }
    }

    /** The wire formats accepted for a member's proposals and commits. */
    enum class Incoming {
        PUBLIC_ONLY,
        PRIVATE_ONLY,
        MIXED,
    }

    /** Whether a member's proposal or commit may arrive as [wireFormat]. */
    fun accepts(wireFormat: WireFormat): Boolean =
        when (incoming) {
            Incoming.PUBLIC_ONLY -> wireFormat == WireFormat.PUBLIC_MESSAGE
            Incoming.PRIVATE_ONLY -> wireFormat == WireFormat.PRIVATE_MESSAGE
            Incoming.MIXED -> wireFormat == WireFormat.PUBLIC_MESSAGE || wireFormat == WireFormat.PRIVATE_MESSAGE
        }

    companion object {
        /** Send and accept PublicMessages only. */
        val PURE_PLAINTEXT = WireFormatPolicy(WireFormat.PUBLIC_MESSAGE, Incoming.PUBLIC_ONLY)

        /** Send and accept PrivateMessages only: the delivery service sees no handshake content. */
        val PURE_CIPHERTEXT = WireFormatPolicy(WireFormat.PRIVATE_MESSAGE, Incoming.PRIVATE_ONLY)

        /** Send PublicMessages, accept both. The default. */
        val MIXED_PLAINTEXT = WireFormatPolicy(WireFormat.PUBLIC_MESSAGE, Incoming.MIXED)

        /** Send PrivateMessages, accept both. */
        val MIXED_CIPHERTEXT = WireFormatPolicy(WireFormat.PRIVATE_MESSAGE, Incoming.MIXED)
    }
}
