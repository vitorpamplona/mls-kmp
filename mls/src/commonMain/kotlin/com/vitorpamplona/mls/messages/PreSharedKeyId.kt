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
package com.vitorpamplona.mls.messages

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsSerializable
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.platform.Hex

/**
 * RFC 9420 §8.4 `PreSharedKeyID`:
 *
 * ```
 * struct {
 *   PSKType psktype;
 *   select (PreSharedKeyID.psktype) {
 *     case external:   opaque psk_id<V>;
 *     case resumption: ResumptionPSKUsage usage;
 *                      opaque psk_group_id<V>;
 *                      uint64 psk_epoch;
 *   };
 *   opaque psk_nonce<V>;
 * } PreSharedKeyID;
 * ```
 *
 * It is what a PreSharedKey proposal carries and what a Welcome's
 * `GroupSecrets.psks` lists, so a joiner can find the same PSKs the
 * committer folded into the key schedule.
 */
public sealed class PreSharedKeyId : TlsSerializable {
    public abstract val pskNonce: ByteArray

    /** The `psktype` on the wire. */
    public abstract val pskType: Int

    /** A PSK the application provisioned out of band, named by [pskId]. */
    public class External(
        public val pskId: ByteArray,
        override val pskNonce: ByteArray,
    ) : PreSharedKeyId() {
        override val pskType: Int = TYPE_EXTERNAL

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint8(pskType)
            writer.putOpaqueVarInt(pskId)
            writer.putOpaqueVarInt(pskNonce)
        }

        override fun equals(other: Any?): Boolean = other is External && pskId.contentEquals(other.pskId) && pskNonce.contentEquals(other.pskNonce)

        override fun hashCode(): Int = 31 * pskId.contentHashCode() + pskNonce.contentHashCode()
    }

    /** The `resumption_psk` of epoch [pskEpoch] of group [pskGroupId] (RFC 9420 §8.6). */
    public class Resumption(
        public val usage: Int,
        public val pskGroupId: ByteArray,
        public val pskEpoch: Long,
        override val pskNonce: ByteArray,
    ) : PreSharedKeyId() {
        override val pskType: Int = TYPE_RESUMPTION

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint8(pskType)
            writer.putUint8(usage)
            writer.putOpaqueVarInt(pskGroupId)
            writer.putUint64(pskEpoch)
            writer.putOpaqueVarInt(pskNonce)
        }

        override fun equals(other: Any?): Boolean =
            other is Resumption &&
                usage == other.usage &&
                pskGroupId.contentEquals(other.pskGroupId) &&
                pskEpoch == other.pskEpoch &&
                pskNonce.contentEquals(other.pskNonce)

        override fun hashCode(): Int = 31 * (31 * pskGroupId.contentHashCode() + pskEpoch.hashCode()) + usage
    }

    /**
     * Identity without the nonce, for "the same PSK" comparisons (RFC 9420 §12.2
     * forbids two PreSharedKey proposals referencing the same PreSharedKeyID).
     */
    public fun identityKey(): String =
        when (this) {
            is External -> "e:" + Hex.encode(pskId)
            is Resumption -> "r:$usage:" + Hex.encode(pskGroupId) + ":" + pskEpoch
        }

    public companion object {
        public const val TYPE_EXTERNAL: Int = 1
        public const val TYPE_RESUMPTION: Int = 2

        public const val USAGE_APPLICATION: Int = 1
        public const val USAGE_REINIT: Int = 2
        public const val USAGE_BRANCH: Int = 3

        public fun decodeTls(reader: TlsReader): PreSharedKeyId =
            when (val type = reader.readUint8()) {
                TYPE_EXTERNAL -> {
                    External(pskId = reader.readOpaqueVarInt(), pskNonce = reader.readOpaqueVarInt())
                }

                TYPE_RESUMPTION -> {
                    val usage = reader.readUint8()
                    require(usage in USAGE_APPLICATION..USAGE_BRANCH) { "Unknown ResumptionPSKUsage: $usage" }
                    Resumption(
                        usage = usage,
                        pskGroupId = reader.readOpaqueVarInt(),
                        pskEpoch = reader.readUint64(),
                        pskNonce = reader.readOpaqueVarInt(),
                    )
                }

                else -> {
                    throw IllegalArgumentException("Unknown PSKType: $type")
                }
            }
    }
}
