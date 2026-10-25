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
package com.vitorpamplona.mls.codec

/**
 * Decoder for TLS presentation language (RFC 8446 Section 3).
 *
 * Reads MLS wire format data encoded by TlsWriter or any conforming
 * MLS implementation (OpenMLS, mls-rs, etc.).
 */
class TlsReader(
    private val data: ByteArray,
    private var position: Int = 0,
    private val limit: Int = data.size,
) {
    companion object {
        /**
         * No longer enforced. Every length is checked against the bytes
         * actually present before anything is allocated, so a field can be
         * as large as the message holding it — a large group's ratchet tree
         * or a large application message — and no larger.
         */
        @Deprecated("No longer enforced: lengths are bounded by the input itself")
        const val MAX_OPAQUE_SIZE = 1_048_576
    }

    val remaining: Int get() = limit - position

    val hasRemaining: Boolean get() = position < limit

    fun readUint8(): Int {
        checkRemaining(1)
        return data[position++].toInt() and 0xFF
    }

    fun readUint16(): Int {
        checkRemaining(2)
        val result =
            ((data[position].toInt() and 0xFF) shl 8) or
                (data[position + 1].toInt() and 0xFF)
        position += 2
        return result
    }

    fun readUint32(): Long {
        checkRemaining(4)
        val result =
            ((data[position].toLong() and 0xFF) shl 24) or
                ((data[position + 1].toLong() and 0xFF) shl 16) or
                ((data[position + 2].toLong() and 0xFF) shl 8) or
                (data[position + 3].toLong() and 0xFF)
        position += 4
        return result
    }

    fun readUint64(): Long {
        checkRemaining(8)
        var result = 0L
        for (i in 0 until 8) {
            result = (result shl 8) or (data[position + i].toLong() and 0xFF)
        }
        position += 8
        return result
    }

    /**
     * A uint32 used as an index or a generation: a leaf, a node, a ratchet
     * position. Values above Int.MAX_VALUE fit no tree and no ratchet, and read
     * as negative Ints would slip past `index < size` checks, so they are
     * refused here.
     */
    fun readIndex(): Int {
        val value = readUint32()
        require(value <= Int.MAX_VALUE) { "Index $value out of range" }
        return value.toInt()
    }

    /**
     * A uint32 element count of a vector of [minElementSize]-byte-or-larger
     * elements. A count the remaining bytes cannot hold is refused before
     * anything is allocated for it.
     */
    fun readCount(minElementSize: Int = 1): Int {
        val value = readUint32()
        require(value <= remaining.toLong() / minElementSize.coerceAtLeast(1)) { "Count $value exceeds the $remaining bytes left" }
        return value.toInt()
    }

    /** Read a fixed number of raw bytes */
    fun readBytes(count: Int): ByteArray {
        require(count >= 0) { "Negative length $count" }
        checkRemaining(count)
        val result = data.copyOfRange(position, position + count)
        position += count
        return result
    }

    /** Read a variable-length opaque with 1-byte length prefix */
    fun readOpaque1(): ByteArray {
        val length = readUint8()
        return readBytes(length)
    }

    /** Read a variable-length opaque with 2-byte length prefix */
    fun readOpaque2(): ByteArray {
        val length = readUint16()
        return readBytes(length)
    }

    /** Read a variable-length opaque with 4-byte length prefix */
    fun readOpaque4(): ByteArray {
        val length = readUint32()
        require(length <= Int.MAX_VALUE) { "Opaque4 length $length too large" }
        return readBytes(length.toInt())
    }

    /**
     * Read a QUIC-style variable-length integer (VarInt).
     * The two most significant bits of the first byte encode the length:
     * - 00: 1 byte (6-bit value, 0..63)
     * - 01: 2 bytes (14-bit value, 64..16383)
     * - 10: 4 bytes (30-bit value, 16384..1073741823)
     */
    fun readVarInt(): Int {
        val first = readUint8()
        return when (first shr 6) {
            0 -> {
                first
            }

            // RFC 9420 §2.1.2: a varint MUST use the smallest encoding that fits,
            // and one using more bits than necessary MUST be treated as malformed.
            1 -> {
                val value = ((first and 0x3F) shl 8) or readUint8()
                require(value >= 64) { "Non-minimal VarInt encoding: $value in 2 bytes" }
                value
            }

            2 -> {
                val b1 = readUint8()
                val b2 = readUint8()
                val b3 = readUint8()
                val value = ((first and 0x3F) shl 24) or (b1 shl 16) or (b2 shl 8) or b3
                require(value >= 16384) { "Non-minimal VarInt encoding: $value in 4 bytes" }
                value
            }

            else -> {
                throw IllegalArgumentException("Unsupported VarInt prefix: 0x${first.toString(16)}")
            }
        }
    }

    /** Read a variable-length opaque with QUIC-style VarInt length prefix */
    fun readOpaqueVarInt(): ByteArray {
        val length = readVarInt()
        return readBytes(length)
    }

    /** Read a variable-length vector with VarInt length prefix */
    fun <T> readVectorVarInt(readItem: (TlsReader) -> T): List<T> {
        val vectorBytes = readOpaqueVarInt()
        val vectorReader = TlsReader(vectorBytes)
        val items = mutableListOf<T>()
        while (vectorReader.hasRemaining) {
            items.add(readItem(vectorReader))
        }
        return items
    }

    /**
     * Read a variable-length vector with 4-byte length prefix,
     * deserializing each item using the provided factory.
     */
    fun <T> readVector4(readItem: (TlsReader) -> T): List<T> {
        val vectorBytes = readOpaque4()
        val vectorReader = TlsReader(vectorBytes)
        val items = mutableListOf<T>()
        while (vectorReader.hasRemaining) {
            items.add(readItem(vectorReader))
        }
        return items
    }

    /**
     * Read a variable-length vector with 2-byte length prefix,
     * deserializing each item using the provided factory.
     */
    fun <T> readVector2(readItem: (TlsReader) -> T): List<T> {
        val vectorBytes = readOpaque2()
        val vectorReader = TlsReader(vectorBytes)
        val items = mutableListOf<T>()
        while (vectorReader.hasRemaining) {
            items.add(readItem(vectorReader))
        }
        return items
    }

    /**
     * Read a variable-length vector with 1-byte length prefix,
     * deserializing each item using the provided factory.
     */
    fun <T> readVector1(readItem: (TlsReader) -> T): List<T> {
        val vectorBytes = readOpaque1()
        val vectorReader = TlsReader(vectorBytes)
        val items = mutableListOf<T>()
        while (vectorReader.hasRemaining) {
            items.add(readItem(vectorReader))
        }
        return items
    }

    /**
     * Read an optional value (uint8 presence flag + value if present).
     */
    fun <T> readOptional(readValue: (TlsReader) -> T): T? =
        when (val present = readUint8()) {
            0 -> null
            1 -> readValue(this)
            else -> throw IllegalArgumentException("Invalid optional<T> presence flag: $present")
        }

    /**
     * Runs [block] and also returns the exact bytes it consumed.
     *
     * For structs whose canonical encoding is needed as-is afterwards, e.g. a
     * Proposal or Commit inside FramedContent: hashing the received bytes
     * rather than a re-encoding keeps signatures and references exact.
     */
    fun <T> readCapturing(block: (TlsReader) -> T): Pair<T, ByteArray> {
        val start = position
        val value = block(this)
        return value to data.copyOfRange(start, position)
    }

    /** Fails unless every byte has been consumed: MLS structs carry no trailing data. */
    fun requireFullyConsumed(what: String) {
        require(!hasRemaining) { "$what has $remaining trailing bytes" }
    }

    /**
     * Create a sub-reader limited to the next [count] bytes.
     * Advances this reader's position past those bytes.
     */
    fun subReader(count: Int): TlsReader {
        checkRemaining(count)
        val sub = TlsReader(data, position, position + count)
        position += count
        return sub
    }

    private fun checkRemaining(needed: Int) {
        require(remaining >= needed) {
            "TLS decode underflow: need $needed bytes, have $remaining at position $position"
        }
    }
}
