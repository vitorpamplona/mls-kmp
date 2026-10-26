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
package com.vitorpamplona.mls.fuzz

import kotlin.random.Random

/**
 * Structure-unaware mutations of valid MLS messages: what a hostile peer or a
 * broken relay can do to bytes in flight. Every mutation changes the input.
 */
internal class Mutator(
    private val random: Random,
) {
    fun mutate(
        input: ByteArray,
        others: List<ByteArray>,
    ): ByteArray {
        repeat(8) {
            val out = once(input, others)
            if (!out.contentEquals(input)) return out
        }
        return input + random.nextInt(256).toByte()
    }

    private fun once(
        input: ByteArray,
        others: List<ByteArray>,
    ): ByteArray {
        if (input.isEmpty()) return byteArrayOf(random.nextInt(256).toByte())
        val b = input.copyOf()
        return when (random.nextInt(9)) {
            // A few bit flips anywhere.
            0 ->
                b.also {
                    repeat(1 + random.nextInt(4)) { _ ->
                        val i = random.nextInt(b.size)
                        b[i] = (b[i].toInt() xor (1 shl random.nextInt(8))).toByte()
                    }
                }
            // A byte set to a boundary value: lengths and enums go out of range.
            1 -> b.also { b[random.nextInt(b.size)] = INTERESTING[random.nextInt(INTERESTING.size)] }
            // Truncate.
            2 -> b.copyOf(random.nextInt(b.size))
            // Trailing garbage.
            3 -> b + random.nextBytes(1 + random.nextInt(64))
            // A varint length prefix inflated to its largest 2- or 4-byte value.
            4 ->
                b.also {
                    val i = random.nextInt(b.size)
                    b[i] = if (random.nextBoolean()) 0x7F else 0xBF.toByte()
                    if (i + 1 < b.size) b[i + 1] = 0xFF.toByte()
                }
            // Delete a chunk from the middle.
            5 -> {
                val from = random.nextInt(b.size)
                val to = minOf(b.size, from + 1 + random.nextInt(32))
                b.copyOfRange(0, from) + b.copyOfRange(to, b.size)
            }
            // Duplicate a chunk.
            6 -> {
                val from = random.nextInt(b.size)
                val to = minOf(b.size, from + 1 + random.nextInt(32))
                b.copyOfRange(0, to) + b.copyOfRange(from, b.size)
            }
            // Splice the head of this message onto the tail of another.
            7 -> {
                val other = others[random.nextInt(others.size)]
                b.copyOf(random.nextInt(b.size + 1)) + other.copyOfRange(random.nextInt(other.size + 1), other.size)
            }
            // Overwrite a run with random bytes.
            else ->
                b.also {
                    val from = random.nextInt(b.size)
                    for (i in from until minOf(b.size, from + 1 + random.nextInt(16))) b[i] = random.nextInt(256).toByte()
                }
        }
    }

    private companion object {
        val INTERESTING = byteArrayOf(0x00, 0x01, 0x02, 0x3F, 0x40, 0x7F, 0x80.toByte(), 0xBF.toByte(), 0xC0.toByte(), 0xFE.toByte(), 0xFF.toByte())
    }
}
