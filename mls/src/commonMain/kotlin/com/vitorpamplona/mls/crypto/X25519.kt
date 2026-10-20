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
package com.vitorpamplona.mls.crypto

import com.vitorpamplona.mls.platform.RandomInstance

/**
 * X25519 Diffie-Hellman key exchange for MLS DHKEM (RFC 9180).
 *
 * Used in TreeKEM for path secret encryption via HPKE.
 *
 * One pure-Kotlin Montgomery-ladder implementation over [Curve25519Field]
 * (a TweetNaCl port) for every platform. It intentionally does NOT delegate to a platform provider such as
 * `java.security` XDH, because Android's KeyStore/JCA integration for raw X25519
 * keys is unreliable across API levels. `dh()` rejects an all-zero shared secret
 * per RFC 7748 §6.1; note the ladder relies on branch-uniform (mask-based)
 * selection but, being pure Kotlin on the JVM/ART, carries no hardware
 * constant-time guarantee.
 */
object X25519 {
    private const val KEY_LENGTH = 32

    /**
     * Generate a new X25519 key pair.
     * @return pair of (privateKey: 32 bytes, publicKey: 32 bytes)
     */
    fun generateKeyPair(): X25519KeyPair {
        val privateKey = RandomInstance.bytes(KEY_LENGTH)
        val publicKey = publicFromPrivate(privateKey)
        return X25519KeyPair(privateKey, publicKey)
    }

    /**
     * Perform X25519 Diffie-Hellman key agreement.
     * @param privateKey 32-byte private key
     * @param publicKey 32-byte public key
     * @return 32-byte shared secret
     */
    fun dh(
        privateKey: ByteArray,
        publicKey: ByteArray,
    ): ByteArray {
        require(privateKey.size == KEY_LENGTH) { "Private key must be 32 bytes" }
        require(publicKey.size == KEY_LENGTH) { "Public key must be 32 bytes" }

        val result = scalarmult(privateKey, publicKey)

        require(!result.all { it == 0.toByte() }) {
            "DH produced all-zero shared secret (possible small-subgroup attack)"
        }

        return result
    }

    /**
     * Derive the public key from a private key.
     * @param privateKey 32-byte private key
     * @return 32-byte public key
     */
    fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        require(privateKey.size == KEY_LENGTH) { "Private key must be 32 bytes" }
        val basepoint = ByteArray(KEY_LENGTH)
        basepoint[0] = 9
        return scalarmult(privateKey, basepoint)
    }

    /**
     * X25519 scalar multiplication via Montgomery ladder (RFC 7748).
     *
     * Computes [n]P on Curve25519 in Montgomery form.
     * Based on the TweetNaCl algorithm by Bernstein et al.
     */
    private fun scalarmult(
        n: ByteArray,
        p: ByteArray,
    ): ByteArray {
        val z = n.copyOf()
        // Clamp scalar per RFC 7748 Section 5
        z[0] = (z[0].toInt() and 248).toByte()
        z[31] = ((z[31].toInt() and 127) or 64).toByte()

        val x = Curve25519Field.unpack25519(p)
        val a = Curve25519Field.GF1.copyOf()
        val b = x.copyOf()
        val c = Curve25519Field.GF0.copyOf()
        val d = Curve25519Field.GF1.copyOf()

        // The ladder's entire working set, allocated ONCE. Every field
        // operation in the loop writes into one of these, so 255 iterations
        // allocate nothing at all — where the allocating form produced a fresh
        // element per operation, about 1.3 MB of garbage per call.
        val e = LongArray(10)
        val f = LongArray(10)
        val g = LongArray(10)
        val h = LongArray(10)
        val dd = LongArray(10)
        val ff = LongArray(10)
        val da = LongArray(10)
        val cb = LongArray(10)
        val cc = LongArray(10)
        val tmp = LongArray(10)

        for (i in 254 downTo 0) {
            val r = ((z[i shr 3].toLong() shr (i and 7)) and 1)
            Curve25519Field.sel25519(a, b, r)
            Curve25519Field.sel25519(c, d, r)

            // a, b, c and d are read only by these four lines; from here on
            // they are dead and can be overwritten with the new values.
            Curve25519Field.addInto(e, a, c)
            Curve25519Field.subInto(g, a, c)
            Curve25519Field.addInto(f, b, d)
            Curve25519Field.subInto(h, b, d)

            Curve25519Field.sqrInto(dd, e)
            Curve25519Field.sqrInto(ff, g)
            Curve25519Field.mulInto(da, h, e)
            Curve25519Field.mulInto(cb, f, g)

            // e := da + cb and g := da - cb. Reusing e and g is safe: both
            // held inputs to the four products above, which are now computed.
            Curve25519Field.addInto(e, da, cb)
            Curve25519Field.subInto(g, da, cb)

            Curve25519Field.sqrInto(b, e)
            Curve25519Field.sqrInto(g, g)
            Curve25519Field.mulInto(d, g, x)

            Curve25519Field.mulInto(a, dd, ff)
            Curve25519Field.subInto(cc, dd, ff)
            Curve25519Field.mulA24Into(tmp, cc)
            Curve25519Field.addInto(tmp, dd, tmp)
            Curve25519Field.mulInto(c, cc, tmp)

            Curve25519Field.sel25519(a, b, r)
            Curve25519Field.sel25519(c, d, r)
        }

        // c := 1/c, then a := a/c. `tmp` is free again and serves as the
        // inversion's scratch element.
        Curve25519Field.inv25519Into(c, c, tmp)
        Curve25519Field.mulInto(a, a, c)
        return Curve25519Field.pack25519(a)
    }
}

data class X25519KeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X25519KeyPair) return false
        return privateKey.contentEquals(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}
