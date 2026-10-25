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

import com.vitorpamplona.mls.interop.PassiveClientRunner
import com.vitorpamplona.mls.interop.PassiveClientVector
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Replays passive-client vectors another implementation generated fresh,
 * rather than the fixed mlswg files: each run of CI's `fresh-vectors` job has
 * mls-rs regenerate its welcome, handle-commit and random suites with new
 * randomness and hands them over here.
 *
 *   MLSKMP_FOREIGN_PASSIVE_VECTORS=a.json:b.json ./gradlew :mls:jvmTest --rerun \
 *     --tests com.vitorpamplona.mls.ForeignPassiveClientVectorsTest
 *
 * Does nothing without the variable.
 */
class ForeignPassiveClientVectorsTest {
    @Test
    fun replayForeignVectors() {
        val paths = System.getenv("MLSKMP_FOREIGN_PASSIVE_VECTORS")?.split(':')?.filter { it.isNotBlank() } ?: return
        val json = Json(from = JsonMapper.jsonInstance) { ignoreUnknownKeys = true }
        var total = 0
        val failures = mutableListOf<String>()
        for (path in paths) {
            val vectors = json.decodeFromString(ListSerializer(PassiveClientVector.serializer()), File(path).readText()).filter { it.cipherSuite == 1 }
            for ((i, v) in vectors.withIndex()) {
                total++
                PassiveClientRunner.run(v)?.let { failures += "${File(path).name}[$i] (${v.epochs.size} epochs): $it" }
            }
        }
        assertTrue(total > 0, "no cipher suite 1 vectors in $paths")
        if (failures.isNotEmpty()) fail("${failures.size} of $total foreign vectors failed:\n" + failures.joinToString("\n"))
        println("$total foreign passive-client vectors passed")
    }
}
