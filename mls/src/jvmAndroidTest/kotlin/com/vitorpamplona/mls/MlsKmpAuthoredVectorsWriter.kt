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

import com.vitorpamplona.mls.interop.MlsKmpAuthoredVectors
import com.vitorpamplona.mls.interop.PassiveClientVector
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.Test

/**
 * Writes the passive-client vectors mls-kmp authors to the file named by
 * `MLSKMP_PASSIVE_VECTORS`, for a foreign implementation to replay:
 *
 *   MLSKMP_PASSIVE_VECTORS=/tmp/mls-kmp-passive.json \
 *     ./gradlew :mls:jvmTest --tests com.vitorpamplona.mls.MlsKmpAuthoredVectorsWriter
 *   node tools/tsmls-vector-gen/verify-passive-client.mjs /tmp/mls-kmp-passive.json
 *
 * Does nothing without the variable. The vectors are generated fresh each
 * time, so every run checks new randomness.
 */
class MlsKmpAuthoredVectorsWriter {
    @Test
    fun writeAuthoredVectors() {
        val path = System.getenv("MLSKMP_PASSIVE_VECTORS") ?: return
        // Every field written, as in the mlswg files: an empty `proposals` list is still a list.
        val json = Json(from = JsonMapper.jsonInstance) { encodeDefaults = true }
        File(path).writeText(json.encodeToString(ListSerializer(PassiveClientVector.serializer()), MlsKmpAuthoredVectors.generate()))
    }
}
