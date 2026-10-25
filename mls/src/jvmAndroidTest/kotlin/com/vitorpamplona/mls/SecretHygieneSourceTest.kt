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

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Source rules for secrets, checked over `commonMain`: a tag, MAC or binder —
 * anything an attacker can submit and have compared against a secret-derived
 * value — is compared with `constantTimeEquals`, never `contentEquals`, so
 * the comparison's timing says nothing about how many bytes matched.
 */
class SecretHygieneSourceTest {
    private val sources =
        generateSequence(File("").absoluteFile) { it.parentFile }
            .first { File(it, "src/commonMain").isDirectory }
            .resolve("src/commonMain")
            .walkTopDown()
            .filter { it.extension == "kt" }
            .toList()

    private val secretComparison = Regex("""(?i)(tag|mac|binder)\w*\s*\??\.contentEquals\(|contentEquals\([^)]*(tag|mac|binder)""")

    @Test
    fun tagsAndMacsAreComparedInConstantTime() {
        val offenders =
            sources.flatMap { file ->
                file.readLines().mapIndexedNotNull { i, line ->
                    if (secretComparison.containsMatchIn(line) && !line.trimStart().startsWith("//") && !line.trimStart().startsWith("*")) "${file.name}:${i + 1}: ${line.trim()}" else null
                }
            }
        assertTrue(offenders.isEmpty(), "Compare these with constantTimeEquals:\n" + offenders.joinToString("\n"))
    }
}
