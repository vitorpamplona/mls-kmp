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
import kotlin.test.fail

/**
 * Keeps `docs/guide` honest: every Kotlin block there that follows a
 * `<!-- snippet: name -->` marker must equal the `// region name` of
 * `GuideSnippetsTest`, which runs as a test. And every region must be used.
 *
 * After changing a region, rewrite the docs with
 *
 *   MLSKMP_UPDATE_GUIDE=1 ./gradlew :mls:jvmTest --rerun --tests com.vitorpamplona.mls.GuideSnippetsSyncTest
 */
class GuideSnippetsSyncTest {
    private val moduleDir = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "src/commonTest").isDirectory }
    private val snippetsFile = File(moduleDir, "src/commonTest/kotlin/com/vitorpamplona/mls/guide/GuideSnippetsTest.kt")
    private val guideDir = File(moduleDir, "../docs/guide").canonicalFile

    private val marker = Regex("""^<!-- snippet: ([\w-]+) -->$""")

    private fun regions(): Map<String, String> {
        val out = linkedMapOf<String, String>()
        var name: String? = null
        val body = mutableListOf<String>()
        for (line in snippetsFile.readLines()) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("// region ") -> {
                    check(name == null) { "Region ${trimmed.removePrefix("// region ")} opens inside $name" }
                    name = trimmed.removePrefix("// region ").trim()
                    body.clear()
                }

                trimmed == "// endregion" -> {
                    val n = checkNotNull(name) { "endregion without a region" }
                    check(out.put(n, dedent(body)) == null) { "Region $n appears twice" }
                    name = null
                }

                name != null -> {
                    body += line
                }
            }
        }
        check(name == null) { "Region $name never ends" }
        return out
    }

    private fun dedent(lines: List<String>): String {
        val indent = lines.filter { it.isNotBlank() }.minOfOrNull { it.length - it.trimStart().length } ?: 0
        return lines.joinToString("\n") { if (it.isBlank()) "" else it.drop(indent) }
    }

    @Test
    fun guideBlocksMatchTheirRegions() {
        val regions = regions()
        val update = System.getenv("MLSKMP_UPDATE_GUIDE") != null
        val used = mutableSetOf<String>()
        val problems = mutableListOf<String>()
        val pages = guideDir.listFiles { f -> f.extension == "md" }.orEmpty().sortedBy { it.name }
        assertTrue(pages.isNotEmpty(), "No guide pages in $guideDir")

        for (page in pages) {
            val lines = page.readLines()
            val rewritten = mutableListOf<String>()
            var i = 0
            while (i < lines.size) {
                val name = marker.find(lines[i])?.groupValues?.get(1)
                rewritten += lines[i]
                i++
                if (name == null) continue
                used += name
                val region = regions[name]
                if (region == null) {
                    problems += "${page.name}: no region '$name' in ${snippetsFile.name}"
                    continue
                }
                if (lines.getOrNull(i) != "```kotlin") {
                    problems += "${page.name}: '$name' marker is not followed by a ```kotlin block"
                    continue
                }
                val end = (i + 1 until lines.size).firstOrNull { lines[it] == "```" } ?: lines.size
                val block = lines.subList(i + 1, end).joinToString("\n")
                if (block != region) problems += "${page.name}: block '$name' differs from its region"
                rewritten += "```kotlin"
                rewritten += region.lines()
                rewritten += "```"
                i = end + 1
            }
            if (update) page.writeText(rewritten.joinToString("\n", postfix = "\n"))
        }
        (regions.keys - used).forEach { problems += "region '$it' is not used by any guide page" }
        if (problems.isNotEmpty() && !update) {
            fail(problems.joinToString("\n", postfix = "\n\nRun with MLSKMP_UPDATE_GUIDE=1 to copy the regions into the guide."))
        }
    }
}
