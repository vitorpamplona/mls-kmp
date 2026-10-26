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
 * Keeps `docs/guide/validation.md` and `MaliciousMemberTest` in step: every
 * case the suite runs is cited in the table, and every case the table cites
 * exists. Likewise every `Class.method` test the table names exists.
 */
class ValidationTableSyncTest {
    private val moduleDir = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "src/commonTest").isDirectory }
    private val table = File(moduleDir, "../docs/guide/validation.md").readText()
    private val suite = File(moduleDir, "src/commonTest/kotlin/com/vitorpamplona/mls/group/MaliciousMemberTest.kt").readText()
    private val testSources = File(moduleDir, "src").walkTopDown().filter { it.extension == "kt" && "Test" in it.path }.associate { it.nameWithoutExtension to it.readText() }

    @Test
    fun everyCaseIsInTheTableAndEveryCitationExists() {
        val cases = Regex("""Case\(\s*"([^"]+)"""").findAll(suite).map { it.groupValues[1] }.toSet()
        val rows = table.lines().filter { it.startsWith("|") && "MaliciousMemberTest` ›" in it }
        val cited = rows.flatMap { row -> Regex(""""([^"]+)"""").findAll(row.substringAfter("MaliciousMemberTest` ›")).map { it.groupValues[1] } }.toSet()
        assertTrue(cases.isNotEmpty(), "no cases found")
        assertTrue((cases - cited).isEmpty(), "Cases missing from validation.md: ${cases - cited}")
        assertTrue((cited - cases).isEmpty(), "validation.md cites cases that do not exist: ${cited - cases}")

        val methods = Regex("""`(\w+Test)\.(\w+)`""").findAll(table).map { it.groupValues[1] to it.groupValues[2] }.toList()
        val missing = methods.filterNot { (cls, fn) -> testSources[cls]?.contains("fun $fn(") == true }
        assertTrue(missing.isEmpty(), "validation.md cites tests that do not exist: $missing")
        val classes = Regex("""`(\w+Test)`""").findAll(table).map { it.groupValues[1] }.toSet()
        assertTrue((classes - testSources.keys).isEmpty(), "validation.md cites test classes that do not exist: ${classes - testSources.keys}")
    }
}
