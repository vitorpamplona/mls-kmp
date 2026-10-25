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
package com.vitorpamplona.mls.sim

import com.vitorpamplona.mls.InternalMlsApi
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.group.MlsGroupState
import com.vitorpamplona.mls.group.ProcessedMessage
import com.vitorpamplona.mls.group.PublicGroup
import com.vitorpamplona.mls.group.WireFormatPolicy
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.messages.ProposalType
import com.vitorpamplona.mls.platform.TimeUtils
import com.vitorpamplona.mls.testEnv
import com.vitorpamplona.mls.toHexKey
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Credential
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.fail

/**
 * Many members, many random steps, and after every step the invariants a
 * group lives by: every member that has caught up agrees on the epoch, its
 * authenticator, the tree and the membership, a [PublicGroup] following the
 * delivery service agrees too, and every message reaches every member that
 * may read it.
 *
 * The delivery service is a log: proposals and commits in the order it
 * accepted them, one commit per epoch. Members commit by staging and merge
 * when their commit comes back; when several commit at once the service
 * picks one and the rest process the winner. Along the way members go
 * offline and catch up, restart from saved state, run with skewed clocks,
 * join by Welcome or external commit, resync, and leave; application
 * messages arrive late, out of order, or not at all.
 *
 * A fresh seed each run (`MLSKMP_SIM_SEED` replays one); the nightly job
 * runs more and longer simulations with `MLSKMP_SIM_RUNS` and
 * `MLSKMP_SIM_STEPS`.
 */
@OptIn(InternalMlsApi::class)
class GroupSimulationTest {
    private val seed = testEnv("MLSKMP_SIM_SEED")?.toLong() ?: Random.nextLong()
    private val steps = testEnv("MLSKMP_SIM_STEPS")?.toInt() ?: 120
    private val runs = testEnv("MLSKMP_SIM_RUNS")?.toInt() ?: 1

    /** Capabilities every member advertises, so SelfRemove can be used. */
    private object SimPolicy : MlsGroupPolicy {
        override val defaultLeafCapabilities = Capabilities(proposals = listOf(ProposalType.SELF_REMOVE.value))
    }

    private object CiphertextPolicy : MlsGroupPolicy {
        override val defaultLeafCapabilities = Capabilities(proposals = listOf(ProposalType.SELF_REMOVE.value))
        override val wireFormatPolicy = WireFormatPolicy.PURE_CIPHERTEXT
    }

    @Test
    fun publicHandshakesFollowedByADeliveryServiceView() = repeat(runs) { Simulation(seed + 2 * it, steps, SimPolicy, withView = true).run() }

    @Test
    fun privateHandshakes() = repeat(runs) { Simulation(seed + 2 * it + 1, steps, CiphertextPolicy, withView = false).run() }

    private class Member(
        val name: String,
        var group: MlsGroup,
        /** Next log entry this member has not processed. */
        var cursor: Int,
        /** First epoch this member can read: the one it joined at. */
        val joinedAt: Long,
    ) {
        var online = true
        var skew = 0L
        var removed = false

        /** Out of the tree by a commit this member has not read yet. */
        var evicted = false
        val inbox = mutableListOf<AppMessage>()
    }

    private class Entry(
        val bytes: ByteArray,
        val epoch: Long,
        val what: String,
    )

    private class AppMessage(
        val bytes: ByteArray,
        val epoch: Long,
        val text: String,
    )

    private class Simulation(
        val seed: Long,
        val steps: Int,
        val policy: MlsGroupPolicy,
        val withView: Boolean,
    ) {
        val random = Random(seed)
        val log = mutableListOf<Entry>()
        val members = mutableListOf<Member>()
        var view: PublicGroup? = null
        var viewCursor = 0
        var nextId = 0
        val trace = ArrayDeque<String>()
        val now = TimeUtils.now()

        fun note(s: String) {
            trace.addLast(s)
            if (trace.size > 40) trace.removeFirst()
        }

        fun fail(why: String): Nothing = kotlin.test.fail("$why\nseed=$seed (replay with MLSKMP_SIM_SEED=$seed)\nlast steps:\n" + trace.joinToString("\n"))

        fun newName() = "m${nextId++}"

        fun keyPackage(name: String) = MlsGroup.createKeyPackage(name.encodeToByteArray(), policy)

        /** Members still in the group's tree. */
        val active get() = members.filter { !it.removed && !it.evicted }
        val current get() = active.filter { it.online && it.cursor == log.size }

        /** Invitees of Add proposals sent by reference, joining from whichever commit carries them. */
        val invitees = mutableListOf<Pair<String, com.vitorpamplona.mls.messages.KeyPackageBundle>>()

        fun applyClock(m: Member) {
            val skew = m.skew
            m.group.clock = { now + skew }
        }

        fun run() {
            val founder = Member(newName(), MlsGroup.create("m0".encodeToByteArray(), policy = policy), 0, 0)
            members += founder
            if (withView) view = PublicGroup.fromGroupInfo(founder.group.groupInfoMessage(), policy)
            repeat(3) { addByWelcome(founder) }
            check()
            for (step in 0 until steps) {
                try {
                    step()
                } catch (e: AssertionError) {
                    throw e
                } catch (t: Throwable) {
                    fail("step $step threw ${t.stackTraceToString().lines().take(12).joinToString("\n")}")
                }
            }
            active.forEach {
                it.online = true
                catchUp(it)
            }
            deliverAll()
            check()
        }

        fun step() {
            val actor =
                current.randomOrNull(random) ?: active.first().also {
                    it.online = true
                    catchUp(it)
                }
            when (random.nextInt(100)) {
                in 0..11 -> if (active.size < 10) addByWelcome(actor)
                in 12..19 -> if (active.size > 2) remove(actor)
                in 20..27 -> selfUpdate(actor)
                in 28..37 -> proposeThenSomeoneCommits(actor)
                in 38..47 -> concurrentCommits()
                in 48..53 -> if (active.size < 10) externalJoin(actor)
                in 54..57 -> resync(actor)
                in 58..61 -> if (active.size > 2) leave(actor)
                in 62..69 -> restart(active.random(random))
                in 70..77 -> toggleOnline()
                in 78..81 -> skewClock(active.random(random))
                else -> sendMessages()
            }
            // Members that are online read what the service has.
            active.filter { it.online }.forEach { catchUp(it) }
            deliverSome()
            check()
        }

        // --- The delivery service ---

        fun publish(
            bytes: ByteArray,
            epoch: Long,
            what: String,
        ) {
            log += Entry(bytes, epoch, what)
            note("log[${log.size - 1}] $what at epoch $epoch")
            if (withView) {
                while (viewCursor < log.size) {
                    val e = log[viewCursor++]
                    try {
                        view!!.processMessage(e.bytes)
                    } catch (t: Throwable) {
                        fail("PublicGroup refused log[${viewCursor - 1}] ${e.what}: $t")
                    }
                }
            }
        }

        fun catchUp(m: Member) {
            while (!m.removed && m.cursor < log.size) {
                val e = log[m.cursor++]
                val result =
                    try {
                        m.group.processMessage(e.bytes)
                    } catch (t: Throwable) {
                        fail("${m.name} refused log[${m.cursor - 1}] ${e.what}: $t")
                    }
                if (result is ProcessedMessage.AppliedCommit && result.removedSelf) {
                    m.removed = true
                    note("${m.name} sees itself removed")
                }
            }
        }

        /** Stage a commit on [m] after [prepare], publish it and let [m] merge it from the log. Returns the result, or null if [m] refused. */
        fun commit(
            m: Member,
            what: String,
            prepare: (MlsGroup) -> Unit = {},
        ): com.vitorpamplona.mls.messages.CommitResult? {
            val before = m.group.epochAuthenticator.toHexKey()
            return try {
                prepare(m.group)
                val result = m.group.stageCommit()
                publish(result.framedCommitBytes, m.group.epoch, "$what by ${m.name}")
                catchUp(m)
                committed(m, result)
                result
            } catch (e: IllegalArgumentException) {
                refused(m, what, e, before)
            } catch (e: IllegalStateException) {
                refused(m, what, e, before)
            }
        }

        /** After [m] merged [result]: who left the tree, and who the Welcome lets in. */
        fun committed(
            m: Member,
            result: com.vitorpamplona.mls.messages.CommitResult,
        ) {
            val inTree =
                m.group
                    .members()
                    .map { (it.second.credential as Credential.Basic).identity.decodeToString() }
                    .toSet()
            for (other in members) {
                if (!other.removed && !other.evicted && other !== m && other.name !in inTree) {
                    other.evicted = true
                    note("${other.name} is out of the tree")
                }
            }
            val welcome = result.welcomeBytes
            if (welcome != null) {
                for (inv in invitees.toList()) {
                    val joined = runCatching { MlsGroup.processWelcome(welcome, inv.second, policy) }.getOrNull() ?: continue
                    members += Member(inv.first, joined, log.size, joined.epoch)
                    note("${inv.first} joins from the Welcome")
                }
            }
            invitees.clear() // proposals do not outlive their epoch
        }

        fun refused(
            m: Member,
            what: String,
            e: Exception,
            before: String,
        ): Nothing? {
            note("${m.name} refused to $what: ${e.message}")
            if (m.group.epochAuthenticator.toHexKey() != before) fail("${m.name} refused $what but its epoch moved")
            // Proposals staged on the way stay pooled; drop them with a restart-free reset.
            m.group = MlsGroup.restore(MlsGroupState.decodeTls(m.group.saveState().encodeTls()), policy).also { g -> g.clock = m.group.clock }
            return null
        }

        // --- Actions ---

        fun addByWelcome(actor: Member) {
            val name = newName()
            val bundle = keyPackage(name)
            invitees += name to bundle
            commit(actor, "add $name") { it.proposeAdd(bundle.keyPackage.toTlsBytes()) }
        }

        fun remove(actor: Member) {
            val target = active.filter { it !== actor }.random(random)
            commit(actor, "remove ${target.name}") { it.proposeRemove(leafOf(actor, target)) }
        }

        fun leafOf(
            viewer: Member,
            target: Member,
        ): Int =
            viewer.group
                .members()
                .first { (it.second.credential as Credential.Basic).identity.decodeToString() == target.name }
                .first

        fun selfUpdate(actor: Member) {
            if (random.nextBoolean()) commit(actor, "rotate keys") { it.proposeSigningKeyRotation() } else commit(actor, "empty commit")
        }

        fun proposeThenSomeoneCommits(proposer: Member) {
            val proposal =
                try {
                    when (random.nextInt(3)) {
                        0 -> proposer.group.proposalMessage(proposer.group.proposeSigningKeyRotation())
                        1 -> if (active.size > 2) proposer.group.proposalMessage(proposer.group.proposeRemove(leafOf(proposer, active.filter { it !== proposer }.random(random)))) else return
                        else -> if (active.size < 10) proposer.group.proposalMessage(proposer.group.proposeAdd(newName().let { name -> keyPackage(name).also { invitees += name to it } }.keyPackage.toTlsBytes())) else return
                    }
                } catch (e: IllegalArgumentException) {
                    note("${proposer.name} could not propose: ${e.message}")
                    return
                }
            publish(proposal, proposer.group.epoch, "proposal by ${proposer.name}")
            active.filter { it.online }.forEach { catchUp(it) }
            val committer = current.filter { it !== proposer }.randomOrNull(random) ?: return
            commit(committer, "commit pending")
        }

        fun concurrentCommits() {
            val racers = current.shuffled(random).take(2 + random.nextInt(2))
            if (racers.size < 2) return
            val epoch = racers.first().group.epoch
            val staged =
                racers.mapNotNull { m ->
                    val invitee = if (active.size < 9 && random.nextBoolean()) newName().let { it to keyPackage(it) } else null
                    try {
                        invitee?.let { m.group.proposeAdd(it.second.keyPackage.toTlsBytes()) }
                        Triple(m, m.group.stageCommit(), invitee)
                    } catch (e: IllegalArgumentException) {
                        note("${m.name} could not stage: ${e.message}")
                        null
                    }
                }
            if (staged.isEmpty()) return
            val (winner, result, invitee) = staged.random(random)
            note("race at epoch $epoch between ${staged.map { it.first.name }}: ${winner.name} wins")
            publish(result.framedCommitBytes, epoch, "winning commit by ${winner.name}")
            staged.forEach { catchUp(it.first) } // the losers' staged commits are discarded by the winner
            invitee?.let { invitees += it }
            committed(winner, result)
        }

        fun externalJoin(helper: Member) {
            val name = newName()
            val joined =
                try {
                    MlsGroup.externalJoin(helper.group.groupInfoMessage(), name.encodeToByteArray(), policy = policy)
                } catch (e: IllegalArgumentException) {
                    note("external join refused: ${e.message}")
                    return
                }
            publish(joined.framedCommitBytes, joined.group.epoch - 1, "external join of $name")
            members += Member(name, joined.group, log.size, joined.group.epoch)
            invitees.clear()
        }

        fun resync(m: Member) {
            val helper = current.filter { it !== m }.randomOrNull(random) ?: return
            val joined = MlsGroup.externalJoin(helper.group.groupInfoMessage(), m.name.encodeToByteArray(), policy = policy, resyncLeafIndex = m.group.leafIndex)
            publish(joined.framedCommitBytes, joined.group.epoch - 1, "resync of ${m.name}")
            invitees.clear()
            // The member lost its state: everything sent to it before is unreadable now.
            members.remove(m)
            members +=
                Member(m.name, joined.group, log.size, joined.group.epoch).also {
                    it.skew = m.skew
                    applyClock(it)
                }
        }

        fun leave(m: Member) {
            val (request, _) =
                try {
                    m.group.buildSelfRemoveProposalMessage()
                } catch (e: IllegalStateException) {
                    return
                }
            publish(request, m.group.epoch, "${m.name} asks to leave")
            active.filter { it.online }.forEach { catchUp(it) }
            val committer = current.filter { it !== m }.randomOrNull(random) ?: return
            commit(committer, "commit ${m.name}'s leave")
        }

        fun restart(m: Member) {
            val bytes = m.group.saveState().encodeTls()
            m.group = MlsGroup.restore(MlsGroupState.decodeTls(bytes), policy)
            applyClock(m)
            note("${m.name} restarts")
        }

        fun toggleOnline() {
            val m = active.random(random)
            if (m.online && active.count { it.online } > 2) {
                m.online = false
                note("${m.name} goes offline")
            } else if (!m.online) {
                m.online = true
                note("${m.name} comes back online")
                catchUp(m)
            }
        }

        fun skewClock(m: Member) {
            m.skew = random.nextLong(-3 * 86_400L, 30 * 86_400L)
            applyClock(m)
            note("${m.name}'s clock is off by ${m.skew}s")
        }

        // --- Application messages ---

        fun sendMessages() {
            val sender = current.randomOrNull(random) ?: return
            val text = "from ${sender.name} at ${sender.group.epoch} #${random.nextInt()}"
            val bytes = sender.group.encrypt(text.encodeToByteArray(), paddingLength = random.nextInt(3) * 16)
            val msg = AppMessage(bytes, sender.group.epoch, text)
            for (m in active) {
                if (m !== sender && m.joinedAt <= msg.epoch && m.group.epoch >= msg.epoch && random.nextInt(10) != 0) m.inbox += msg
            }
            note("${sender.name} sends at epoch ${msg.epoch}")
        }

        fun deliverSome() {
            for (m in active.filter { it.online }) {
                m.inbox.shuffle(random)
                val now = m.inbox.filter { random.nextBoolean() }
                m.inbox.removeAll(now)
                now.forEach { deliver(m, it) }
            }
        }

        fun deliverAll() =
            active.forEach { m ->
                m.inbox
                    .toList()
                    .forEach { deliver(m, it) }
                    .also { m.inbox.clear() }
            }

        fun deliver(
            m: Member,
            msg: AppMessage,
        ) {
            if (m.removed) return
            val behind = m.group.epoch - msg.epoch
            val text =
                try {
                    when {
                        behind == 0L -> (m.group.processMessage(msg.bytes) as ProcessedMessage.Application).message.content.decodeToString()
                        behind in 1..MlsGroup.RETAIN_EPOCHS.toLong() ->
                            m.group
                                .decryptFormerEpoch(msg.bytes)
                                .content
                                .decodeToString()
                        else -> return // out of the retention window: expected to be unreadable
                    }
                } catch (t: Throwable) {
                    fail("${m.name} at epoch ${m.group.epoch} could not read \"${msg.text}\": $t")
                }
            if (text != msg.text) fail("${m.name} read \"$text\" instead of \"${msg.text}\"")
        }

        // --- Invariants ---

        fun check() {
            val caughtUp = current
            if (caughtUp.isEmpty()) return
            val first = caughtUp.first()
            val names =
                first.group
                    .members()
                    .map { (it.second.credential as Credential.Basic).identity.decodeToString() }
                    .sorted()
            val expected = active.map { it.name }.sorted()
            if (caughtUp.size == active.size && names != expected) fail("members disagree with the simulation: tree has $names, simulation has $expected")
            for (m in caughtUp) {
                if (!m.group.isLocalMember()) fail("${m.name} believes it is not a member")
                if (m.group.epoch != first.group.epoch) fail("${m.name} is at epoch ${m.group.epoch}, ${first.name} at ${first.group.epoch}")
                if (!m.group.epochAuthenticator.contentEquals(first.group.epochAuthenticator)) fail("${m.name} and ${first.name} diverged at epoch ${m.group.epoch}")
                if (!m.group.exportTreeBytes().contentEquals(first.group.exportTreeBytes())) fail("${m.name}'s tree differs from ${first.name}'s")
            }
            view?.let { v ->
                if (v.epoch != first.group.epoch) fail("the PublicGroup is at epoch ${v.epoch}, members at ${first.group.epoch}")
                if (!v.exportTreeBytes().contentEquals(first.group.exportTreeBytes())) fail("the PublicGroup's tree differs from the members'")
            }
        }
    }
}
