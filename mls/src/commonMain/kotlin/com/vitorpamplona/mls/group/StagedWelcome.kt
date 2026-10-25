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
package com.vitorpamplona.mls.group

import com.vitorpamplona.mls.messages.PreSharedKeyId
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode

/**
 * A Welcome that decrypted and passed every check, but not yet joined.
 *
 * [MlsGroup.stageWelcome] does all of [MlsGroup.processWelcome]'s work — the
 * GroupInfo signature, the whole-tree validation of RFC 9420 §12.4.3.1, the
 * confirmation tag, [MlsGroupPolicy.validateJoin] — and then stops, so the
 * application can look at the group before it becomes a member: who is in
 * it, who invited us, what its extensions require. [join] hands over the
 * group; dropping the StagedWelcome declines it, and nothing was sent either
 * way. A Welcome needs no reply, so declining is invisible to the group
 * until a member notices our leaf never speaks; a member who should not be
 * there is removed by a commit, like any other.
 */
public class StagedWelcome internal constructor(
    private val group: MlsGroup,
    /** The leaf of the member whose commit added us: it signed the GroupInfo. */
    public val welcomerLeafIndex: Int,
    /** The PSKs the Welcome folded into the epoch, in order. */
    public val psks: List<PreSharedKeyId>,
) {
    private var joined = false

    public val groupId: ByteArray get() = group.groupId.copyOf()

    public val epoch: Long get() = group.epoch

    /** Our own leaf in the group. */
    public val leafIndex: Int get() = group.leafIndex

    /** The GroupContext extensions: what the group requires of its members. */
    public val extensions: List<Extension> get() = group.groupContextExtensionsSnapshot()

    /** The occupied leaves, ours included, by leaf index. */
    public fun members(): List<Pair<Int, LeafNode>> = group.members()

    /** The leaf of the member who added us. */
    public val welcomer: LeafNode get() = members().first { it.first == welcomerLeafIndex }.second

    /** Become a member. Once only: the group this returns is the one live copy. */
    public fun join(): MlsGroup {
        check(!joined) { "This Welcome was already joined" }
        joined = true
        return group
    }
}
