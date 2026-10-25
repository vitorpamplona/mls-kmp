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

import com.vitorpamplona.mls.messages.CommitResult
import com.vitorpamplona.mls.schedule.SecretTree
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode

/**
 * The application's rules about who in a group may do what.
 *
 * RFC 9420 says who may *send* a proposal and never who may *commit* one:
 * beyond the protocol's own validity checks, any member may commit anything.
 * Real deployments need more than that — Marmot's MIP-03 names a set of admin
 * accounts and allows everyone else only a self-Update or a SelfRemove — but
 * that is the application's rule, not the protocol's, and an engine with one
 * binding's rules compiled into it cannot host a second binding.
 *
 * Every hook defaults to permissive, and that direction is deliberate. A
 * policy defaulting to closed would make the engine unusable without one and
 * would tempt callers into a "policy that allows everything" anyway; defaulting
 * to open puts each restriction in the binding that actually documents it.
 *
 * The cost of that choice is that a group built or restored without its policy
 * silently drops the binding's rules. A policy is behaviour, not state, so it
 * is **not** carried in [MlsGroupState] — whatever restores a group has to
 * supply the same policy it was created with. For Marmot that is
 * `MlsGroupManager`, which is the only thing that restores a group in order to
 * commit with it.
 */
public interface MlsGroupPolicy {
    /**
     * Rejects, by throwing, a commit the application does not allow.
     *
     * Called for both directions — before building a local commit and before
     * applying an inbound one — with [committerLeafIndex] identifying whose
     * commit it is. Returning normally means "allowed"; the engine's own RFC
     * 9420 validation runs regardless and is not something a policy can waive.
     */
    public fun authorizeCommit(
        group: GroupView,
        proposals: List<PendingProposal>,
        committerLeafIndex: Int,
    ): Unit = Unit

    /**
     * Rejects, by throwing, a SelfRemove the local member is not allowed to
     * issue.
     *
     * Separate from [authorizeCommit] because it gates a *proposal* at its
     * sender rather than a commit: Marmot requires an admin to first
     * self-demote through a GroupContextExtensions proposal, and catching that
     * locally is the difference between a clear error here and a commit every
     * peer silently refuses.
     */
    public fun authorizeSelfRemove(group: GroupView): Unit = Unit

    /**
     * Rejects, by throwing, a group this client should not finish joining.
     *
     * Runs once the Welcome has been processed far enough to see the group's
     * extensions and tree, so a policy can enforce requirements MLS itself
     * cannot carry — a component that demands leaf capabilities outside
     * `required_capabilities`, for instance. Failing here beats joining a group
     * whose every commit peers would reject.
     */
    public fun validateJoin(group: GroupView): Unit = Unit

    /**
     * Rejects, by throwing, a standalone proposal this member should not hold.
     *
     * Called when a proposal arrives on its own (by reference, RFC 9420
     * §12.1), after the engine has authenticated it and checked it is valid.
     * Whatever is accepted waits in the pending pool, and [MlsGroup.commit]
     * commits the whole pool — so this is where a binding keeps, say, a
     * non-admin's Add out of an admin's next commit. Inline proposals never
     * reach this hook; they are judged as part of their commit by
     * [authorizeCommit].
     */
    public fun authorizeProposal(
        group: GroupView,
        proposal: PendingProposal,
    ): Unit = Unit

    /**
     * Rejects, by throwing, a credential the application does not accept as
     * the holder of [signatureKey] (RFC 9420 §5.3.1).
     *
     * MLS authenticates members only as far as their credentials do, and the
     * protocol itself cannot tell whether a credential is genuine: that is the
     * Authentication Service's job. Called for every LeafNode the engine
     * validates — in KeyPackages, Updates, UpdatePaths and a joined tree.
     */
    public fun validateCredential(
        credential: Credential,
        signatureKey: ByteArray,
    ): Unit = Unit

    /**
     * Rejects, by throwing, [next] as the successor of [previous] when a
     * member replaces its leaf — an Update, its own UpdatePath, or an external
     * resync (RFC 9420 §5.3.1: the new credential must present identifiers
     * that are valid successors of the old ones).
     *
     * The default keeps the credential type and, for a BasicCredential, the
     * identity: a member may rotate keys, not become someone else. A binding
     * whose identities legitimately change overrides it.
     */
    public fun validateCredentialSuccession(
        previous: Credential,
        next: Credential,
    ) {
        require(previous.credentialType == next.credentialType) { "A member cannot change its credential type" }
        if (previous is Credential.Basic) require(previous == next) { "A member cannot change its BasicCredential identity" }
    }

    /**
     * Rejects, by throwing, an external commit (RFC 9420 §12.4.3.2): a
     * non-member adding itself, or a member re-joining in place of [resynced].
     *
     * Anyone holding the group's GroupInfo can build one, so a group that
     * publishes its GroupInfo only to some may still want to refuse others.
     * [joiner] is the LeafNode the commit puts in the tree.
     */
    public fun authorizeExternalCommit(
        group: GroupView,
        joiner: LeafNode,
        resynced: LeafNode?,
    ): Unit = Unit

    /**
     * Leaf capabilities a new leaf advertises when the caller names none.
     *
     * Empty by default: RFC 9420 §7.2 forbids advertising the DEFAULT
     * extension and proposal types, so a group that requires nothing beyond
     * them needs nothing here.
     */
    public val defaultLeafCapabilities: Capabilities get() = Capabilities()

    /**
     * The epoch-0 `required_capabilities` extension when the caller names none.
     *
     * Null means the group carries no such extension at all, which is the RFC
     * 9420 default — requirements only ever restrict which leaves may join, so
     * a binding that needs one says so.
     */
    public val defaultRequiredCapabilities: Extension? get() = null

    /**
     * How this binding derives the pre-commit exporter secret a [CommitResult]
     * carries, or null if it seals nothing outside MLS.
     *
     * A binding that wraps MLS messages in its own encryption needs a key both
     * the committer and the members still at epoch N can derive, and RFC 9420
     * gives it one through `MLS-Exporter` — but the label is the application's,
     * and `"marmot"` was hardcoded here. Null yields the empty secret that
     * [CommitResult] already defaults to.
     */
    public val commitExporter: MlsExporterLabel? get() = null

    /**
     * Extension types this binding's own members are known to support, even
     * when an older member's leaf does not advertise them.
     *
     * RFC 9420 §13.4 makes every GroupContext extension mandatory for every
     * member, and the engine enforces that from leaf capabilities. A binding
     * whose own group-metadata extension predates it advertising that type has
     * groups in the wild that would fail the check; listing the type here is
     * how such a binding keeps them working, and it is the binding's statement
     * about its own members - not a licence to skip the rule for types nobody
     * declared.
     */
    public val knownExtensionTypes: Set<Int> get() = emptySet()

    /**
     * How many generations one message may move a sender's ratchet forward
     * (see [SecretTree]). A member that falls further behind than this within
     * one epoch cannot read that sender's next message there.
     */
    public val maxForwardRatchetDistance: Int get() = SecretTree.DEFAULT_MAX_FORWARD_DISTANCE

    /**
     * Whether leaves this engine builds advertise GREASE values in their
     * capabilities (RFC 9420 §13.5 says they SHOULD). Turn off only for a
     * peer that wrongly rejects values it does not know.
     */
    public val greaseCapabilities: Boolean get() = true

    /** How many skipped generations' keys are kept for messages that arrive out of order. */
    public val outOfOrderTolerance: Int get() = SecretTree.DEFAULT_OUT_OF_ORDER_TOLERANCE

    /**
     * Which wire format members' proposals and commits travel in (RFC 9420
     * §6). The default sends PublicMessages and accepts both; a group that
     * hides its handshake from the delivery service uses
     * [WireFormatPolicy.PURE_CIPHERTEXT].
     */
    public val wireFormatPolicy: WireFormatPolicy get() = WireFormatPolicy.MIXED_PLAINTEXT

    /**
     * The largest message, Welcome, GroupInfo or ratchet tree accepted, in
     * bytes, checked before anything is decoded. Lengths inside a message are
     * already bounded by the message itself; this bounds the message. The
     * default fits the ratchet tree of a group of some 80,000 members.
     */
    public val maxMessageSize: Int get() = DEFAULT_MAX_MESSAGE_SIZE

    public companion object {
        /** RFC 9420 exactly as written: any member may commit anything valid. */
        public val Permissive: MlsGroupPolicy = object : MlsGroupPolicy {}

        /** 16 MiB: see [maxMessageSize]. */
        public const val DEFAULT_MAX_MESSAGE_SIZE: Int = 16 * 1024 * 1024
    }
}

/**
 * The read-only slice of a group that a policy decision may look at.
 *
 * A projection rather than the [MlsGroup] itself. A policy handed the group
 * could commit, rotate keys, or mutate epoch state from inside the very check
 * meant to gate those things; passing only what a decision needs makes that
 * impossible to write by accident. The accessors are functions rather than
 * materialised collections so that a policy which inspects one leaf does not
 * pay for walking the whole tree.
 */
public class GroupView(
    /**
     * GroupContext extensions as they stand *before* the commit under
     * consideration applies. A commit that replaces them carries the
     * replacement in its own GroupContextExtensions proposal, which the policy
     * reads from the proposal list.
     */
    public val extensions: List<Extension>,
    /** Leaf count of the ratchet tree, counting blank leaves. */
    public val leafCount: Int,
    /** The local member's leaf index. */
    public val myLeafIndex: Int,
    private val identityAt: (Int) -> String?,
    private val capabilitiesAt: (Int) -> Capabilities?,
) {
    /** Lowercase hex of the BasicCredential identity at [leafIndex], or null if blank. */
    public fun memberIdentityHex(leafIndex: Int): String? = identityAt(leafIndex)

    /** Capabilities advertised by the leaf at [leafIndex], or null if blank. */
    public fun leafCapabilities(leafIndex: Int): Capabilities? = capabilitiesAt(leafIndex)
}

/**
 * The three inputs to `MLS-Exporter` (RFC 9420 §8.5) that identify one
 * application's key derivation.
 *
 * Not a data class: [context] is a ByteArray, whose `equals` is identity, so
 * generated equality would quietly be wrong.
 */
public class MlsExporterLabel(
    public val label: String,
    public val context: ByteArray,
    public val length: Int,
)
