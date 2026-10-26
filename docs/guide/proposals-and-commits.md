# Proposals and commits

A **proposal** asks for a change: add, remove, update keys, change the
group's extensions, mix in a PSK. A **commit** applies a list of proposals
and starts a new epoch. Commit right away (`addMembers`, `removeMember`),
or send a proposal on its own and let any member commit it later.

## Proposals by reference

<!-- snippet: propose-by-reference -->
```kotlin
val proposal = bob.proposalMessage(bob.proposeSigningKeyRotation())
publish(proposal) // any member may commit it
```

Every member that processes the proposal holds it in its pending pool. The
next `commit()` by any member includes everything pending. The policy's
`authorizeProposal` can refuse a proposal on arrival; `authorizeCommit`
sees the full list before a commit is built or applied.

## Staged commits

Two members can commit in the same epoch, and only one commit can win. The
delivery service decides which. Stage yours, and merge it only once it is
accepted:

<!-- snippet: staged-commit -->
```kotlin
val staged = alice.stageCommit() // built, signed, not applied
val accepted = true // the delivery service took it, and no other commit won the epoch
if (accepted) alice.mergePendingCommit() else alice.clearPendingCommit()
```

Until it is merged, the group stays in the current epoch and keeps reading
messages there. If the server sends your own commit back, processing it
merges it. If someone else's commit wins, process theirs: that discards
yours. A staged commit survives `saveState` and `restore`.

## Custom proposals

An application can define its own proposal types, carried in commits like
the built-in ones:

<!-- snippet: custom-proposal -->
```kotlin
alice.proposeCustom(proposalType = 0xF0F0, data = "pin message 7".encodeToByteArray())
val withCustom = alice.commit()
```

Receivers find it in `AppliedCommit.proposals`, as a `Proposal.Custom`, and
act on it. Every member's leaf must list the type in its capabilities
first: see [capabilities](membership.md#capabilities).

## Wire formats

Proposals and commits can travel as **PublicMessages**, which the server can
read and check (see [PublicGroup](public-group.md)), or as
**PrivateMessages**, which hide even that. The group's policy picks:

<!-- snippet: wire-format-policy -->
```kotlin
val hidden =
    object : MlsGroupPolicy {
        override val wireFormatPolicy = WireFormatPolicy.PURE_CIPHERTEXT
    }
val group = MlsGroup.create("alice".encodeToByteArray(), policy = hidden)
// group.commit() and group.proposalMessage(...) now send PrivateMessages,
// and a member's PublicMessage proposal or commit is refused.
```

The four presets are `PURE_PLAINTEXT`, `PURE_CIPHERTEXT`, `MIXED_PLAINTEXT`
(the default: send public, accept both) and `MIXED_CIPHERTEXT`. Application
messages are always private, and external commits always public, whatever
the policy says.

Next: [Membership changes](membership.md).
