# Membership changes

## Removing a member

<!-- snippet: remove-member -->
```kotlin
val removal = alice.removeMember(targetLeafIndex = carolGroup.leafIndex)
publish(removal.framedCommitBytes)
```

The removed member processes the same commit and gets
`AppliedCommit.removedSelf == true`. Leaf indexes are stable, but a removed
member's leaf may be reused by the next member added.

## Updating your keys

Updating replaces your leaf's keys, which is how a member recovers from a
compromise. Do it periodically:

<!-- snippet: update-keys -->
```kotlin
bob.proposeSigningKeyRotation() // a fresh leaf: new encryption and signature keys
val update = bob.commit()
```

Any commit you make carries a fresh path of keys anyway, so an active
member's keys turn over on their own.

## Leaving

A member cannot commit its own removal. It asks, and another member commits
the request:

<!-- snippet: leave -->
```kotlin
val (leaveRequest, _) = bob.buildSelfRemoveProposalMessage()
publish(leaveRequest) // another member commits it
```

This is the SelfRemove proposal from `draft-ietf-mls-extensions`. Like every
proposal type beyond RFC 9420's own, the group can only use it once all
members support it.

## Capabilities

Each leaf lists the proposal types, extensions and credentials its client
understands. A commit using a type that some member does not list is
refused, by the committer and by every receiver. Declare what your
application uses in its policy, and every leaf the engine builds for it
(KeyPackages, the creator's leaf, external joins) lists it:

<!-- snippet: capabilities -->
```kotlin
object WithSelfRemoveAndPins : MlsGroupPolicy {
    // A proposal type beyond RFC 9420's own can only be committed once every
    // member's leaf lists it; the policy's default leaf capabilities do that.
    override val defaultLeafCapabilities = Capabilities(proposals = listOf(ProposalType.SELF_REMOVE.value, 0xF0F0))
}
```

The group's `required_capabilities` extension goes further: it makes
listing them a condition of joining.

Next: [Persistence](persistence.md).
