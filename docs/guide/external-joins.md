# Joining by external commit

A Welcome needs a member to add you. An **external commit** lets you add
yourself, from a GroupInfo the group published:

<!-- snippet: group-info -->
```kotlin
val groupInfoBytes = alice.groupInfoMessage() // signed; carries the tree and external_pub
publish(groupInfoBytes)
```

The GroupInfo is signed by the member who made it. It carries the tree and
the group's `external_pub` key, and anyone holding it can join, so publish
it only where joining is allowed. A group can still refuse a joiner in its
policy's `authorizeExternalCommit`.

<!-- snippet: external-join -->
```kotlin
val joined = MlsGroup.externalJoin(groupInfoBytes, identity = "zara".encodeToByteArray())
val zara = joined.group
publish(joined.framedCommitBytes) // every member processes it
```

The joiner is in the group as soon as `externalJoin` returns. The other
members process `framedCommitBytes` like any commit. Pass `ratchetTree` when
the GroupInfo was made with `groupInfoMessage(includeRatchetTree = false)`.

## Resync

A member who lost its state (a new device, a restore from an old backup) can
rejoin in place of its old leaf:

<!-- snippet: external-resync -->
```kotlin
val again = MlsGroup.externalJoin(alice.groupInfoMessage(), identity = "zara".encodeToByteArray(), resyncLeafIndex = zara.leafIndex)
```

The old leaf is removed in the same commit. The policy's
`validateCredentialSuccession` must accept the new credential as the same
member; by default the BasicCredential identity has to match.

Next: [Application messages](messages.md).
