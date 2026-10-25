# Joining from a Welcome

The member a commit added receives its Welcome and joins with the bundle
from [its KeyPackage](key-packages.md):

<!-- snippet: join-welcome -->
```kotlin
val bob = MlsGroup.processWelcome(welcomeBytes, bundle)
```

`processWelcome` decrypts the group secrets, checks the GroupInfo signature,
validates the whole ratchet tree (RFC 9420 §12.4.3.1) and the confirmation
tag, and runs your policy's `validateJoin`. If any of that fails it throws,
and you are not in the group.

## Look before you join

`stageWelcome` does the same work and stops just before joining, so you can
see who is in the group and who invited you:

<!-- snippet: stage-welcome -->
```kotlin
val staged = MlsGroup.stageWelcome(secondWelcome, carolBundle)
val inviter = (staged.welcomer.credential as Credential.Basic).identity.decodeToString()
val everyone = staged.members().map { (_, leaf) -> (leaf.credential as Credential.Basic).identity.decodeToString() }
val carol = if (inviter == "alice" && "mallory" !in everyone) staged.join() else null
```

`join()` hands over the group, once. Declining is just not calling it:
nothing was sent, so nothing needs undoing. `StagedWelcome` also shows the
group's extensions, its epoch, and any PSKs the Welcome used.

## When the Welcome carries no tree

The ratchet tree can be large, so a group may leave it out of the Welcome
and deliver it separately:

<!-- snippet: welcome-without-tree -->
```kotlin
alice.proposeAdd(daveBundle.keyPackage.toTlsBytes())
val commit = alice.commit(includeRatchetTreeInWelcome = false)
val treeBytes = alice.exportTreeBytes() // deliver it some other way
val dave = MlsGroup.processWelcome(commit.welcomeBytes!!, daveBundle, ratchetTree = treeBytes)
```

The tree is checked against the hash the GroupInfo signs, so it can come
from anywhere, even an untrusted server.

## PSKs

A Welcome can name pre-shared keys the group mixed into the epoch. Pass a
`psks` lookup to `processWelcome` or `stageWelcome`; the join fails if a
named PSK is missing.

Next: [Joining by external commit](external-joins.md).
