# Fork recovery

A group **forks** when its members merge different commits for the same
epoch, through a bug or a delivery service that let two commits through.
From then on each side holds keys the other cannot use, and messages
across the split fail to decrypt. MLS cannot merge the sides back. Instead,
one side rebuilds the group around itself. mls-kmp has two helpers for
that, after OpenMLS's.

## Re-adding the other side

When you know who merged the same commit you did, remove everyone else and
add them back from fresh KeyPackages, in one commit:

<!-- snippet: fork-readd -->
```kotlin
val ourSide = listOf(alice.leafIndex, charlie.leafIndex) // who merged the same commit we did
val stranded = alice.forkComplement(ourSide) // [bob]
val repair = alice.recoverForkByReadding(ourSide, keyPackages = listOf(freshBobBytes))
```

Your side processes the commit; the re-added members join from its Welcome
with `processWelcome`. This is cheap, but only as good as your knowledge of
the partition.

## Rebooting the group

When you do not know the partition, start over: a new group with the same
extensions, inviting everyone else.

<!-- snippet: fork-reboot -->
```kotlin
val others = alice.rebootMembers() // everyone to re-invite
val rebooted = alice.reboot(keyPackages = keyPackagesForEveryoneElse.map { it.keyPackage.toTlsBytes() })
publish(rebooted.commit.welcomeBytes!!) // they join with processWelcome
```

Everyone joins with `processWelcome`. Pass `extensions` when the old ones
name the old group. Unlike a [branch](successor-groups.md), a reboot has no
resumption PSK tying it to the old group, because forked members could not
supply it.

## Detecting a fork

Neither helper detects a fork. Messages that repeatedly fail to decrypt are
a hint, but also happen for other reasons. A reliable signal: after merging
a commit, each member reports the new `epochAuthenticator` (it is safe to
share within the group), and members compare. Two different authenticators
for one epoch mean the group forked, and tell you who is on which side.

Next: [ReInit and branches](successor-groups.md).
