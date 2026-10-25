# ReInit and branches

Some changes cannot be made to a running group, such as moving to a new
group id or protocol version. RFC 9420 §11 replaces the group with a
**successor** instead, linked to it by a resumption PSK so members can tell
it really continues the old one.

## ReInit

<!-- snippet: reinit -->
```kotlin
alice.proposeReInit(newGroupId = "group-v2".encodeToByteArray())
bob.processMessage(alice.commit().framedCommitBytes) // both groups are now frozen

val bobNext = bob.createKeyPackage("bob".encodeToByteArray(), ByteArray(0))
val successor = alice.reinit(keyPackages = listOf(bobNext.keyPackage.toTlsBytes()))
val bobInNewGroup = MlsGroup.joinSuccessor(successor.commit.welcomeBytes!!, bobNext, predecessor = bob)
```

Once the ReInit is committed, the old group refuses to send. Any member can
then create the successor with everyone else's fresh KeyPackages. Members
join with `joinSuccessor`, which checks that the new group is what the
ReInit asked for.

## Branch

A branch starts a new group with some of the members, and the old group
carries on:

<!-- snippet: branch -->
```kotlin
val daveNext = MlsGroup.createKeyPackage("bob".encodeToByteArray())
val side = carol.branch(keyPackages = listOf(daveNext.keyPackage.toTlsBytes()))
val daveInBranch = MlsGroup.joinSuccessor(side.commit.welcomeBytes!!, daveNext, predecessor = dave)
```

`joinSuccessor` checks that everyone in the branch was a member of the
predecessor.

Next: [Security considerations](security.md).
