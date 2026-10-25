# Creating a group and adding members

<!-- snippet: create-group -->
```kotlin
val alice = MlsGroup.create(identity = "alice".encodeToByteArray())
```

The creator is the group's only member, at epoch 0. The group id is 32 random
bytes unless you pass `groupId`; it is visible to whoever carries the group's
messages, so it should say nothing.

A group's rules come from its [policy](application-rules.md):
`MlsGroup.create(identity, policy = ourRules)`. With no policy, the group
follows RFC 9420 exactly and any member may commit anything valid.

## Adding members

Add people from their published KeyPackage bytes:

<!-- snippet: add-members -->
```kotlin
val result = alice.addMembers(listOf(bobKeyPackageBytes, carolKeyPackageBytes))
publish(result.framedCommitBytes) // to the members already in the group: none yet
publish(result.welcomeBytes!!) // to bob and carol
```

`addMembers` is a **commit**: the group moves to the next epoch at once. The
result carries two messages. `framedCommitBytes` goes to the members who
were already in the group, and `welcomeBytes` goes to the new ones. Both have
to arrive. A member who misses the commit cannot read anything sent in the
new epoch.

When the delivery service can refuse a commit (because another member's
commit won the epoch), stage it instead and merge only once it is accepted:
see [staged commits](proposals-and-commits.md#staged-commits).

Next: [Joining from a Welcome](joining.md).
