# Processing incoming messages

Everything the group sends you, whether application message, proposal or
commit, in either wire format, goes through one call:

<!-- snippet: process-message -->
```kotlin
when (val result = group.processMessage(bytes)) {
    is ProcessedMessage.Application -> show(result.message.content.decodeToString())
    is ProcessedMessage.StagedProposal -> Unit // waits in the pending pool for a commit
    is ProcessedMessage.AppliedCommit -> if (result.removedSelf) show("removed") else show("now at epoch ${result.epoch}")
}
```

What happens for each kind:

- **Application messages** are decrypted and their signature checked.
- **Proposals** are authenticated, checked against the current epoch, and
  kept in the pending pool until a commit includes them.
- **Commits** are checked in full (see [validation](validation.md)) and
  applied all-or-nothing: if anything is wrong, `processMessage` throws and
  the group is exactly as it was.

`removedSelf` means the commit removed you. The group object then only
describes the final state; it cannot send or read anything new.

Your own messages may come back from the delivery service. An echo of your
staged commit merges it, and an echo of your own proposal is recognized,
so you can process everything the server sends without filtering.

## Errors

A message that fails a check throws, mostly `IllegalArgumentException`.
Typical reasons are a message for another epoch, a bad signature, or a
commit your policy refuses. The group is unchanged, so log it and carry on.
Repeated failures to decrypt can be a sign of a [fork](fork-recovery.md).

Next: [Proposals and commits](proposals-and-commits.md).
