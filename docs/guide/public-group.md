# Following a group from a server

A delivery service or relay is not a member, but it can still follow a
group from the PublicMessages members send, and refuse to forward a commit
the members would reject:

<!-- snippet: public-group -->
```kotlin
val view = PublicGroup.fromGroupInfo(groupInfoBytes)
val incoming = bob.commit().framedCommitBytes
val forward =
    try {
        view.processMessage(incoming) // checked as a member would, minus the secrets
        true
    } catch (e: IllegalArgumentException) {
        false // refuse it: the members would too
    }
```

`PublicGroup` starts from a signed GroupInfo, checks it and the whole tree,
then follows proposals, commits and external joins. It runs the same checks
a member does, with your policy, minus the steps that need the epoch's
secrets. It tracks the members, the tree (`exportTreeBytes()` serves joiners
whose GroupInfo leaves it out), the extensions and the pending proposals,
and persists with `saveState()` and `PublicGroup.restore`.

## What it cannot check

Without secrets, a view cannot verify:

- the membership tag, which proves a sender was a member (it only checks the
  tag is present);
- the confirmation tag, which binds a commit to the new epoch's keys;
- whether the PSKs a commit names exist;
- anything inside a PrivateMessage.

So a member with a valid signing key can get a commit past the view that
the members then refuse. The view then trails the group; rebuild it from a
fresh GroupInfo. A group whose policy is `PURE_CIPHERTEXT` cannot be
followed at all, which is the point of that policy.

Next: [Fork recovery](fork-recovery.md).
