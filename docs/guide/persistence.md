# Persistence

Save the group after every change: each commit you make or process, each
proposal you receive, and each message you send or read.

<!-- snippet: save-state -->
```kotlin
val bytes: ByteArray = alice.saveState().encodeTls() // after every change; encrypt at rest
```

<!-- snippet: restore-state -->
```kotlin
val restored = MlsGroup.restore(MlsGroupState.decodeTls(bytes), policy = MlsGroupPolicy.Permissive)
```

The state holds every secret the member has: its private keys, the epoch's
secrets and those of the epochs it still keeps. Encrypt it at rest, and
overwrite old copies. An old state left on disk undoes forward secrecy, and
restoring one rewinds your sending ratchet, which reuses keys.

The policy is not saved: it is code, not state. Restore with the same
policy the group was created with. A group restored without its policy
silently drops your application's rules.

Pending proposals and a staged commit are part of the state, so they
survive a restart.

Next: [Your application's rules](application-rules.md).
