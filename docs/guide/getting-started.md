# Getting started

```kotlin
dependencies {
    implementation("com.vitorpamplona.mls:mls:1.2.0")
}
```

## What MLS gives you

MLS keeps a group of members, from two to many thousands, agreeing on one
shared secret per **epoch**. Every message is encrypted under the current
epoch's keys, and every change to the group (someone joins, leaves or
rotates keys) starts a new epoch. Two properties follow:

- **Forward secrecy**: keys for past epochs are deleted, so stealing a
  device today does not open last month's messages.
- **Post-compromise security**: once a compromised member updates its keys,
  an attacker who copied the old ones is locked out again.

MLS does not move bytes. Your application carries every message between
members, usually through a server the RFC calls the **delivery service**.
MLS also does not decide who people are: credentials say "this leaf belongs
to alice", and checking that is the job of your **authentication service**
(see [Your application's rules](application-rules.md)).

## The four things you handle

| Object | What it is | Where it goes |
| ------ | ---------- | ------------- |
| `KeyPackageBundle` | A signed, single-use invitation plus its private keys | Publish `keyPackage`; keep the bundle |
| `MlsGroup` | Your member state in one group | Keep it; persist `saveState()` after every change |
| Commit (`CommitResult.framedCommitBytes`) | Moves the group to the next epoch | Send to every member |
| Welcome (`CommitResult.welcomeBytes`) | Lets new members join | Send to the members a commit added |

Everything that travels is a `ByteArray` in the RFC 9420 wire format, so
members can run other MLS implementations: mls-kmp is tested against
OpenMLS, mls-rs and ts-mls.

## Ciphersuite

mls-kmp implements ciphersuite `0x0001`,
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, the one RFC 9420 makes
mandatory. It cannot join a group that uses any other.

Next: [KeyPackages](key-packages.md).
