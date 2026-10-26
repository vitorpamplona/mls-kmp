# MLS for Kotlin Multiplatform

A Messaging Layer Security ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) engine in
pure Kotlin Multiplatform: TLS presentation-language codec, HPKE, the
ratchet tree, the key schedule, the secret tree, message framing, proposals, commits,
Welcome, and the `app_data_dictionary` component carrier from
`draft-ietf-mls-extensions-10`.

It implements ciphersuite `0x0001`
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) and runs on JVM, Android, iOS
(arm64 and simulator), macOS (arm64) and Linux (x64).

It is the engine under [Amethyst](https://github.com/vitorpamplona/amethyst)'s two MLS
bindings, Marmot (MLS over Nostr) and cordn (MLS over an MCP coordinator), both in
Quartz. **It knows nothing about either, nor about Nostr, and must stay that way.**
The library depends on no Nostr code, so a binding cannot leak into it.

## Setup

```kotlin
dependencies {
    implementation("com.vitorpamplona.mls:mls:1.2.0")
}
```

## Using it

**[The guide](docs/guide/README.md)** walks through everything below in order,
from the first KeyPackage to fork recovery, and covers what the library
validates and what your application must. Its examples are compiled and run
as tests. This section is the short version.

```kotlin
val group = MlsGroup.create(identity)                    // a plain RFC 9420 group
val group = MlsGroup.create(identity, policy = myPolicy)  // a binding's profile
```

The default group requires nothing beyond RFC 9420: no `required_capabilities`,
no leaf capabilities (§7.2 forbids advertising DEFAULT types), no commit
exporter, and no limit on who may commit what.

### Messages, proposals and commits

```kotlin
// Any MLSMessage for the group: application data, a proposal or a commit,
// as a PublicMessage or a PrivateMessage.
when (val result = group.processMessage(bytes)) {
    is ProcessedMessage.Application -> show(result.message.content)
    is ProcessedMessage.StagedProposal -> {}   // waits in the pending pool
    is ProcessedMessage.AppliedCommit -> {}    // the group moved to result.epoch
}

// Send a proposal by reference for any member to commit.
val update = group.proposalMessage(group.proposeSigningKeyRotation())

// Commit everything pending. stageCommit() builds the commit without moving
// the group; merge it once the delivery service accepts it, or clear it if
// another commit won the epoch (receiving our own commit back also merges it).
val staged = group.stageCommit(wireFormat = WireFormat.PRIVATE_MESSAGE)
group.mergePendingCommit()   // or group.clearPendingCommit()
```

`commit()` is `stageCommit()` + `mergePendingCommit()`. Whichever is used, a
commit is all-or-nothing: if building or applying one fails, the group is left
exactly as it was.

Standalone proposals are accepted from members, from the group's
`external_senders` and from a new member proposing its own Add, after the
RFC 9420 §12.1 checks. Everything accepted waits in the pending pool and goes
into this member's next `commit()`, so a binding that must keep, say, a
non-admin's Add out of an admin's commit restricts it in
`MlsGroupPolicy.authorizeProposal`.

### Joining

```kotlin
MlsGroup.processWelcome(welcome, bundle,
    ratchetTree = treeBytes,              // when the GroupInfo carries no ratchet_tree
    psks = { id -> lookUp(id) })          // PSKs the Welcome names
MlsGroup.externalJoin(groupInfo, identity,
    ratchetTree = treeBytes,              // likewise
    resyncLeafIndex = myOldLeaf)          // a resync replaces our old leaf
```

`groupInfoMessage()` publishes the GroupInfo as an MLSMessage for external
joiners; `commit(includeRatchetTreeInWelcome = false)` leaves the tree out of
Welcomes for applications that deliver it separately. `stageWelcome` does
everything `processWelcome` does but lets you inspect the group before
`join()`.

### More

- `MlsGroupPolicy.wireFormatPolicy` sends handshakes as PublicMessages or
  PrivateMessages and refuses the other kind
  ([guide](docs/guide/proposals-and-commits.md#wire-formats)).
- `PublicGroup` follows a group from a server, from its GroupInfo and
  PublicMessages, without being a member ([guide](docs/guide/public-group.md)).
- `recoverForkByReadding` and `reboot` repair a forked group
  ([guide](docs/guide/fork-recovery.md)).

### ReInit and branches

```kotlin
group.proposeReInit(newGroupId = id, newExtensions = exts); group.commit()
val next = group.reinit(otherMembersKeyPackages)       // RFC 9420 §11.2
val sub  = group.branch(someMembersKeyPackages)         // RFC 9420 §11.3
MlsGroup.joinSuccessor(next.commit.welcomeBytes!!, myNewBundle, predecessor = group)
```

The successor's first commit carries the predecessor's resumption PSK, and
`joinSuccessor` checks that the new group is what the ReInit asked for (or,
for a branch, only holds members of the predecessor).

### Validation

Every LeafNode, KeyPackage, proposal list, UpdatePath and joined tree is held
to RFC 9420 §7.3, §10.1, §12.2, §12.4.2 and §12.4.3.1, by the committer
before sending and by every receiver before applying. The credential itself
is the application's to judge (the Authentication Service): implement
`MlsGroupPolicy.validateCredential`.

## The `MlsGroupPolicy` seam

RFC 9420 says who may *send* a proposal and never who may *commit* one. Real
deployments need more — Marmot's MIP-03 names admin accounts and allows everyone
else only a self-Update or a SelfRemove — so the engine asks a policy wherever
the spec defers to the application:

| Hook | Called from | Marmot uses it for |
| ---- | ----------- | ------------------ |
| `authorizeCommit` | `commit()` and both inbound commit paths | MIP-03 proposal-set rules + admin depletion |
| `authorizeSelfRemove` | `proposeSelfRemove`, `buildSelfRemoveProposalMessage` | admin must self-demote first |
| `authorizeProposal` | every standalone proposal received | — |
| `authorizeExternalCommit` | every inbound external commit | — |
| `validateCredential` | every LeafNode validated | — |
| `validateCredentialSuccession` | every replaced leaf (Update, UpdatePath, resync) | — (default: same type and Basic identity) |
| `validateJoin` | `processWelcome`, `stageWelcome` | `required_member_roles` on the agent-text-stream component |
| `defaultLeafCapabilities` | every leaf the engine builds | `0xF2EE` + `self_remove` |
| `defaultRequiredCapabilities` | `create()`, epoch 0 | the MIP-era interop set |
| `knownExtensionTypes` | GroupContextExtensions validation | `0xF2EE` |
| `commitExporter` | `CommitResult.preCommitExporterSecret` | `MLS-Exporter("marmot", "group-event", 32)` |
| `wireFormatPolicy` | the default wire format of commits and proposals; every member's inbound handshake | — (default: send public, accept both) |

Three things to know before you add a binding:

1. **One argument selects a whole profile.** `policy` supplies the rules *and*
   the capability defaults *and* the exporter binding, so `capabilities` and
   `requiredCapabilities` default from it. Adopting a profile is one argument,
   not five.

2. **A policy is behaviour, not state.** It is deliberately absent from
   `MlsGroupState`, so whatever restores a group must pass the same policy it
   was created with. A restore that forgets it gets a group that silently skips
   the binding's rules.

3. **A policy gets a `GroupView`, not the `MlsGroup`.** A policy holding the
   group could commit or rotate keys from inside the check meant to gate exactly
   that.

The default is permissive rather than closed. Closed would make the engine
unusable without a policy and would push callers into writing an
allow-everything one anyway; open puts each restriction in the binding that
documents it. The cost is item 2 above.

## `@InternalMlsApi`

A handful of engine internals (the lifetime clock, the staged-proposal pool, the
PSK secret, the `required_capabilities` checks, the join-time parent-hash
verifier) are public only so the bindings' own test suites can reach them. They
require `@OptIn(InternalMlsApi::class)` and are not a stable API.

## Upgrading

See [docs/guide/upgrading.md](docs/guide/upgrading.md): what changed on the
wire since 1.2, and the APIs added since.

## Crypto

Every primitive comes from [crypto-kmp](https://github.com/vitorpamplona/crypto-kmp)
(`com.vitorpamplona.crypto:crypto`): SHA-256, HMAC-SHA256 and HKDF, AES-128-GCM,
X25519, Ed25519 and the secure random source. It is an `api` dependency because
`MlsGroup` takes its `Ed25519KeyPair`. crypto-kmp uses JCA on the JVM and Android,
CommonCrypto on Apple where it has the primitive, and constant-time pure Kotlin
elsewhere, and depends on nothing but the Kotlin stdlib. So does this library,
apart from crypto-kmp.

JS and Wasm are not targets yet. The engine is synchronous and WebCrypto's
ciphers are async-only, but crypto-kmp 2.1 brings synchronous, constant-time
Kotlin primitives to both, so nothing in the crypto layer stands in the way
any more.

## Tests

`mls/src/commonTest` runs on every target; `mls/src/jvmAndroidTest` holds the
JVM/Android-only suites. `interop/` replays the RFC 9420 test vectors from
[mls-implementations](https://github.com/mlswg/mls-implementations) — the
passive-client vectors end to end through `MlsGroup` (joining, every commit
shape, a 200-epoch random run), plus TreeKEM, message protection, tree
validation, PSK secrets and the rest.

The other direction is covered too: `MlsKmpAuthoredVectors` has mls-kmp
members run a group through every epoch change — commits of every shape,
proposals by reference, external joins and resyncs, PSKs, ReInit and branch
successors — and records it as passive-client vectors, which ts-mls
(`tools/tsmls-vector-gen/verify-passive-client.mjs`), OpenMLS
(`tools/openmls-verifier/run.sh`) and mls-rs (`tools/mlsrs-verifier/run.sh`)
must follow epoch by epoch. CI runs all three, and also has mls-kmp join
ts-mls groups by external commit from ts-mls GroupInfos
(`tools/tsmls-vector-gen/external-join.mjs`), with ts-mls then following
mls-kmp's commits and messages.
Live interop goes through the mlswg test-runner: `interop-client/` is the gRPC
client it drives, and the nightly runs it alone and against OpenMLS's
([interop-client/README.md](interop-client/README.md)). CI also has mls-rs
write fresh passive-client vectors and mls-kmp replay them
(`ForeignPassiveClientVectorsTest`).
`MdkWelcomeInteropTest` and `TsMlsWelcomeInteropTest` join groups created by
OpenMLS (via MDK) and ts-mls, and `TsMlsExternalJoinInteropTest` joins
ts-mls groups by external commit. `group/MlsGroupPolicySeamTest` pins the policy seam
itself with a recording policy.

```bash
./gradlew jvmTest                  # JVM
./gradlew testAndroidHostTest      # Android, on the host JVM
./gradlew linuxX64Test             # Linux native
./gradlew iosSimulatorArm64Test    # iOS (macOS host)
```

Vector generators: `tools/tsmls-vector-gen` (ts-mls) here; the OpenMLS one is
Amethyst's `quartz/tools/mdk-vector-gen`, because it shares an MDK pin with
Marmot's vectors.

### Working on it together with Amethyst

Amethyst consumes the published artifact. To build Amethyst against a local
checkout instead, point it at this directory:

```bash
./gradlew -PmlsKmpDir=../mls-kmp :quartz:jvmTest
```

## Public API and persisted formats

The library is built in explicit-API mode, and its public ABI is dumped to
`mls/api/`. CI's `checkKotlinAbi` fails when the API changes without the dump
changing too, so every API change shows up as a diff in review: run
`./gradlew updateKotlinAbi` and commit the result.

Saved group states (`MlsGroupState`, v1 to v10) and KeyPackage bundles
(`KeyPackageBundleCodec` v1) are frozen in
`mls/src/commonTest/resources/mls/persisted-formats.json`.
`PersistedFormatsTest` restores every one of them and keeps using it. A new
layout version adds an entry (`PersistedFormatFixtureWriter`); the old entries
never change.

## Releasing

Push a `v*` tag. `.github/workflows/create-release.yml` runs the tests and
publishes to Maven Central with the version taken from the tag.
`publishToMavenLocal` works without signing keys for local testing.

## License

MIT. See [LICENSE](LICENSE).
