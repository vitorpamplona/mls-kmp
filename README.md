# MLS for Kotlin Multiplatform

A Messaging Layer Security ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) engine in
pure Kotlin Multiplatform: TLS presentation-language codec, HPKE, X25519/Ed25519, the
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
    implementation("com.vitorpamplona.mls:mls:1.0.0")
}
```

## Using it

```kotlin
val group = MlsGroup.create(identity)                    // a plain RFC 9420 group
val group = MlsGroup.create(identity, policy = myPolicy)  // a binding's profile
```

The default group requires nothing beyond RFC 9420: no `required_capabilities`,
no leaf capabilities (§7.2 forbids advertising DEFAULT types), no commit
exporter, and no limit on who may commit what.

## The `MlsGroupPolicy` seam

RFC 9420 says who may *send* a proposal and never who may *commit* one. Real
deployments need more — Marmot's MIP-03 names admin accounts and allows everyone
else only a self-Update or a SelfRemove — so the engine asks a policy wherever
the spec defers to the application:

| Hook | Called from | Marmot uses it for |
| ---- | ----------- | ------------------ |
| `authorizeCommit` | `commit()` and both inbound commit paths | MIP-03 proposal-set rules + admin depletion |
| `authorizeSelfRemove` | `proposeSelfRemove`, `buildSelfRemoveProposalMessage` | admin must self-demote first |
| `validateJoin` | `processWelcome` | `required_member_roles` on the agent-text-stream component |
| `defaultLeafCapabilities` | every leaf the engine builds | `0xF2EE` + `self_remove` |
| `defaultRequiredCapabilities` | `create()`, epoch 0 | the MIP-era interop set |
| `knownExtensionTypes` | GroupContextExtensions validation | `0xF2EE` |
| `commitExporter` | `CommitResult.preCommitExporterSecret` | `MLS-Exporter("marmot", "group-event", 32)` |

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

## Platform primitives

The library has no runtime dependencies beyond the Kotlin standard library: no
third-party crypto. Ed25519 and X25519 are pure Kotlin on every platform. The rest
sits behind the internal `com.vitorpamplona.mls.platform` package:

| | JVM / Android | Apple | Linux |
| --- | --- | --- | --- |
| SHA-256 | JCA | CommonCrypto | pure Kotlin (`platform/sha2`) |
| SHA-512 (Ed25519) | JCA | pure Kotlin | pure Kotlin |
| HMAC-SHA256 | JCA | CommonCrypto | pure Kotlin (`platform/mac`) |
| AES-128-GCM | JCA | pure Kotlin (`platform/aes`) | pure Kotlin |
| CSPRNG | `SecureRandom` | `SecRandomCopyBytes` | `/dev/urandom` |

The Kotlin AES is a port of BearSSL's constant-time `aes_ct64` (bitsliced, no
secret-indexed tables) with GHASH from `ghash_ctmul64`. CommonCrypto has no public
GCM. These files are kept in sync with Quartz's `utils/sha2`, `utils/mac` and
`utils/ciphers/aes`, where they were written and reviewed.

JS and Wasm are not targets yet: AES-GCM there is only available through the
asynchronous WebCrypto API, and the engine is synchronous.

## Tests

`mls/src/commonTest` runs on every target; `mls/src/jvmAndroidTest` holds the
JVM/Android-only suites. `interop/` replays the RFC 9420 test vectors from
[mls-implementations](https://github.com/mlswg/mls-implementations).
`MdkWelcomeInteropTest` and `TsMlsWelcomeInteropTest` join groups created by
OpenMLS (via MDK) and ts-mls. `group/MlsGroupPolicySeamTest` pins the policy seam
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

## Releasing

Push a `v*` tag. `.github/workflows/create-release.yml` runs the tests and
publishes to Maven Central with the version taken from the tag.
`publishToMavenLocal` works without signing keys for local testing.

## License

MIT. See [LICENSE](LICENSE).
