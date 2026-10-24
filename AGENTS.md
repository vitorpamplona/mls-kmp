# mls-kmp

An RFC 9420 Messaging Layer Security engine in pure Kotlin Multiplatform (JVM, Android, iOS, macOS,
Linux), published to Maven Central as `com.vitorpamplona.mls:mls`. It is the engine under the two
MLS bindings [Amethyst](https://github.com/vitorpamplona/amethyst) uses, each in its own repo:
[marmot-kmp](https://github.com/vitorpamplona/marmot-kmp) (MLS over Nostr) and
[cordn-kmp](https://github.com/vitorpamplona/cordn-kmp) (MLS over an MCP coordinator). It started in
Quartz's `mls` package and moved here so the engine has no Nostr in it.

## Layout

- `mls/src/commonMain/kotlin/com/vitorpamplona/mls/`: `codec` (TLS presentation language),
  `crypto` (HPKE and the ciphersuite over crypto-kmp), `tree` (ratchet tree), `schedule` (key
  schedule, secret tree), `framing`, `messages`, `group` (`MlsGroup`, `MlsGroupPolicy`, `GroupView`),
  `components` (`app_data_dictionary`), `platform`, and `InternalMlsApi`.
- Tests: `commonTest` (every target), `jvmAndroidTest` (the RFC vectors from mls-implementations,
  `MdkWelcomeInteropTest`, `TsMlsWelcomeInteropTest`), `nativeTest`. Vectors are in
  `mls/src/commonTest/resources/mls/`.
- `tools/tsmls-vector-gen`: the ts-mls vector generator. The OpenMLS (MDK) one is marmot-kmp's
  `marmot/tools/mdk-vector-gen`, because it shares an MDK pin with Marmot's vectors.

## Rules

- **No Nostr and no binding.** Nothing here may import Quartz, marmot-kmp or cordn-kmp, or name a
  Marmot or cordn concept. Where RFC 9420 defers to the application, the engine asks an
  `MlsGroupPolicy`; a binding's rules (admins, required capabilities, exporter labels) live in the
  binding's repo as a policy, never as a branch here.
- **Crypto comes from crypto-kmp** (`com.vitorpamplona.crypto`), an `api` dependency. Don't add a
  primitive here; add it there. No other runtime dependency beyond the Kotlin stdlib.
- **Constant time** for anything touching secrets, and wipe secret temporaries once done.
- Anything public only so the bindings' tests can reach it is `@InternalMlsApi`, not stable API.
- `MlsGroupState`'s serialized bytes are API: the bindings persist them, and a change that the next
  version cannot read is a group a user has lost.
- `commonMain` and `commonTest` stay free of JVM-only APIs: use `kotlin.concurrent.Volatile`, and
  `assertTrue`, not `assert`, in tests.
- JVM target is 17. Releases follow semantic versioning: marmot-kmp, cordn-kmp and Amethyst pin a
  version and must move together on a breaking change.
- Commits: conventional commits (`feat:`, `fix:`, …). Never `--no-verify`.

## Verify, don't guess

Don't assert a diagnosis you haven't reproduced: write the failing case first, watch it fail, then
explain. Interop claims are checked against the vectors, not from memory of the RFC.

## Build and test

```bash
./gradlew installGitHook                 # pre-push runs jvmTest and testAndroidHostTest
./gradlew spotlessApply
./gradlew jvmTest testAndroidHostTest linuxX64Test
./gradlew iosSimulatorArm64Test macosArm64Test   # macOS only
```

To try a change in a binding or in Amethyst, build that repo with `-PmlsKmpDir=../mls-kmp`.

## Dependency licensing

Before adding any dependency, read its actual `LICENSE` file or published POM. This library is MIT
and ships inside apps. Permissive (MIT, Apache-2.0, BSD, ISC, MPL-2.0, zlib): OK. LGPL, or GPL/EPL
with a linking exception: WARN in your summary. Anything stricter: STOP and leave the decision to a
maintainer.

## Releasing

Push a `v<version>` tag: `.github/workflows/create-release.yml` runs the tests and publishes to
Maven Central with the version taken from the tag.
