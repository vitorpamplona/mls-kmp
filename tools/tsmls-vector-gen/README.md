# tsmls-vector-gen

Node helper that emits MLS interop test vectors from `ts-mls`, the
TypeScript MLS implementation that powers
[marmot-ts](https://github.com/marmot-protocol/marmot-ts) (the Marmot
protocol client that runs in the browser / Node / Bun / Deno).

Produces `mls/src/commonTest/resources/mls/tsmls-welcome.json`, which
`TsMlsWelcomeInteropTest` consumes to prove this engine can parse and
decrypt a Welcome + application messages authored by the TypeScript
side. Together with `mdk-vector-gen` (OpenMLS/Rust, in Amethyst's
`quartz/tools/`) the engine has cross-implementation KATs from two
independent MLS backends.

## Regenerating

```
cd tools/tsmls-vector-gen
npm install --legacy-peer-deps
node generate.mjs > ../../mls/src/commonTest/resources/mls/tsmls-welcome.json
```

The generator uses fresh randomness each run; commit the regenerated
JSON if you change the generator. `ts-mls` returns Ed25519 signature
private keys as PKCS#8-DER envelopes (16-byte header + 32-byte seed);
we strip the header before emitting so the vector's `signature_priv`
field is directly comparable to the one `mdk-vector-gen` produces.

## Replaying mls-kmp's own vectors (sending direction)

`verify-passive-client.mjs` makes ts-mls the passive member of a
passive-client vector. On the mlswg files it checks this runner; on the
vectors mls-kmp authors (`MlsKmpAuthoredVectorsWriter`) it checks that ts-mls
accepts every Welcome, commit and proposal mls-kmp sends:

```
npm install --legacy-peer-deps
MLSKMP_PASSIVE_VECTORS=/tmp/mls-kmp-passive.json \
  ../../gradlew -p ../.. :mls:jvmTest --tests com.vitorpamplona.mls.MlsKmpAuthoredVectorsWriter
node verify-passive-client.mjs /tmp/mls-kmp-passive.json
```

`../openmls-verifier` and `../mlsrs-verifier` do the same against OpenMLS and mls-rs.


## Joining a ts-mls group by external commit

`external-join.mjs` checks mls-kmp against a GroupInfo it did not write.
ts-mls creates two groups and publishes their GroupInfos, one with the
`ratchet_tree` extension and one with the tree out of band. mls-kmp joins
each one by external commit, sends a message, commits a Remove as a
PrivateMessage and sends another message. ts-mls then has to accept all of
it and reach mls-kmp's epoch authenticator:

```
node external-join.mjs fixture /tmp/extjoin-fixture.json
MLSKMP_EXTJOIN_FIXTURE=/tmp/extjoin-fixture.json MLSKMP_EXTJOIN_RESULT=/tmp/extjoin-result.json \
  ../../gradlew -p ../.. :mls:jvmTest --rerun --tests com.vitorpamplona.mls.ExternalJoinFromTsMls
node external-join.mjs verify /tmp/extjoin-fixture.json /tmp/extjoin-result.json
```

`mls/src/commonTest/resources/mls/tsmls-external-join.json` holds a copy of
the GroupInfos without the ts-mls states, so `TsMlsExternalJoinInteropTest`
runs the joining half in every build.

Two ts-mls 2.0.0-rc.10 quirks show up here:

- ts-mls writes `external_pub` as the bare key instead of the `opaque<V>`
  that RFC 9420 §12.4.3.2 specifies. mls-kmp accepts both forms and writes
  the RFC one, as OpenMLS does. 2.0.0-rc.16 still uses the bare key on both
  sides, so ts-mls cannot join a group by external commit when mls-kmp or
  OpenMLS published the GroupInfo.
- A ts-mls member that a commit removes throws instead of reporting
  `removedFromGroup`, because it tries to decrypt the UpdatePath. The
  verifier tolerates exactly that error. Alice, the remaining member, still
  checks the commit. 2.0.0-rc.16 handles this case.
