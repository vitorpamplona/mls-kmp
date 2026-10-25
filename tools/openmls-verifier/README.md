# openmls-verifier

Checks that what mls-kmp **sends** is accepted by [OpenMLS](https://github.com/openmls/openmls),
the Rust implementation under MDK and White Noise.

`MlsKmpAuthoredVectorsWriter` writes passive-client vectors authored entirely
by mls-kmp — Welcomes, commits of every shape, proposals by reference,
external joins and resyncs, PSKs — in the mlswg `passive-client-*` format.
`run.sh` clones OpenMLS, appends a test that feeds them to OpenMLS's own
passive-client KAT runner, and runs it: OpenMLS joins from our Welcome and
must reach our epoch authenticator after every epoch.

```
MLSKMP_PASSIVE_VECTORS=/tmp/mls-kmp-passive.json \
  ./gradlew :mls:jvmTest --tests com.vitorpamplona.mls.MlsKmpAuthoredVectorsWriter
tools/openmls-verifier/run.sh /tmp/mls-kmp-passive.json
```

Needs `git` and a Rust toolchain. `OPENMLS_TAG` picks the OpenMLS release
(default `v0.9.2`); the first run compiles OpenMLS's test suite and takes a
few minutes. `tools/tsmls-vector-gen/verify-passive-client.mjs` does the same
against ts-mls, and `tools/mlsrs-verifier/run.sh` against mls-rs.
