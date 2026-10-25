# mlsrs-verifier

Checks that what mls-kmp **sends** is accepted by [mls-rs](https://github.com/awslabs/mls-rs),
the AWS Labs Rust implementation. It is the third receiver, after ts-mls and
OpenMLS.

`MlsKmpAuthoredVectorsWriter` writes passive-client vectors authored entirely
by mls-kmp in the mlswg `passive-client-*` format. `run.sh` clones mls-rs,
appends a test that replays them the way mls-rs's own `interop_passive_client`
KAT replays the mlswg files, and runs it. mls-rs joins from our Welcome and
must reach our epoch authenticator after every epoch.

```
MLSKMP_PASSIVE_VECTORS=/tmp/mls-kmp-passive.json \
  ./gradlew :mls:jvmTest --rerun --tests com.vitorpamplona.mls.MlsKmpAuthoredVectorsWriter
tools/mlsrs-verifier/run.sh /tmp/mls-kmp-passive.json
```

Needs `git` and a Rust toolchain. `MLSRS_TAG` picks the mls-rs release
(default `0.56.0`). The first run compiles mls-rs's test suite and takes a few
minutes.
