# interop-client

The client the [mlswg interop test-runner](https://github.com/mlswg/mls-implementations/tree/main/interop)
drives: a gRPC server implementing `MLSClient` (`src/main/proto/mls_client.proto`,
vendored unchanged) over the engine. The runner plays scripted scenarios —
Welcome and external joins, commits by reference and by value, PSKs, ReInit,
branches, external senders — across every pairing of the clients it is given,
and checks that everyone agrees on each epoch.

```bash
./gradlew :interop-client:run --args="-port 50001"

# in mls-implementations/interop, after building test-runner (see its README)
test-runner/test-runner -client localhost:50001 -suite 1 -config configs/welcome_join.json
```

Ciphersuite 1 only. Ignored: `force_path` (mls-kmp always sends a path
except for a SelfRemove-only commit, which the runner never asks for).

`MlsClientServiceTest` replays the runner's scenarios with mls-kmp on every
side through an in-process channel; it runs with the rest of CI
(`./gradlew :interop-client:test`). The nightly `mlswg-interop` job runs the real
test-runner against this client alone and against OpenMLS's `interop_client`.
