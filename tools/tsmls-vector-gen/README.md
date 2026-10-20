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
