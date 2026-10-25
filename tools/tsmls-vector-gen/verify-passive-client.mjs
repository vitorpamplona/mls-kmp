// Passive-client verifier: ts-mls replays RFC 9420 passive-client vectors.
//
//   node verify-passive-client.mjs <vectors.json> [<more.json> ...]
//
// The vectors use the mlswg/mls-implementations `passive-client-*` format:
// a KeyPackage with its private keys, a Welcome, optionally an out-of-band
// ratchet tree and external PSKs, then for each epoch the standalone
// proposals, the commit and the epoch authenticator after it.
//
// Run on the official vectors it checks this runner; run on the vectors
// `MlsKmpAuthoredPassiveClientGen` writes it checks that everything mls-kmp
// SENDS — Welcomes, commits of every shape, proposals by reference, external
// commits — is accepted by an independent implementation, epoch by epoch.
//
// Exits 0 when every suite-1 vector passes.

import { readFileSync } from "node:fs";
import {
  bytesToBase64,
  decode,
  defaultCryptoProvider,
  defaultKeyPackageEqualityConfig,
  defaultKeyRetentionConfig,
  defaultPaddingConfig,
  getCiphersuiteImpl,
  joinGroup,
  keyPackageDecoder,
  mlsMessageDecoder,
  processMessage,
  unsafeTestingAuthenticationService,
  wireformats,
} from "ts-mls";
import { ratchetTreeDecoder } from "./node_modules/ts-mls/dist/src/ratchetTree.js";

const hexToBytes = (s) => Uint8Array.from((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// ts-mls keeps Ed25519 private keys as PKCS#8 DER; the vectors carry the raw seed.
const PKCS8_ED25519_PREFIX = hexToBytes("302e020100300506032b657004220420");
const pkcs8 = (seed) => {
  const out = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  out.set(PKCS8_ED25519_PREFIX, 0);
  out.set(seed, PKCS8_ED25519_PREFIX.length);
  return out;
};

const cs = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", defaultCryptoProvider);

// Lifetimes in archived vectors may have lapsed; this checks protocol
// behaviour, not the wall clock.
const lifetimeOff = {
  keyRetentionConfig: defaultKeyRetentionConfig,
  keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
  paddingConfig: defaultPaddingConfig,
  lifetimeConfig: { validateLifetimeOnReceive: false, maximumTotalLifetime: 2n ** 64n - 1n },
};

async function run(v) {
  const externalPsks = {};
  for (const p of v.external_psks ?? []) externalPsks[bytesToBase64(hexToBytes(p.psk_id))] = hexToBytes(p.psk);
  const context = { cipherSuite: cs, authService: unsafeTestingAuthenticationService, externalPsks, clientConfig: lifetimeOff };

  const kpMsg = decode(mlsMessageDecoder, hexToBytes(v.key_package));
  const keyPackage = kpMsg.keyPackage ?? decode(keyPackageDecoder, hexToBytes(v.key_package));
  const privateKeys = {
    initPrivateKey: hexToBytes(v.init_priv),
    hpkePrivateKey: hexToBytes(v.encryption_priv),
    signaturePrivateKey: pkcs8(hexToBytes(v.signature_priv)),
  };
  const welcome = decode(mlsMessageDecoder, hexToBytes(v.welcome));
  if (welcome.wireformat !== wireformats.mls_welcome) return "welcome: not an mls_welcome";
  const ratchetTree = v.ratchet_tree ? decode(ratchetTreeDecoder, hexToBytes(v.ratchet_tree)) : undefined;

  let state;
  try {
    state = await joinGroup({ context, welcome: welcome.welcome, keyPackage, privateKeys, ratchetTree });
  } catch (e) {
    return `welcome: ${e?.message ?? e}`;
  }
  if (toHex(state.keySchedule.epochAuthenticator) !== v.initial_epoch_authenticator) return "initial epoch_authenticator mismatch";

  for (const [i, epoch] of v.epochs.entries()) {
    try {
      for (const p of epoch.proposals ?? []) {
        const res = await processMessage({ context, state, message: decode(mlsMessageDecoder, hexToBytes(p)) });
        state = res.newState;
      }
      const res = await processMessage({ context, state, message: decode(mlsMessageDecoder, hexToBytes(epoch.commit)) });
      state = res.newState;
    } catch (e) {
      return `epoch ${i} of ${v.epochs.length}: ${e?.message ?? e}`;
    }
    if (toHex(state.keySchedule.epochAuthenticator) !== epoch.epoch_authenticator) {
      return `epoch ${i} of ${v.epochs.length}: epoch_authenticator mismatch`;
    }
  }
  return null;
}

let failed = 0;
let total = 0;
for (const path of process.argv.slice(2)) {
  const vectors = JSON.parse(readFileSync(path, "utf8")).filter((v) => v.cipher_suite === 1);
  for (const [i, v] of vectors.entries()) {
    total++;
    const err = await run(v);
    if (err) {
      failed++;
      console.log(`FAIL ${path}[${i}] ${v.description ?? ""}: ${err}`);
    } else {
      console.log(`PASS ${path}[${i}] ${v.description ?? ""} (${v.epochs.length} epochs)`);
    }
  }
}
console.log(`${total - failed} of ${total} vectors passed`);
process.exit(failed === 0 && total > 0 ? 0 : 1);
