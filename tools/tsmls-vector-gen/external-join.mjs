// External-join interop: mls-kmp joins a ts-mls group from a ts-mls GroupInfo.
//
//   node external-join.mjs fixture <fixture.json>
//   (mls-kmp: ExternalJoinFromTsMls reads the fixture, writes <result.json>)
//   node external-join.mjs verify <fixture.json> <result.json>
//
// `fixture`: alice creates a group in ts-mls and adds bob, then publishes two
// GroupInfos with external_pub — one carrying the ratchet_tree extension and
// one without it, with the tree handed over out of band. The ts-mls states of
// both members are saved so `verify` can resume them.
//
// mls-kmp then joins each group by external commit, sends an application
// message, commits a Remove of bob as a PrivateMessage and sends another.
//
// `verify`: alice and bob process all of it in ts-mls. Both must reach
// mls-kmp's epoch authenticator after the join, decrypt the message, and bob
// must see himself removed while alice follows into the next epoch.
//
// Exits 0 when every scenario passes.

import { readFileSync, writeFileSync } from "node:fs";
import {
  clientStateDecoder,
  clientStateEncoder,
  createCommit,
  createGroup,
  createGroupInfoWithExternalPub,
  createGroupInfoWithExternalPubAndRatchetTree,
  decode,
  defaultCryptoProvider,
  defaultLifetime,
  encode,
  generateKeyPackage,
  getCiphersuiteImpl,
  joinGroup,
  mlsMessageDecoder,
  mlsMessageEncoder,
  processMessage,
  protocolVersions,
  unsafeTestingAuthenticationService,
  wireformats,
} from "ts-mls";
import { ratchetTreeEncoder } from "./node_modules/ts-mls/dist/src/ratchetTree.js";

const hexToBytes = (s) => Uint8Array.from((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const text = (s) => new TextEncoder().encode(s);

const cs = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", defaultCryptoProvider);
const context = { cipherSuite: cs, authService: unsafeTestingAuthenticationService };

async function makeGroup() {
  const kp = async (name) =>
    generateKeyPackage({ credential: { credentialType: 1, identity: text(name) }, lifetime: defaultLifetime(), cipherSuite: cs });
  const aliceKp = await kp("alice");
  const bobKp = await kp("bob");
  const alice0 = await createGroup({
    context,
    groupId: crypto.getRandomValues(new Uint8Array(32)),
    keyPackage: aliceKp.publicPackage,
    privateKeyPackage: aliceKp.privatePackage,
  });
  const { newState: alice, welcome } = await createCommit({
    context,
    state: alice0,
    extraProposals: [{ proposalType: 1, add: { keyPackage: bobKp.publicPackage } }],
    ratchetTreeExtension: true,
  });
  const bob = await joinGroup({ context, welcome: welcome.welcome, keyPackage: bobKp.publicPackage, privateKeys: bobKp.privatePackage });
  return { alice, bob };
}

const groupInfoMessage = (groupInfo) =>
  toHex(encode(mlsMessageEncoder, { version: protocolVersions.mls10, wireformat: wireformats.mls_group_info, groupInfo }));

async function fixture(out) {
  const scenarios = [];
  for (const outOfBandTree of [false, true]) {
    const { alice, bob } = await makeGroup();
    const groupInfo = outOfBandTree
      ? await createGroupInfoWithExternalPub(alice, [], cs)
      : await createGroupInfoWithExternalPubAndRatchetTree(alice, [], cs);
    scenarios.push({
      description: outOfBandTree ? "GroupInfo without ratchet_tree, tree out of band" : "GroupInfo with ratchet_tree",
      group_info: groupInfoMessage(groupInfo),
      ratchet_tree: outOfBandTree ? toHex(encode(ratchetTreeEncoder, alice.ratchetTree)) : null,
      epoch: Number(alice.groupContext.epoch),
      epoch_authenticator: toHex(alice.keySchedule.epochAuthenticator),
      bob_leaf_index: 1,
      alice_state: toHex(encode(clientStateEncoder, alice)),
      bob_state: toHex(encode(clientStateEncoder, bob)),
    });
  }
  writeFileSync(out, JSON.stringify(scenarios, null, 2));
  console.log(`wrote ${scenarios.length} external-join scenarios to ${out}`);
}

async function verifyScenario(f, r) {
  const states = {
    alice: decode(clientStateDecoder, hexToBytes(f.alice_state)),
    bob: decode(clientStateDecoder, hexToBytes(f.bob_state)),
  };
  const deliver = async (who, hex) => {
    const res = await processMessage({ context, state: states[who], message: decode(mlsMessageDecoder, hexToBytes(hex)) });
    states[who] = res.newState;
    return res;
  };

  for (const who of ["alice", "bob"]) {
    try {
      await deliver(who, r.external_commit);
    } catch (e) {
      return `${who}: external commit: ${e?.message ?? e}`;
    }
    if (toHex(states[who].keySchedule.epochAuthenticator) !== r.epoch_authenticator_after_join) {
      return `${who}: epoch_authenticator mismatch after the external join`;
    }
    const app = await deliver(who, r.application_message).catch((e) => e);
    if (app instanceof Error) return `${who}: application message: ${app.message}`;
    if (app.kind !== "applicationMessage" || toHex(app.message) !== r.application_plaintext) return `${who}: application message mismatch`;
  }

  try {
    await deliver("alice", r.remove_commit);
  } catch (e) {
    return `alice: remove commit: ${e?.message ?? e}`;
  }
  if (toHex(states.alice.keySchedule.epochAuthenticator) !== r.epoch_authenticator_after_remove) {
    return "alice: epoch_authenticator mismatch after the remove";
  }
  // ts-mls 2.0.0-rc.10 applies the UpdatePath even for a member the commit
  // removes, and that member holds no key on it, so it throws instead of
  // reporting removedFromGroup. Tolerate exactly that; anything else fails.
  try {
    await deliver("bob", r.remove_commit);
    if (states.bob.groupActiveState.kind !== "removedFromGroup") return `bob: expected removedFromGroup, got ${states.bob.groupActiveState.kind}`;
  } catch (e) {
    if (!String(e?.message).includes("No overlap between provided private keys and update path")) return `bob: remove commit: ${e?.message ?? e}`;
    console.log("  note: ts-mls cannot process the commit that removes it (upstream limitation); alice's view checks the commit");
  }

  const app = await deliver("alice", r.second_application_message).catch((e) => e);
  if (app instanceof Error) return `alice: second application message: ${app.message}`;
  if (app.kind !== "applicationMessage" || toHex(app.message) !== r.second_application_plaintext) return "alice: second application message mismatch";
  return null;
}

async function verify(fixturePath, resultPath) {
  const fixtures = JSON.parse(readFileSync(fixturePath, "utf8"));
  const results = JSON.parse(readFileSync(resultPath, "utf8"));
  if (fixtures.length !== results.length) {
    console.log(`FAIL: ${fixtures.length} scenarios but ${results.length} results`);
    return 1;
  }
  let failed = 0;
  for (const [i, f] of fixtures.entries()) {
    const err = await verifyScenario(f, results[i]);
    if (err) failed++;
    console.log(`${err ? "FAIL" : "PASS"} external join [${i}] ${f.description}${err ? `: ${err}` : ""}`);
  }
  console.log(`${fixtures.length - failed} of ${fixtures.length} external-join scenarios passed`);
  return failed === 0 ? 0 : 1;
}

const [mode, ...paths] = process.argv.slice(2);
if (mode === "fixture" && paths.length === 1) {
  await fixture(paths[0]);
} else if (mode === "verify" && paths.length === 2) {
  process.exit(await verify(paths[0], paths[1]));
} else {
  console.error("usage: node external-join.mjs fixture <fixture.json> | verify <fixture.json> <result.json>");
  process.exit(2);
}
