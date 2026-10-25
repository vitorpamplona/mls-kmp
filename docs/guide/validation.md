# What mls-kmp validates, and what you must

## What the library checks

Every check below runs on our own commits before they are sent, and on every
commit and proposal we receive before it is applied. A failure throws and
leaves the group unchanged. Each row names the test that breaks the rule on
purpose. The `MaliciousMemberTest` cases are commits from a real member,
signed and MACed with its keys, that break only that one rule. Every other
member and a [PublicGroup](public-group.md) view must refuse each one for that
reason and stay where they were.

| Check | RFC 9420 | Tested by |
| ----- | -------- | --------- |
| Message syntax: minimal varints, strict optionals, in-range indices and counts, nothing left over | §2.1 | `TlsCodecTest`, `HostileInputTest`, `MessageFuzzTest` |
| Group id and epoch of every message | §6 | `MaliciousMemberTest` › "wrong epoch", "wrong group", `WireFormatPolicyTest.aPrivateMessageForAnotherGroupIsRefusedByItsHeader` |
| Sender signature over `FramedContentTBS`, from a leaf in the tree, inside PrivateMessages too (every member can derive every sender's keys) | §6.1 | `MaliciousMemberTest` › "signed by someone else", "claims another member's leaf", "sender leaf off the end of the tree", `WireFormatPolicyTest.aPrivateMessageSealedWithAnotherMembersKeysIsRefused` |
| Membership tag on a member's PublicMessage | §6.2 | `MaliciousMemberTest` › "bad membership tag" |
| Confirmation tag on every commit | §6.1, §8 | `MaliciousMemberTest` › "no confirmation tag", "bad confirmation tag" |
| LeafNode rules: source, signature, capabilities, unique keys | §7.3 | `MaliciousMemberTest` › "an add whose leaf is not a key_package leaf", "an add whose leaf signature is forged", "an add whose leaf does not support MLS 1.0", "an add whose leaf does not support the group's suite", "an add whose leaf does not support its own credential", "an add that reuses a member's encryption key", "an update path that reuses the committer's encryption key", `ProposalValidationTest.keyPackagesThatBreakLeafRulesAreRefusedLocally` |
| Credential types: every member supports the new leaf's, and it supports theirs | §7.3, §12.2 | `MaliciousMemberTest` › "an add with a credential the members do not support", "an add that does not support the members' credential" |
| KeyPackage lifetime, judged by the committer only, so no receiver forks itself off over its own clock | §7.3 | `MaliciousMemberTest.theCommitterRefusesAnExpiredKeyPackage`, `AuditRegressionTest.aMemberPastAKeyPackagesLifetimeStillAppliesTheCommitThatAddedIt` |
| KeyPackage version, suite, signature and init key | §10.1 | `MaliciousMemberTest` › "an add of a key package for another protocol version", "an add of a key package for another suite", "an add with a forged key package", "an add whose init key is its encryption key" |
| No Add of a member already in the group, or of one client twice | §12.2 | `MaliciousMemberTest` › "an add of a member already in the group", "two adds of one client" |
| One Update, Remove or SelfRemove per leaf, of a live leaf; not the committer's removal, Update or SelfRemove | §12.2 | `MaliciousMemberTest` › "two removes of one leaf", "two updates from one member", "an update and a remove of one member", "a self-remove and a remove of one member", "removes a blank leaf", "removes a leaf off the end of the tree", "removes the committer", "the committer's own update", "the committer's own self-remove" |
| At most one GroupContextExtensions, of types every member supports; ReInit alone; ExternalInit only in external commits | §12.2 | `MaliciousMemberTest` › "two group context extensions", "group context extensions no member supports", "reinit with other proposals", "a reinit to an older protocol version", "external init in a member commit" |
| An external commit: exactly one ExternalInit, at most one Remove, nothing but ExternalInit, Remove and PreSharedKey | §12.2 | `MaliciousMemberTest` › "an external commit without an external init", "an external commit with two external inits", "an external commit that removes two members", "an external commit that adds someone" |
| PSKs: a nonce of the hash length, each PSK once; a reinit or branch PSK only in a new group's first commit, and only one | §8.4, §11, §12.2 | `MaliciousMemberTest` › "a psk with a short nonce", "the same psk twice", "a branch psk outside a new group's first commit" |
| Every proposal type supported by every member, and never a GREASE one | §12.2, §13.5 | `MaliciousMemberTest` › "a proposal type some member does not support", "a grease proposal" |
| An UpdatePath wherever one is required | §12.4.2 | `MaliciousMemberTest` › "remove without a path", "empty commit without a path" |
| UpdatePath parent hashes, and derived keys matching the path | §7.9, §12.4.2 | `MaliciousMemberTest` › "a tampered update path", `TreeKemInteropTest` |
| A ProposalRef names a proposal that was sent this epoch | §12.4.2 | `MaliciousMemberTest` › "a reference to an unknown proposal", `AuditRegressionTest.aCommitCannotReferenceAProposalWeStagedButNeverSent` |
| A commit that removes us gets every public check too | §12.4.2 | `MaliciousMemberTest` › "remove without a path" (carol is the one removed) |
| A joined tree: tree hash, parent hashes, every leaf, credential support across leaves, unmerged leaves | §12.4.3.1 | `TreeValidationInteropTest.testFullTreeValidation`, `JoinedTreeValidationTest` (trees only a malicious GroupInfo signer could build) |
| External commits: signer, path, resync identity | §12.4.3.2 | `RfcFlowsTest.externalResyncMustKeepTheCredential` |
| A successor group matches its ReInit or branch | §11 | `RfcFlowsTest.aSuccessorMustMatchItsPredecessor` |
| Default extensions in their allowed message, well formed, not repeated | §17.3 | `ExtensionValidationTest` |
| The group's wire-format policy | §6 | `WireFormatPolicyTest` |
| Size: no message, Welcome, GroupInfo or tree over the policy's `maxMessageSize` | | `HostileInputTest.maxMessageSizeIsCheckedBeforeDecoding` |
| All-or-nothing: a failed commit changes nothing | | `RfcFlowsTest.aFailedCommitChangesNothing`, every `MaliciousMemberTest` case |

The official RFC 9420 test vectors from
[mls-implementations](https://github.com/mlswg/mls-implementations) run
through the same code in the `interop` suites. Groups mls-kmp creates are
replayed by OpenMLS, mls-rs and ts-mls in CI. `GroupSimulationTest` runs
random multi-member scenarios and checks after every step that all members,
and a PublicGroup view, agree on the group.

## What you must check

RFC 9420 leaves these to the application, and mls-kmp cannot do them for
you:

- **Credentials are genuine.** A BasicCredential is only a name. Decide
  which identities you accept and how a credential proves one (a signature
  from an account key, a certificate) in `validateCredential`.
  > The application using MLS is responsible for specifying which identifiers
  > it finds acceptable for each member in a group. (§5.3.1)
- **Identities may change only as you allow.** When a member replaces its
  leaf, `validateCredentialSuccession` decides whether the new credential is
  still the same member.
- **Who may change the group.** The protocol lets any member commit any
  valid change. Admins, roles and rate limits belong in `authorizeCommit`,
  `authorizeProposal` and `authorizeExternalCommit`, and must be the same on
  every member.
- **Which commit wins an epoch.** When two members commit at once, the
  delivery service has to pick one and everyone must apply that one: see
  [staged commits](proposals-and-commits.md#staged-commits).
- **Keeping state safe.** Encrypt what `saveState()` returns, and delete old
  copies: see [Persistence](persistence.md).

Next: [Following a group from a server](public-group.md).
