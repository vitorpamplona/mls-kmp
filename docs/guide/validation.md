# What mls-kmp validates, and what you must

## What the library checks

Every check below runs on our own commits before they are sent, and on every
commit and proposal we receive before it is applied. A failure throws and
leaves the group unchanged. Each row names a test that breaks the rule on
purpose.

| Check | RFC 9420 | Tested by |
| ----- | -------- | --------- |
| Message syntax: minimal varints, strict optionals, nothing left over | §2.1 | `TlsCodecTest`, `PskSecretAndDeserializationInteropTest` |
| Group id, epoch and wire format of every message | §6 | `MlsGroupNegativeTest.wrongWireFormatIsRejected`, `PublicGroupTest.aCommitFromTheWrongEpochOrGroupIsRejected` |
| Sender signature over `FramedContentTBS` | §6.1 | `MlsGroupNegativeTest.tamperedSignatureIsRejectedAndStateRolledBack`, `spoofedSenderLeafIndexIsRejected` |
| Membership tag on a member's PublicMessage | §6.2 | `MlsGroupNegativeTest.tamperedMembershipTagFailsPublicMessageCheck` |
| Confirmation tag on every commit | §6.1, §8 | `MlsGroupNegativeTest.tamperedConfirmationTagIsRejectedAndStateRolledBack`, `emptyConfirmationTagIsRejected` |
| LeafNode rules: source, signature, lifetime, capabilities, unique keys | §7.3 | `ProposalValidationTest.keyPackagesThatBreakLeafRulesAreRefusedLocally` |
| KeyPackage signature, suite and init key | §10.1 | `ProposalValidationTest.anAddWithAForgedKeyPackageIsRejected` |
| No Add of a member already in the group | §12.2 | `ProposalValidationTest.anAddOfAMemberAlreadyInTheGroupIsRejected` |
| One Update or Remove per leaf; no removal of the committer; not the committer's own Update | §12.2 | `ProposalValidationTest.twoRemovalsOfOneLeafAreRejected`, `removingTheCommitterIsRejected`, `theCommittersOwnUpdateIsRejected` |
| At most one GroupContextExtensions; ReInit alone; ExternalInit only in external commits | §12.2 | `ProposalValidationTest.twoGroupContextExtensionsAreRejected`, `aReInitWithOtherProposalsIsRejected`, `anExternalInitInAMemberCommitIsRejected` |
| Every proposal type supported by every member | §12.2 | `ProposalValidationTest.aProposalTypeSomeMemberDoesNotSupportIsRejected`, `RfcFlowsTest.aCustomProposalNotEveryMemberSupportsIsRefused` |
| An UpdatePath wherever one is required | §12.4.2 | `ProposalValidationTest.aRemoveWithoutAPathIsRejected`, `anEmptyCommitWithoutAPathIsRejected` |
| UpdatePath parent hashes, and derived keys matching the path | §7.9, §12.4.2 | `ProposalValidationTest.aTamperedUpdatePathIsRejected`, `TreeKemInteropTest` |
| A joined tree: tree hash, parent hashes, every leaf | §12.4.3.1 | `TreeValidationInteropTest.testFullTreeValidation` |
| External commits: signer, path, resync identity | §12.4.3.2 | `RfcFlowsTest.externalResyncMustKeepTheCredential` |
| A successor group matches its ReInit or branch | §11 | `RfcFlowsTest.aSuccessorMustMatchItsPredecessor` |
| Default extensions in their allowed message, well formed, not repeated | §17.3 | `ExtensionValidationTest` |
| The group's wire-format policy | §6 | `WireFormatPolicyTest` |
| All-or-nothing: a failed commit changes nothing | | `RfcFlowsTest.aFailedCommitChangesNothing` |

The official RFC 9420 test vectors from
[mls-implementations](https://github.com/mlswg/mls-implementations) run
through the same code in the `interop` suites. Groups mls-kmp creates are
replayed by OpenMLS, mls-rs and ts-mls in CI.

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
