# Upgrading

## To the next release

- **New:** `PublicGroup`, `MlsGroup.stageWelcome` and `StagedWelcome`,
  `MlsGroupPolicy.wireFormatPolicy`, `recoverForkByReadding`, `reboot`,
  and the companion `MlsGroup.createKeyPackage(identity, policy)`.
- `KeyPackageBundleCodec.decode` refuses trailing bytes.
- `commit`, `stageCommit` and `proposalMessage` take their default wire
  format from the policy. The default policy still sends PublicMessages.
- `buildSelfRemoveProposalMessage` also follows the policy's wire format.
- An `external_pub` sent as the bare key (ts-mls does this) is accepted.
- The instance method `createKeyPackage(identity, signingKey, ...)` still
  works; its `signingKey` was always ignored.
- A KeyPackage's lifetime is checked by the member that commits its Add,
  not again by every receiver: a member reading a week-old backlog, or with a
  skewed clock, no longer refuses a commit the rest of the group applied.
- `commit()` leaves out pooled proposals it cannot commit (a PSK it was never
  given, an Add whose KeyPackage expired in the pool) instead of failing.
- A commit can only reference proposals that were sent; one we staged and
  never sent cannot be named by a guessed reference.
- A ReInit that keeps the group_id works: the new group's first commit used
  to leave out the reinit PSK, and every member refused its Welcome.
- A new group's interim transcript hash follows from its epoch-0
  confirmation tag, as RFC 9420 §11 says (§8.2 says it is empty; OpenMLS
  follows §11). It used to be empty, so an external join into a group still
  at epoch 0 failed across implementations, and fails between this version
  and older ones. A group an older release saved at epoch 0 is repaired when
  its creator restores it.
- A new group's first epoch secret is random (§11). It was derived from the
  GroupContext alone.
- `MlsGroupState` is at version 10: a key rotation or leaf advertisement
  staged for the next commit survives a restart. Older blobs still restore;
  version 10 blobs do not restore on older releases.

## From 1.2

Several fixes bring the engine in line with RFC 9420 and with OpenMLS,
mls-rs and ts-mls, and so change what it puts on the wire. Members on 1.2.0
or older and members on this version disagree in these cases; upgrade a
group's members together.

- **Path secrets** are derived along the *filtered* direct path (§7.4). Older
  versions advanced the chain once per level, so the two disagree on any
  commit whose sender has a blank subtree on its copath (a removed member in
  the middle of the tree).
- **PSKs**: `psk_secret` chains `Extract(psk_input, psk_secret)` as §8.4 says
  (the arguments were swapped), a Welcome lists full `PreSharedKeyID`s, and
  resumption PSKs work.
- **External commits** are signed by the joiner with sender
  `new_member_commit` and start from the GroupInfo's transcript; receivers
  verify that signature. The joiner's init secret uses HPKE `Export` as RFC
  9180 defines it (the exporter context was hashed first), and `external_pub`
  is an `opaque<V>` key (it was the bare key), so external joins work across
  implementations.
- **Lifetimes** are compared as the uint64s they are: a `not_after` of 2^64-1
  used to read as expired.
- `commit()` folds our own Update into the UpdatePath instead of committing
  it (§12.2 forbids that), and refuses to commit our own SelfRemove.
- Standalone proposals of every type are accepted, not only SelfRemove; see
  `authorizeProposal` in [Your application's rules](application-rules.md).
- Default extensions are checked for placement, structure and duplicates:
  `application_id` belongs in a LeafNode, not the GroupContext.
- `MlsGroupState` is at version 9; older blobs still restore.
