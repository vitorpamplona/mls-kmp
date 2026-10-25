# Security considerations

## Forward secrecy needs you to delete things

MLS deletes each epoch's keys when it moves on, but anything you kept
elsewhere can undo that:

- **Old saved states.** Each `saveState()` holds that moment's secrets.
  Overwrite the previous copy rather than keeping versions, and keep
  backups only if you accept what they expose.
- **Former epochs.** mls-kmp keeps the decryption keys of the last 4 epochs
  so [late messages](messages.md#late-messages) still open, and resumption
  secrets of the last 64 for ReInit and branches. That is a window an
  attacker who takes a device also gets.
- **Skipped message keys.** When messages arrive out of order, keys for the
  skipped ones are kept (up to `outOfOrderTolerance`, 1000 by default) until
  those messages arrive.
- **KeyPackage bundles.** Delete each one once its Welcome is processed.

## Post-compromise security needs updates

A member's keys turn over when it commits or [updates](membership.md#updating-your-keys).
A member that never does stays readable by whoever copied its keys, so have
idle members update periodically.

## Treat the delivery service as untrusted

The server sees who talks to whom, when, and how much, plus the group id,
the epoch, authenticated data and every PublicMessage. It cannot read
application messages or forge members' messages, but it can drop, delay or
reorder them, or let two commits through and [fork](fork-recovery.md) the
group. Use `PURE_CIPHERTEXT` to hide handshakes, and padding to hide sizes.

## The group's rules are only as strong as their weakest member

Every member enforces the policy on its own. One that skips a check accepts
commits the others refuse, and the group forks. Ship the same policy to
every client.

## One thread at a time per group

An `MlsGroup` is mutable and not thread-safe. Every call, reads included
(decrypting advances a ratchet), must come from one thread at a time. Confine
each group to a thread or coroutine, or guard every call with one lock. Two
threads encrypting at once could seal two messages under the same key and
nonce. Separate groups share no mutable state and can be used in parallel.
`ConcurrencyStressTest` holds the engine to both.

## GREASE

Leaves advertise a few reserved, meaningless type values (RFC 9420 §13.5),
so implementations that wrongly refuse unknown values fail early instead of
on the day a real extension appears. Turn it off with
`greaseCapabilities = false` only for a peer that cannot cope.
