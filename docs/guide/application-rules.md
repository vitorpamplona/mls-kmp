# Your application's rules

RFC 9420 leaves several decisions to the application: whether a credential
is genuine, who may commit what, who may join. mls-kmp asks an
`MlsGroupPolicy` at each of those points. Every hook defaults to allowing
what the protocol allows; implement the ones your application needs.

<!-- snippet: policy -->
```kotlin
class OurRules(
    private val admins: Set<String>,
) : MlsGroupPolicy {
    override fun validateCredential(
        credential: Credential,
        signatureKey: ByteArray,
    ) {
        val identity = (credential as? Credential.Basic)?.identity ?: throw IllegalArgumentException("basic credentials only")
        require(identity.isNotEmpty()) { "empty identity" }
    }

    override fun authorizeCommit(
        group: GroupView,
        proposals: List<PendingProposal>,
        committerLeafIndex: Int,
    ) {
        val committer = group.memberIdentityHex(committerLeafIndex)
        require(committer in admins) { "only admins commit" }
    }
}
```

A hook rejects by throwing, and the group is left unchanged. The policy gets
a `GroupView` (extensions, members' identities and capabilities), not the
group itself, so it cannot change the group from inside a check.
`memberIdentityHex` gives a member's BasicCredential identity as hex.

| Hook | Called for |
| ---- | ---------- |
| `validateCredential` | every LeafNode the engine validates: KeyPackages, Updates, UpdatePaths, a joined tree |
| `validateCredentialSuccession` | a member replacing its leaf; by default it must keep its identity |
| `authorizeCommit` | every commit, before building ours and before applying others' |
| `authorizeProposal` | every standalone proposal received |
| `authorizeSelfRemove` | a member asking to leave |
| `authorizeExternalCommit` | every external join or resync |
| `validateJoin` | joining from a Welcome |
| `defaultLeafCapabilities`, `defaultRequiredCapabilities` | the capabilities leaves and new groups get |
| `wireFormatPolicy` | the wire format of proposals and commits |
| `maxForwardRatchetDistance`, `outOfOrderTolerance` | how far one message may skip ahead, and how many skipped keys are kept |
| `greaseCapabilities` | whether leaves advertise GREASE values (RFC 9420 §13.5; on by default) |

Run the same policy on every member. A rule one member enforces and another
does not makes the group disagree about which commits are valid, which
[forks](fork-recovery.md) it.

Next: [What mls-kmp validates](validation.md).
