# KeyPackages

Before anyone can add you to a group, you publish a **KeyPackage**: your
credential, a public key to encrypt the Welcome to, and the capabilities of
your client, all signed. It is single-use; publish several, and a fresh one
after each is consumed.

<!-- snippet: key-package -->
```kotlin
val bundle = MlsGroup.createKeyPackage(identity = "bob".encodeToByteArray())
publish(bundle.keyPackage.toTlsBytes()) // what others add bob with
val stored: ByteArray = KeyPackageBundleCodec.encode(bundle) // keep it, encrypted: it holds private keys
```

The bundle holds the private keys the Welcome will need, possibly days later.
Keep it until then, encrypted like any other key material, and read it back
with:

<!-- snippet: key-package-restore -->
```kotlin
val restored = KeyPackageBundleCodec.decode(stored)
```

Delete a bundle once its Welcome has been processed. Reusing one lets two
groups share key material.

`createKeyPackage` takes the group's [policy](application-rules.md) too.
The policy supplies the capabilities the leaf advertises: a group that uses
SelfRemove or custom proposals needs every member's leaf to list them (see
[Membership changes](membership.md)). The leaf lives 84 days by default; pass
`lifetime` to change that.

Next: [Creating a group](groups.md).
