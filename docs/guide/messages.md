# Application messages

<!-- snippet: send-message -->
```kotlin
val ciphertext = alice.encrypt("hello".encodeToByteArray())
publish(ciphertext)
```

Application messages are always encrypted (an MLS PrivateMessage) and signed
by the sender. Receiving one:

<!-- snippet: receive-message -->
```kotlin
when (val received = bob.processMessage(ciphertext)) {
    is ProcessedMessage.Application -> show(received.message.content.decodeToString())
    else -> Unit
}
```

`received.message` also says who sent it (`senderLeafIndex`) and in which
epoch.

## Authenticated data and padding

<!-- snippet: authenticated-data -->
```kotlin
val tagged =
    alice.encrypt(
        plaintext = "hello again".encodeToByteArray(),
        authenticatedData = "thread:42".encodeToByteArray(), // readable by the server, but tamper-proof
        paddingLength = 64, // hides the message length
    )
```

`authenticatedData` travels in the clear but is covered by the encryption,
so the server can read it (to route a message, say) and cannot change it.
Put nothing secret there. Padding adds zero bytes inside the ciphertext so
message sizes leak less.

## Late messages

A member who sent a message just before a commit reached it sealed it in the
previous epoch. Members that already moved on can still open it:

<!-- snippet: late-message -->
```kotlin
// Sealed in an epoch we already left: its sender had not seen the latest commit yet.
val late = bob.decryptFormerEpoch(lateBytes)
```

mls-kmp keeps the decryption keys of the last 4 epochs for this, and each
message opens only once. Keeping old keys is a forward-secrecy trade-off;
see [Security considerations](security.md).

## Deriving keys for your application

Every member derives the same secret from the epoch, for anything your
application encrypts outside MLS (files, calls):

<!-- snippet: exporter -->
```kotlin
val key = alice.exporterSecret(label = "my-app file key", context = "file 9".encodeToByteArray(), length = 32)
```

Use a label that names your application and purpose. The secret changes
every epoch, so a removed member does not learn new ones.

Next: [Processing incoming messages](processing.md).
