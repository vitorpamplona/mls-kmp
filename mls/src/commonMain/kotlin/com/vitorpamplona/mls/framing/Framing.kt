/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.mls.framing

import com.vitorpamplona.crypto.mac.MacInstance
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsSerializable
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.messages.Commit
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.schedule.KeyNonceGeneration

/**
 * RFC 9420 §6 FramedContent: who sent what, in which group and epoch.
 *
 * ```
 * struct {
 *     opaque group_id<V>;
 *     uint64 epoch;
 *     Sender sender;
 *     opaque authenticated_data<V>;
 *     ContentType content_type;
 *     select (FramedContent.content_type) {
 *         case application: opaque application_data<V>;
 *         case proposal:    Proposal proposal;
 *         case commit:      Commit commit;
 *     };
 * } FramedContent;
 * ```
 *
 * [body] holds the raw application data for application content and the
 * serialized Proposal or Commit struct otherwise, so every structure built
 * on top of this one (the signed TBS, the membership MAC input, the
 * AuthenticatedContent a ProposalRef hashes, the transcript hash input) is
 * produced by the one encoder below and cannot drift.
 */
public class FramedContent(
    public val groupId: ByteArray,
    public val epoch: Long,
    public val sender: Sender,
    public val authenticatedData: ByteArray,
    public val contentType: ContentType,
    public val body: ByteArray,
) : TlsSerializable {
    override fun encodeTls(writer: TlsWriter) {
        writer.putOpaqueVarInt(groupId)
        writer.putUint64(epoch)
        encodeSender(writer, sender)
        writer.putOpaqueVarInt(authenticatedData)
        writer.putUint8(contentType.value)
        when (contentType) {
            ContentType.APPLICATION -> writer.putOpaqueVarInt(body)
            ContentType.PROPOSAL, ContentType.COMMIT -> writer.putBytes(body)
        }
    }

    public fun proposal(): Proposal {
        require(contentType == ContentType.PROPOSAL) { "FramedContent carries $contentType, not a proposal" }
        val reader = TlsReader(body)
        return Proposal.decodeTls(reader).also { reader.requireFullyConsumed("Proposal") }
    }

    public fun commit(): Commit {
        require(contentType == ContentType.COMMIT) { "FramedContent carries $contentType, not a commit" }
        val reader = TlsReader(body)
        return Commit.decodeTls(reader).also { reader.requireFullyConsumed("Commit") }
    }
}

/** The FramedContent a PublicMessage carries. */
public fun PublicMessage.framedContent(): FramedContent = FramedContent(groupId, epoch, sender, authenticatedData, contentType, content)

/**
 * The structures RFC 9420 §6 derives from a FramedContent, in one place.
 *
 * Every signed, MACed or hashed form of a message is built here so the
 * sending and the receiving side cannot encode them differently.
 */
public object Framing {
    /** Whether FramedContentTBS appends the GroupContext for this sender (RFC 9420 §6.1). */
    public fun senderSignsGroupContext(sender: Sender): Boolean = sender.senderType == SenderType.MEMBER || sender.senderType == SenderType.NEW_MEMBER_COMMIT

    /**
     * FramedContentTBS:
     *
     * ```
     * struct {
     *     ProtocolVersion version = mls10;
     *     WireFormat wire_format;
     *     FramedContent content;
     *     select (FramedContentTBS.content.sender.sender_type) {
     *         case member:
     *         case new_member_commit: GroupContext context;
     *         case external:
     *         case new_member_proposal: struct{};
     *     };
     * } FramedContentTBS;
     * ```
     */
    public fun tbs(
        wireFormat: WireFormat,
        content: FramedContent,
        groupContext: ByteArray?,
    ): ByteArray {
        val writer = TlsWriter()
        writer.putUint16(MlsMessage.MLS_VERSION_10)
        writer.putUint16(wireFormat.value)
        content.encodeTls(writer)
        if (senderSignsGroupContext(content.sender)) {
            writer.putBytes(requireNotNull(groupContext) { "a ${content.sender.senderType} sender signs over the GroupContext" })
        }
        return writer.toByteArray()
    }

    public fun sign(
        signingKey: ByteArray,
        wireFormat: WireFormat,
        content: FramedContent,
        groupContext: ByteArray?,
    ): ByteArray = MlsCryptoProvider.signWithLabel(signingKey, "FramedContentTBS", tbs(wireFormat, content, groupContext))

    public fun verify(
        verificationKey: ByteArray,
        wireFormat: WireFormat,
        content: FramedContent,
        groupContext: ByteArray?,
        signature: ByteArray,
    ): Boolean = MlsCryptoProvider.verifyWithLabel(verificationKey, "FramedContentTBS", tbs(wireFormat, content, groupContext), signature)

    /** FramedContentAuthData: the signature, plus the confirmation tag for a commit. */
    public fun encodeAuthData(
        writer: TlsWriter,
        contentType: ContentType,
        signature: ByteArray,
        confirmationTag: ByteArray?,
    ) {
        writer.putOpaqueVarInt(signature)
        if (contentType == ContentType.COMMIT) {
            writer.putOpaqueVarInt(requireNotNull(confirmationTag) { "a commit's auth data carries a confirmation_tag" })
        }
    }

    /** AuthenticatedContent = wire_format || FramedContent || FramedContentAuthData. */
    public fun authenticatedContent(
        wireFormat: WireFormat,
        content: FramedContent,
        signature: ByteArray,
        confirmationTag: ByteArray? = null,
    ): ByteArray {
        val writer = TlsWriter()
        writer.putUint16(wireFormat.value)
        content.encodeTls(writer)
        encodeAuthData(writer, content.contentType, signature, confirmationTag)
        return writer.toByteArray()
    }

    /** RFC 9420 §5.2 ProposalRef = RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent). */
    public fun proposalRef(authenticatedContent: ByteArray): ByteArray = MlsCryptoProvider.refHash(PROPOSAL_REF_LABEL, authenticatedContent)

    /** RFC 9420 §6.2: membership_tag = MAC(membership_key, AuthenticatedContentTBM), TBM = TBS || auth. */
    public fun membershipTag(
        membershipKey: ByteArray,
        content: FramedContent,
        groupContext: ByteArray,
        signature: ByteArray,
        confirmationTag: ByteArray?,
    ): ByteArray {
        val writer = TlsWriter()
        writer.putBytes(tbs(WireFormat.PUBLIC_MESSAGE, content, groupContext))
        encodeAuthData(writer, content.contentType, signature, confirmationTag)
        val mac = MacInstance("HmacSHA256", membershipKey)
        mac.update(writer.toByteArray())
        return mac.doFinal()
    }

    /** RFC 9420 §8.2 ConfirmedTranscriptHashInput = wire_format || FramedContent || signature. */
    public fun confirmedTranscriptHashInput(
        wireFormat: WireFormat,
        content: FramedContent,
        signature: ByteArray,
    ): ByteArray {
        val writer = TlsWriter()
        writer.putUint16(wireFormat.value)
        content.encodeTls(writer)
        writer.putOpaqueVarInt(signature)
        return writer.toByteArray()
    }

    public fun publicMessage(
        content: FramedContent,
        signature: ByteArray,
        confirmationTag: ByteArray?,
        membershipTag: ByteArray?,
    ): PublicMessage {
        // RFC 9420 §6.2: application data is only ever sent encrypted.
        require(content.contentType != ContentType.APPLICATION) { "Application messages MUST be sent as PrivateMessage" }
        return PublicMessage(
            groupId = content.groupId,
            epoch = content.epoch,
            sender = content.sender,
            authenticatedData = content.authenticatedData,
            contentType = content.contentType,
            content = content.body,
            signature = signature,
            confirmationTag = confirmationTag,
            membershipTag = membershipTag,
        )
    }

    public const val PROPOSAL_REF_LABEL: String = "MLS 1.0 Proposal Reference"
}

/**
 * RFC 9420 §6.3 PrivateMessage protection, split the way the receiver needs
 * it: the sender data names which ratchet key opens the content, so it is
 * opened first and the caller looks the key up before the content is opened.
 */
public object PrivateMessageCodec {
    public const val REUSE_GUARD_LENGTH: Int = 4

    /** SenderData: leaf_index, generation, reuse_guard. */
    public class SenderData(
        public val leafIndex: Int,
        public val generation: Int,
        public val reuseGuard: ByteArray,
    )

    /** An opened PrivateMessage: its FramedContent (sender = member) and auth data. */
    public class Opened(
        public val content: FramedContent,
        public val signature: ByteArray,
        public val confirmationTag: ByteArray?,
    )

    /**
     * Seal [content] (a member sender's) with the ratchet key [keyNonce].
     *
     * [paddingLength] zero bytes are appended to PrivateMessageContent, which
     * hides the plaintext length from whoever carries the message (§16.3).
     */
    public fun seal(
        content: FramedContent,
        signature: ByteArray,
        confirmationTag: ByteArray?,
        keyNonce: KeyNonceGeneration,
        senderDataSecret: ByteArray,
        paddingLength: Int = 0,
    ): PrivateMessage {
        require(content.sender.senderType == SenderType.MEMBER) { "only a member can send a PrivateMessage" }
        require(paddingLength >= 0) { "padding length must not be negative" }

        val reuseGuard = MlsCryptoProvider.randomBytes(REUSE_GUARD_LENGTH)

        val plaintext = TlsWriter()
        when (content.contentType) {
            ContentType.APPLICATION -> plaintext.putOpaqueVarInt(content.body)
            ContentType.PROPOSAL, ContentType.COMMIT -> plaintext.putBytes(content.body)
        }
        Framing.encodeAuthData(plaintext, content.contentType, signature, confirmationTag)
        if (paddingLength > 0) plaintext.putBytes(ByteArray(paddingLength))

        val ciphertext =
            MlsCryptoProvider.aeadEncrypt(
                keyNonce.key,
                guardNonce(keyNonce.nonce, reuseGuard),
                privateContentAad(content.groupId, content.epoch, content.contentType, content.authenticatedData),
                plaintext.toByteArray(),
            )

        val senderData = TlsWriter()
        senderData.putUint32(content.sender.leafIndex.toLong())
        senderData.putUint32(keyNonce.generation.toLong() and 0xFFFFFFFFL)
        senderData.putBytes(reuseGuard)
        val (sdKey, sdNonce) = senderDataKeyNonce(senderDataSecret, ciphertext)
        val encryptedSenderData =
            MlsCryptoProvider.aeadEncrypt(
                sdKey,
                sdNonce,
                senderDataAad(content.groupId, content.epoch, content.contentType),
                senderData.toByteArray(),
            )

        return PrivateMessage(
            groupId = content.groupId,
            epoch = content.epoch,
            contentType = content.contentType,
            authenticatedData = content.authenticatedData,
            encryptedSenderData = encryptedSenderData,
            ciphertext = ciphertext,
        )
    }

    public fun openSenderData(
        message: PrivateMessage,
        senderDataSecret: ByteArray,
    ): SenderData {
        val (sdKey, sdNonce) = senderDataKeyNonce(senderDataSecret, message.ciphertext)
        val plain =
            MlsCryptoProvider.aeadDecrypt(
                sdKey,
                sdNonce,
                senderDataAad(message.groupId, message.epoch, message.contentType),
                message.encryptedSenderData,
            )
        val reader = TlsReader(plain)
        val leafIndex = reader.readIndex()
        val generation = reader.readIndex()
        val reuseGuard = reader.readBytes(REUSE_GUARD_LENGTH)
        reader.requireFullyConsumed("SenderData")
        return SenderData(leafIndex, generation, reuseGuard)
    }

    public fun openContent(
        message: PrivateMessage,
        senderData: SenderData,
        keyNonce: KeyNonceGeneration,
    ): Opened {
        val plain =
            MlsCryptoProvider.aeadDecrypt(
                keyNonce.key,
                guardNonce(keyNonce.nonce, senderData.reuseGuard),
                privateContentAad(message.groupId, message.epoch, message.contentType, message.authenticatedData),
                message.ciphertext,
            )
        val reader = TlsReader(plain)
        val body =
            when (message.contentType) {
                ContentType.APPLICATION -> reader.readOpaqueVarInt()
                ContentType.PROPOSAL -> reader.readCapturing { Proposal.decodeTls(it) }.second
                ContentType.COMMIT -> reader.readCapturing { Commit.decodeTls(it) }.second
            }
        val signature = reader.readOpaqueVarInt()
        val confirmationTag = if (message.contentType == ContentType.COMMIT) reader.readOpaqueVarInt() else null
        // RFC 9420 §6.3.1: the padding MUST be all zeros.
        while (reader.hasRemaining) {
            require(reader.readUint8() == 0) { "PrivateMessageContent padding must be zero" }
        }
        val content =
            FramedContent(
                groupId = message.groupId,
                epoch = message.epoch,
                sender = Sender(SenderType.MEMBER, senderData.leafIndex),
                authenticatedData = message.authenticatedData,
                contentType = message.contentType,
                body = body,
            )
        return Opened(content, signature, confirmationTag)
    }

    private fun guardNonce(
        nonce: ByteArray,
        reuseGuard: ByteArray,
    ): ByteArray {
        val guarded = nonce.copyOf()
        for (i in 0 until REUSE_GUARD_LENGTH) {
            guarded[i] = (guarded[i].toInt() xor reuseGuard[i].toInt()).toByte()
        }
        return guarded
    }

    /** RFC 9420 §6.3.2: keyed on the first KDF.Nh bytes of the content ciphertext. */
    private fun senderDataKeyNonce(
        senderDataSecret: ByteArray,
        ciphertext: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val sample = ciphertext.copyOfRange(0, minOf(ciphertext.size, MlsCryptoProvider.HASH_OUTPUT_LENGTH))
        return MlsCryptoProvider.expandWithLabel(senderDataSecret, "key", sample, MlsCryptoProvider.AEAD_KEY_LENGTH) to
            MlsCryptoProvider.expandWithLabel(senderDataSecret, "nonce", sample, MlsCryptoProvider.AEAD_NONCE_LENGTH)
    }

    /** PrivateContentAAD: group_id, epoch, content_type, authenticated_data. */
    private fun privateContentAad(
        groupId: ByteArray,
        epoch: Long,
        contentType: ContentType,
        authenticatedData: ByteArray,
    ): ByteArray {
        val writer = TlsWriter()
        writer.putOpaqueVarInt(groupId)
        writer.putUint64(epoch)
        writer.putUint8(contentType.value)
        writer.putOpaqueVarInt(authenticatedData)
        return writer.toByteArray()
    }

    /** SenderDataAAD: group_id, epoch, content_type. */
    private fun senderDataAad(
        groupId: ByteArray,
        epoch: Long,
        contentType: ContentType,
    ): ByteArray {
        val writer = TlsWriter()
        writer.putOpaqueVarInt(groupId)
        writer.putUint64(epoch)
        writer.putUint8(contentType.value)
        return writer.toByteArray()
    }
}
