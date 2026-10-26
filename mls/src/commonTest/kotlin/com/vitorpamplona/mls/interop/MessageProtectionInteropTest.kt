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
package com.vitorpamplona.mls.interop

import com.vitorpamplona.mls.JsonMapper
import com.vitorpamplona.mls.TestResourceLoader
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.FramedContent
import com.vitorpamplona.mls.framing.Framing
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.PrivateMessage
import com.vitorpamplona.mls.framing.PrivateMessageCodec
import com.vitorpamplona.mls.framing.PublicMessage
import com.vitorpamplona.mls.framing.Sender
import com.vitorpamplona.mls.framing.SenderType
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.framing.framedContent
import com.vitorpamplona.mls.hexToByteArray
import com.vitorpamplona.mls.messages.GroupContext
import com.vitorpamplona.mls.schedule.SecretTree
import com.vitorpamplona.mls.toHexKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * RFC 9420 §6 message protection against the `message-protection` vectors
 * from github.com/mlswg/mls-implementations.
 *
 * Each vector is a two-member group seen by leaf 1. For a proposal, a commit
 * and an application message, the vector's PublicMessage (not for
 * application data) and PrivateMessage must unprotect to the raw content,
 * and protecting the raw content ourselves must produce messages that
 * unprotect again.
 */
class MessageProtectionInteropTest {
    private val vectors: List<MessageProtectionVector> =
        JsonMapper.jsonInstance
            .decodeFromString<List<MessageProtectionVector>>(TestResourceLoader().loadString("mls/message-protection.json"))
            .filter { it.cipherSuite == 1 }

    private val sender = Sender(SenderType.MEMBER, 1)

    private fun context(v: MessageProtectionVector) =
        GroupContext(
            groupId = v.groupId.hexToByteArray(),
            epoch = v.epoch,
            treeHash = v.treeHash.hexToByteArray(),
            confirmedTranscriptHash = v.confirmedTranscriptHash.hexToByteArray(),
        ).toTlsBytes()

    private fun signingKey(v: MessageProtectionVector) = v.signaturePriv.hexToByteArray() + v.signaturePub.hexToByteArray()

    private fun unprotectPublic(
        v: MessageProtectionVector,
        bytes: ByteArray,
    ): PublicMessage {
        val msg = MlsMessage.decodeTls(TlsReader(bytes))
        assertEquals(WireFormat.PUBLIC_MESSAGE, msg.wireFormat)
        val pub = PublicMessage.decodeTls(TlsReader(msg.payload))
        val content = pub.framedContent()
        val tag = Framing.membershipTag(v.membershipKey.hexToByteArray(), content, context(v), pub.signature, pub.confirmationTag)
        assertContentEquals(tag, pub.membershipTag, "membership_tag")
        assertTrue(Framing.verify(v.signaturePub.hexToByteArray(), WireFormat.PUBLIC_MESSAGE, content, context(v), pub.signature), "PublicMessage signature")
        return pub
    }

    private fun unprotectPrivate(
        v: MessageProtectionVector,
        bytes: ByteArray,
        secretTree: SecretTree,
    ): PrivateMessageCodec.Opened {
        val msg = MlsMessage.decodeTls(TlsReader(bytes))
        assertEquals(WireFormat.PRIVATE_MESSAGE, msg.wireFormat)
        val priv = PrivateMessage.decodeTls(TlsReader(msg.payload))
        val senderData = PrivateMessageCodec.openSenderData(priv, v.senderDataSecret.hexToByteArray())
        assertEquals(1, senderData.leafIndex, "sender data leaf index")
        val keyNonce =
            if (priv.contentType == ContentType.APPLICATION) {
                secretTree.applicationKeyNonceForGeneration(1, senderData.generation)
            } else {
                secretTree.handshakeKeyNonceForGeneration(1, senderData.generation)
            }
        val opened = PrivateMessageCodec.openContent(priv, senderData, keyNonce)
        assertTrue(
            Framing.verify(v.signaturePub.hexToByteArray(), WireFormat.PRIVATE_MESSAGE, opened.content, context(v), opened.signature),
            "PrivateMessage signature",
        )
        return opened
    }

    private fun protectPublic(
        v: MessageProtectionVector,
        contentType: ContentType,
        raw: ByteArray,
    ): ByteArray {
        val content = FramedContent(v.groupId.hexToByteArray(), v.epoch, sender, ByteArray(0), contentType, raw)
        val signature = Framing.sign(signingKey(v), WireFormat.PUBLIC_MESSAGE, content, context(v))
        val tag = if (contentType == ContentType.COMMIT) ByteArray(32) { 7 } else null
        val membershipTag = Framing.membershipTag(v.membershipKey.hexToByteArray(), content, context(v), signature, tag)
        return MlsMessage.fromPublicMessage(Framing.publicMessage(content, signature, tag, membershipTag)).toTlsBytes()
    }

    private fun protectPrivate(
        v: MessageProtectionVector,
        contentType: ContentType,
        raw: ByteArray,
        secretTree: SecretTree,
    ): ByteArray {
        val content = FramedContent(v.groupId.hexToByteArray(), v.epoch, sender, ByteArray(0), contentType, raw)
        val signature = Framing.sign(signingKey(v), WireFormat.PRIVATE_MESSAGE, content, context(v))
        val tag = if (contentType == ContentType.COMMIT) ByteArray(32) { 7 } else null
        val keyNonce = if (contentType == ContentType.APPLICATION) secretTree.nextApplicationKeyNonce(1) else secretTree.nextHandshakeKeyNonce(1)
        return MlsMessage.fromPrivateMessage(PrivateMessageCodec.seal(content, signature, tag, keyNonce, v.senderDataSecret.hexToByteArray(), paddingLength = 13)).toTlsBytes()
    }

    private fun check(
        v: MessageProtectionVector,
        contentType: ContentType,
        raw: String,
        pub: String?,
        priv: String,
    ) {
        val rawBytes = raw.hexToByteArray()
        if (pub != null) {
            assertEquals(raw, unprotectPublic(v, pub.hexToByteArray()).content.toHexKey(), "$contentType PublicMessage content")
            assertEquals(raw, unprotectPublic(v, protectPublic(v, contentType, rawBytes)).content.toHexKey(), "$contentType own PublicMessage")
        } else {
            assertFailsWith<IllegalArgumentException> { protectPublic(v, contentType, rawBytes) }
        }

        val receiver = SecretTree(v.encryptionSecret.hexToByteArray(), 2)
        assertEquals(raw, unprotectPrivate(v, priv.hexToByteArray(), receiver).content.body.toHexKey(), "$contentType PrivateMessage content")

        val ours = protectPrivate(v, contentType, rawBytes, SecretTree(v.encryptionSecret.hexToByteArray(), 2))
        val opened = unprotectPrivate(v, ours, SecretTree(v.encryptionSecret.hexToByteArray(), 2))
        assertEquals(raw, opened.content.body.toHexKey(), "$contentType own PrivateMessage")
    }

    @Test
    fun testProposalProtection() {
        assertTrue(vectors.isNotEmpty(), "No cipher_suite==1 message-protection vectors")
        for (v in vectors) check(v, ContentType.PROPOSAL, v.proposal, v.proposalPub, v.proposalPriv)
    }

    @Test
    fun testCommitProtection() {
        for (v in vectors) check(v, ContentType.COMMIT, v.commit, v.commitPub, v.commitPriv)
    }

    @Test
    fun testApplicationProtection() {
        for (v in vectors) check(v, ContentType.APPLICATION, v.application, null, v.applicationPriv)
    }
}
