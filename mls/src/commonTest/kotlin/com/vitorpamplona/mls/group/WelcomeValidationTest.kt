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
package com.vitorpamplona.mls.group

import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.messages.EncryptedGroupSecrets
import com.vitorpamplona.mls.messages.GroupInfo
import com.vitorpamplona.mls.messages.GroupSecrets
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.Welcome
import com.vitorpamplona.mls.schedule.KeySchedule
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFails

/**
 * What a joiner checks of a Welcome, and an external joiner or a
 * [PublicGroup] of a GroupInfo, before trusting the group in it
 * (RFC 9420 §12.4.3.1, §12.4.3.2).
 */
class WelcomeValidationTest {
    private val bob = MlsGroup.createKeyPackage("bob".encodeToByteArray())

    private fun refuses(
        reason: String,
        join: () -> Unit,
    ) = assertContains(assertFails { join() }.message.orEmpty(), reason)

    /**
     * [welcome] opened as [joiner] would, its GroupInfo edited and re-sealed
     * (and re-signed with [signingKey] when given), the GroupSecrets
     * re-encrypted to the new ciphertext. A Welcome only a malicious creator
     * would write.
     */
    private fun rewrap(
        welcome: ByteArray,
        joiner: KeyPackageBundle,
        signingKey: ByteArray?,
        /** The secret of the one PSK the Welcome names, if any (a successor's resumption PSK). */
        psk: ByteArray? = null,
        edit: (GroupInfo) -> GroupInfo,
    ): ByteArray {
        val w = Welcome.decodeTls(TlsReader(MlsMessage.decodeTls(TlsReader(welcome)).payload))
        val mine = w.secrets.single()
        val gsBytes = MlsCryptoProvider.decryptWithLabel(joiner.initPrivateKey, "Welcome", w.encryptedGroupInfo, mine.encryptedGroupSecrets.kemOutput, mine.encryptedGroupSecrets.ciphertext)
        val secrets = GroupSecrets.decodeTls(TlsReader(gsBytes))
        val welcomeSecret = MlsCryptoProvider.deriveSecret(MlsCryptoProvider.hkdfExtract(secrets.joinerSecret, KeySchedule.pskSecret(secrets.psks.map { it to psk!! })), "welcome")
        val key = MlsCryptoProvider.expandWithLabel(welcomeSecret, "key", ByteArray(0), MlsCryptoProvider.AEAD_KEY_LENGTH)
        val nonce = MlsCryptoProvider.expandWithLabel(welcomeSecret, "nonce", ByteArray(0), MlsCryptoProvider.AEAD_NONCE_LENGTH)
        val edited = edit(GroupInfo.decodeTls(TlsReader(MlsCryptoProvider.aeadDecrypt(key, nonce, ByteArray(0), w.encryptedGroupInfo))))
        val signed = if (signingKey == null) edited else edited.copy(signature = MlsCryptoProvider.signWithLabel(signingKey, "GroupInfoTBS", edited.encodeTbs()))
        val sealed = MlsCryptoProvider.aeadEncrypt(key, nonce, ByteArray(0), signed.toTlsBytes())
        val toJoiner = EncryptedGroupSecrets(mine.newMember, MlsCryptoProvider.encryptWithLabel(joiner.keyPackage.initKey, "Welcome", sealed, gsBytes))
        return MlsMessage(wireFormat = WireFormat.WELCOME, payload = w.copy(secrets = listOf(toJoiner), encryptedGroupInfo = sealed).toTlsBytes()).toTlsBytes()
    }

    /** alice invites bob; returns the Welcome and alice's signing key. */
    private fun invite(): Pair<ByteArray, ByteArray> {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        return alice.addMember(bob.keyPackage.toTlsBytes()).welcomeBytes!! to alice.saveState().signingPrivateKey
    }

    @Test
    fun anUnchangedRewrapStillJoins() {
        val (welcome, key) = invite()
        MlsGroup.processWelcome(rewrap(welcome, bob, key) { it }, bob)
    }

    @Test
    fun aMessageThatIsNotAWelcome() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        refuses("Expected Welcome message") { MlsGroup.processWelcome(alice.commit().framedCommitBytes, bob) }
    }

    @Test
    fun aWelcomeForAnotherSuite() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val honest = MlsMessage.decodeTls(TlsReader(alice.addMember(bob.keyPackage.toTlsBytes()).welcomeBytes!!))
        val welcome = Welcome.decodeTls(TlsReader(honest.payload))
        val other = MlsMessage(wireFormat = WireFormat.WELCOME, payload = welcome.copy(cipherSuite = 2).toTlsBytes()).toTlsBytes()
        refuses("Welcome ciphersuite 2") { MlsGroup.processWelcome(other, bob) }
    }

    @Test
    fun aGroupInfoSignedBySomeoneElse() {
        val (welcome, _) = invite()
        refuses("Invalid GroupInfo signature") { MlsGroup.processWelcome(rewrap(welcome, bob, Ed25519.generateKeyPair().privateKey) { it }, bob) }
    }

    @Test
    fun aGroupInfoWithAnotherConfirmationTag() {
        val (welcome, key) = invite()
        val forged = rewrap(welcome, bob, key) { it.copy(confirmationTag = it.confirmationTag.copyOf().also { t -> t[0] = (t[0] + 1).toByte() }) }
        refuses("confirmation_tag does not match") { MlsGroup.processWelcome(forged, bob) }
    }

    @Test
    fun aGroupForAnotherProtocolVersion() {
        val (welcome, key) = invite()
        val forged = rewrap(welcome, bob, key) { it.copy(groupContext = it.groupContext.copy(version = 2)) }
        refuses("version or ciphersuite doesn't match our KeyPackage") { MlsGroup.processWelcome(forged, bob) }
    }

    @Test
    fun aBranchThatDoesNotStartAtEpochOne() {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val bobInAlice = MlsGroup.processWelcome(alice.addMember(bob.keyPackage.toTlsBytes()).welcomeBytes!!, bob)
        val next = MlsGroup.createKeyPackage("bob".encodeToByteArray())
        val branch = alice.branch(listOf(next.keyPackage.toTlsBytes()))
        val key = branch.group.saveState().signingPrivateKey
        val forged = rewrap(branch.commit.welcomeBytes!!, next, key, psk = bobInAlice.resumptionPsk) { it.copy(groupContext = it.groupContext.copy(epoch = 2)) }
        refuses("must start the group at epoch 1") { MlsGroup.joinSuccessor(forged, next, predecessor = bobInAlice) }
    }

    /** alice's GroupInfo, edited and re-signed with [signingKey] (alice's own unless given). */
    private fun groupInfo(
        signingKey: ByteArray? = null,
        edit: (GroupInfo) -> GroupInfo = { it },
    ): ByteArray {
        val alice = MlsGroup.create("alice".encodeToByteArray())
        val info = edit(GroupInfo.decodeTls(TlsReader(MlsMessage.decodeTls(TlsReader(alice.groupInfoMessage())).payload)))
        val signed = info.copy(signature = MlsCryptoProvider.signWithLabel(signingKey ?: alice.saveState().signingPrivateKey, "GroupInfoTBS", info.encodeTbs()))
        return MlsMessage(wireFormat = WireFormat.GROUP_INFO, payload = signed.toTlsBytes()).toTlsBytes()
    }

    @Test
    fun aGroupInfoForAnotherVersionIsNotJoinedOrObserved() {
        val info = groupInfo { it.copy(groupContext = it.groupContext.copy(version = 2)) }
        refuses("Unsupported group version 2") { MlsGroup.externalJoin(info, "dave".encodeToByteArray()) }
        refuses("Unsupported group version 2") { PublicGroup.fromGroupInfo(info) }
    }

    @Test
    fun aGroupInfoSignedBySomeoneElseIsNotJoinedOrObserved() {
        val info = groupInfo(signingKey = Ed25519.generateKeyPair().privateKey)
        refuses("Invalid GroupInfo signature in externalJoin") { MlsGroup.externalJoin(info, "dave".encodeToByteArray()) }
        refuses("Invalid GroupInfo signature") { PublicGroup.fromGroupInfo(info) }
    }
}
