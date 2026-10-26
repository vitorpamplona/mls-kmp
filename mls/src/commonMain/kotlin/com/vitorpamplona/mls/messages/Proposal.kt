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
package com.vitorpamplona.mls.messages

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsSerializable
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode

/**
 * MLS Proposal types (RFC 9420 Section 12).
 *
 * Proposals represent requested changes to group state. They must be
 * collected into a Commit to take effect.
 *
 * Marmot uses: Add, Remove, Update, SelfRemove (custom), GroupContextExtensions.
 */
public enum class ProposalType(
    public val value: Int,
) {
    ADD(1),
    UPDATE(2),
    REMOVE(3),
    PSK(4),
    REINIT(5),
    EXTERNAL_INIT(6),
    GROUP_CONTEXT_EXTENSIONS(7),

    // AppDataUpdate is the MLS Extensions draft's proposal for mutating
    // GroupContext app components. Every current-profile Marmot group requires
    // it, because that profile keeps all its mutable group state in the
    // `app_data_dictionary` rather than in a bespoke extension.
    APP_DATA_UPDATE(0x0008),

    // SelfRemove is standardized in MLS Extensions draft-ietf-mls-extensions
    // as IANA proposal type 0x000A, NOT a Marmot private-use value.
    // openmls / mdk encode it as 0x000A on the wire; quartz was writing
    // 0xF001, which strict receivers reject as "Unknown ProposalType".
    SELF_REMOVE(0x000A),

    /** Any other type: see [Proposal.Custom]. Never on the wire as -1. */
    CUSTOM(-1),
    ;

    public companion object {
        public fun fromValue(value: Int): ProposalType =
            entries.find { it.value == value }
                ?: throw IllegalArgumentException("Unknown ProposalType: $value")
    }
}

/**
 * MLS Proposal (RFC 9420 Section 12).
 */
public sealed class Proposal : TlsSerializable {
    public abstract val proposalType: ProposalType

    /** The `proposal_type` on the wire. */
    public open val proposalTypeValue: Int get() = proposalType.value

    /**
     * A proposal type this engine has no struct for, carried as its type and
     * an opaque<V> body — the encoding OpenMLS and ts-mls use for custom
     * proposals. It has no effect on the tree or GroupContext; an
     * application that defines it reads it from the commit (see
     * [com.vitorpamplona.mls.group.MlsGroupPolicy.authorizeCommit]). Every
     * member that processes a commit carrying one must list its type in its
     * capabilities, as RFC 9420 §12.2 requires for any non-default type.
     */
    public class Custom(
        override val proposalTypeValue: Int,
        public val data: ByteArray,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.CUSTOM

        init {
            require(proposalTypeValue in 0..0xFFFF && ProposalType.entries.none { it.value == proposalTypeValue }) {
                "0x${proposalTypeValue.toString(16)} is not a custom proposal type"
            }
        }

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalTypeValue)
            writer.putOpaqueVarInt(data)
        }

        override fun equals(other: Any?): Boolean = other is Custom && proposalTypeValue == other.proposalTypeValue && data.contentEquals(other.data)

        override fun hashCode(): Int = 31 * proposalTypeValue + data.contentHashCode()
    }

    /**
     * Add proposal: includes a KeyPackage for the member to be added.
     */
    public data class Add(
        val keyPackage: MlsKeyPackage,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.ADD

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            keyPackage.encodeTls(writer)
        }
    }

    /**
     * Update proposal: member updates their own LeafNode (new encryption key, etc.)
     */
    public data class Update(
        val leafNode: LeafNode,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.UPDATE

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            leafNode.encodeTls(writer)
        }
    }

    /**
     * Remove proposal: remove a member by their leaf index.
     */
    public data class Remove(
        val removedLeafIndex: Int,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.REMOVE

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            writer.putUint32(removedLeafIndex.toLong())
        }
    }

    /**
     * SelfRemove proposal (Marmot extension): member removes themselves.
     * Sent as a PublicMessage since the sender needs to authenticate it.
     */
    public class SelfRemove : Proposal() {
        override val proposalType: ProposalType = ProposalType.SELF_REMOVE

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
        }
    }

    /**
     * GroupContextExtensions proposal: update the group's extensions
     * (e.g., change group name/description via MarmotGroupData extension).
     */
    public data class GroupContextExtensions(
        val extensions: List<Extension>,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.GROUP_CONTEXT_EXTENSIONS

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            writer.putVectorVarInt(extensions)
        }
    }

    /**
     * AppDataUpdate proposal (MLS Extensions draft): set or remove ONE
     * component in the GroupContext `app_data_dictionary`.
     *
     * ```text
     * struct {
     *     ComponentID component_id;
     *     AppDataUpdateOperation op;   // uint8: 1 = update, 2 = remove
     *     select (op) {
     *       case update: opaque update<V>;
     *       case remove: struct{};
     *     };
     * } AppDataUpdate;
     * ```
     *
     * This targets the GroupContext dictionary ONLY. It is not an update
     * mechanism for a LeafNode, KeyPackage, or GroupInfo dictionary — leaf
     * state changes by replacing the leaf, which is what keeps a member's
     * account identity proof out of reach of anyone else's proposal.
     *
     * Marmot layers its own authorization on top: most component changes are
     * admin-gated, and a Commit's resulting state still has to satisfy every
     * component's own validation rules. None of that is expressed here — this
     * type is the wire format, not the policy.
     */
    public data class AppDataUpdate(
        val componentId: Int,
        val operation: Operation,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.APP_DATA_UPDATE

        init {
            require(componentId in 0..0xFFFF) {
                "ComponentID must fit in a uint16, was $componentId"
            }
        }

        public sealed class Operation {
            /** Set the component's data, creating the entry if absent. */
            public data class Update(
                val data: ByteArray,
            ) : Operation() {
                override fun equals(other: Any?): Boolean {
                    if (this === other) return true
                    if (other !is Update) return false
                    return data.contentEquals(other.data)
                }

                override fun hashCode(): Int = data.contentHashCode()
            }

            /** Drop the component's entry entirely. */
            public object Remove : Operation()

            public companion object {
                public const val TYPE_UPDATE: Int = 1
                public const val TYPE_REMOVE: Int = 2
            }
        }

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            writer.putUint16(componentId)
            when (operation) {
                is Operation.Update -> {
                    writer.putUint8(Operation.TYPE_UPDATE)
                    writer.putOpaqueVarInt(operation.data)
                }

                Operation.Remove -> {
                    writer.putUint8(Operation.TYPE_REMOVE)
                }
            }
        }

        public companion object {
            public fun update(
                componentId: Int,
                data: ByteArray,
            ): AppDataUpdate = AppDataUpdate(componentId, Operation.Update(data))

            public fun remove(componentId: Int): AppDataUpdate = AppDataUpdate(componentId, Operation.Remove)
        }
    }

    /**
     * PreSharedKey proposal (RFC 9420 §12.1.4): fold the PSK named by [psk]
     * into the next epoch's key schedule.
     */
    public class Psk(
        public val psk: PreSharedKeyId,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.PSK

        /** An external PSK, the only kind the old three-field shape could name. */
        public constructor(pskType: Int, pskId: ByteArray, pskNonce: ByteArray) : this(
            run {
                require(pskType == PreSharedKeyId.TYPE_EXTERNAL) { "Use Psk(PreSharedKeyId.Resumption(...)) for psktype $pskType" }
                PreSharedKeyId.External(pskId, pskNonce)
            },
        )

        public val pskType: Int get() = psk.pskType

        /** The external `psk_id`, or empty for a resumption PSK. */
        public val pskId: ByteArray get() = (psk as? PreSharedKeyId.External)?.pskId ?: ByteArray(0)

        public val pskNonce: ByteArray get() = psk.pskNonce

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            psk.encodeTls(writer)
        }

        override fun equals(other: Any?): Boolean = other is Psk && psk == other.psk

        override fun hashCode(): Int = psk.hashCode()
    }

    /**
     * ReInit proposal: reinitialize the group with new parameters (RFC 9420 Section 12.1.5).
     */
    public data class ReInit(
        val groupId: ByteArray,
        val version: Int,
        val cipherSuite: Int,
        val extensions: List<Extension>,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.REINIT

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            writer.putOpaqueVarInt(groupId)
            writer.putUint16(version)
            writer.putUint16(cipherSuite)
            writer.putVectorVarInt(extensions)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ReInit) return false
            return groupId.contentEquals(other.groupId) && version == other.version && cipherSuite == other.cipherSuite
        }

        override fun hashCode(): Int = groupId.contentHashCode()
    }

    /**
     * ExternalInit proposal: allows an external party to join via external commit (RFC 9420 Section 12.1.6).
     */
    public data class ExternalInit(
        val kemOutput: ByteArray,
    ) : Proposal() {
        override val proposalType: ProposalType = ProposalType.EXTERNAL_INIT

        override fun encodeTls(writer: TlsWriter) {
            writer.putUint16(proposalType.value)
            writer.putOpaqueVarInt(kemOutput)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ExternalInit) return false
            return kemOutput.contentEquals(other.kemOutput)
        }

        override fun hashCode(): Int = kemOutput.contentHashCode()
    }

    public companion object {
        public fun decodeTls(reader: TlsReader): Proposal {
            val typeValue = reader.readUint16()
            val type = ProposalType.entries.find { it.value == typeValue } ?: return Custom(typeValue, reader.readOpaqueVarInt())
            return when (type) {
                ProposalType.CUSTOM -> {
                    throw IllegalStateException("unreachable")
                }

                ProposalType.ADD -> {
                    Add(MlsKeyPackage.decodeTls(reader))
                }

                ProposalType.UPDATE -> {
                    Update(LeafNode.decodeTls(reader))
                }

                ProposalType.REMOVE -> {
                    Remove(reader.readIndex())
                }

                ProposalType.SELF_REMOVE -> {
                    SelfRemove()
                }

                ProposalType.APP_DATA_UPDATE -> {
                    val componentId = reader.readUint16()
                    when (val op = reader.readUint8()) {
                        AppDataUpdate.Operation.TYPE_UPDATE ->
                            AppDataUpdate.update(componentId, reader.readOpaqueVarInt())

                        AppDataUpdate.Operation.TYPE_REMOVE ->
                            AppDataUpdate.remove(componentId)

                        else ->
                            throw IllegalArgumentException("Unknown AppDataUpdateOperation: $op")
                    }
                }

                ProposalType.GROUP_CONTEXT_EXTENSIONS -> {
                    GroupContextExtensions(reader.readVectorVarInt { Extension.decodeTls(it) })
                }

                ProposalType.PSK -> {
                    Psk(PreSharedKeyId.decodeTls(reader))
                }

                ProposalType.REINIT -> {
                    ReInit(
                        groupId = reader.readOpaqueVarInt(),
                        version = reader.readUint16(),
                        cipherSuite = reader.readUint16(),
                        extensions = reader.readVectorVarInt { Extension.decodeTls(it) },
                    )
                }

                ProposalType.EXTERNAL_INIT -> {
                    ExternalInit(reader.readOpaqueVarInt())
                }
            }
        }
    }
}

/**
 * ProposalOrRef: a Proposal can be included inline or by reference (hash).
 */
public sealed class ProposalOrRef : TlsSerializable {
    public data class Inline(
        val proposal: Proposal,
    ) : ProposalOrRef() {
        override fun encodeTls(writer: TlsWriter) {
            writer.putUint8(1) // proposal
            proposal.encodeTls(writer)
        }
    }

    public data class Reference(
        val proposalRef: ByteArray,
    ) : ProposalOrRef() {
        override fun encodeTls(writer: TlsWriter) {
            writer.putUint8(2) // reference
            writer.putOpaqueVarInt(proposalRef)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Reference) return false
            return proposalRef.contentEquals(other.proposalRef)
        }

        override fun hashCode(): Int = proposalRef.contentHashCode()
    }

    public companion object {
        public fun decodeTls(reader: TlsReader): ProposalOrRef {
            val type = reader.readUint8()
            return when (type) {
                1 -> Inline(Proposal.decodeTls(reader))
                2 -> Reference(reader.readOpaqueVarInt())
                else -> throw IllegalArgumentException("Unknown ProposalOrRef type: $type")
            }
        }
    }
}
