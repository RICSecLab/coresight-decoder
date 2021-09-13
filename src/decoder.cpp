/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <iostream>
#include <vector>
#include <cassert>
#include <optional>
#include <sstream>

#include "decoder.hpp"
#include "utils.hpp"
#include "deformatter.hpp"


Packet Decoder::decodePacket()
{
    const uint8_t header = this->trace_data[this->trace_data_offset];
    Packet result;

    switch (header) {
        // Extension packet header: 0b00000000
        case 0b00000000:
            result = this->decodeExtensionPacket();
            break;

        // Trace Info packet header: 0b00000001
        case 0b00000001:
            result = this->decodeTraceInfoPacket();
            break;

        // Timestamp packet header: 0b0000001x
        case 0b00000010 ... 0b00000011:
            result = this->decodeTimestampPacket();
            break;

        // Trace On packet header: 0b00000100
        case 0b00000100:
            result = this->decodeTraceOnPacket();
            break;

        // Exception packet header: 0b00000110
        case 0b00000110:
            result = this->decodeExceptionPacket();
            break;

        // Context packet header: 0b1000000x
        case 0b10000000 ... 0b10000001:
            result = this->decodeContextPacket();
            break;

        // 64-bit IS0 long Address and Context packet header: 0b10000101
        case 0b10000101:
            result = this->decodeAddressLong64IS0WithContextPacket();
            break;

        // IS0 Short Address packet header: 0b10010101
        case 0b10010101:
            result = this->decodeAddressShortIS0Packet();
            break;

        // 64-bit IS0 long Address packet header: 0b10011101
        case 0b10011101:
            result = this->decodeAddressLong64IS0Packet();
            break;

        // Atom 6 packet header:  0b11000000 - 0b11010100
        case 0b11000000 ... 0b11010100:
            result = this->decodeAtomF6Packet();
            break;

        // Atom 5 packet header: 0b11010101 - 0b11010111
        case 0b11010101 ... 0b11010111:
            result = this->decodeAtomF5Packet();
            break;

        // Atom 2 packet header: 0b110110xx
        case 0b11011000 ... 0b11011011:
            result = this->decodeAtomF2Packet();
            break;

        // Atom 4 packet header: 0b110111xx
        case 0b11011100 ... 0b11011111:
            result = this->decodeAtomF4Packet();
            break;

        // Atom 6 packet header: 0b11100000 - 0b11110100
        case 0b11100000 ... 0b11110100:
            result = this->decodeAtomF6Packet();
            break;

        // Atom 5 packet header: 0b11110101
        case 0b11110101:
            result = this->decodeAtomF5Packet();
            break;

        // Atom 1 packet header: 0b1111011x
        case 0b11110110 ... 0b11110111:
            result = this->decodeAtomF1Packet();
            break;

        // Atom 3 packet header: 0b11111xxx
        case 0b11111000 ... 0b11111111:
            result = this->decodeAtomF3Packet();
            break;

        default:
            result = {
                PKT_UNKNOWN,
                1, 0, 0, 0
            };
            break;
    }

    return result;
}

void Decoder::reset() {
    this->trace_data = std::vector<std::uint8_t>();
    this->trace_data_offset = 0;
    this->state = DecodeState::START;
}

Packet Decoder::decodeExtensionPacket()
{
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;

    // Header is correct, but packet size is incomplete.
    if (rest_data_size < 2) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    // Overflow packet
    if (this->trace_data[this->trace_data_offset + 1] == 0x5) {
        return Packet{
            ETM4_PKT_I_OVERFLOW,
            2,
            0,
            0,
            0
        };
    }

    // Header is correct, but packet size is incomplete.
    if (rest_data_size < 12) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    // Check Async packet
    bool is_async = true;
    for (size_t i = 0; i <= 10; i++) {
        if (this->trace_data[this->trace_data_offset + i] != 0) {
            is_async = false;
        }
    }
    if (this->trace_data[this->trace_data_offset + 11] != 0x80) {
        is_async = false;
    }

    const PacketType type = is_async ? ETM4_PKT_I_ASYNC : PKT_UNKNOWN;
    const size_t size = is_async ? 12 : 1;

    Packet packet = {
        type,
        size,
        0,
        0,
        0
    };
    return packet;
}

Packet Decoder::decodeTraceInfoPacket()
{
    // Header is correct, but packet size is incomplete.
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;
    if (rest_data_size < 2) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    // TODO
    size_t packet_size = 2;
    while(this->trace_data[packet_size - 1] & 0b10000000) {
        break;
    }

    const Packet packet = {
        ETM4_PKT_I_TRACE_INFO,
        packet_size,
        0,
        0,
        0,
    };
    return packet;
}

Packet Decoder::decodeTimestampPacket()
{
    const size_t packet_size = (this->trace_data[this->trace_data_offset] & 0x1) ? 11 : 8;

    // Header is correct, but packet size is incomplete.
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;
    if (rest_data_size < packet_size) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    Packet packet = {
        ETM4_PKT_I_TIMESTAMP,
        packet_size,
        0,
        0,
        0
    };
    return packet;
}

Packet Decoder::decodeTraceOnPacket()
{
    const Packet packet = {
        ETM4_PKT_I_TRACE_ON,
        1,
        0,
        0,
        0,
    };
    return packet;
}

Packet Decoder::decodeContextPacket()
{
    // This bit indicates if the packet has a payload or not.
    const bool has_payload = (this->trace_data[this->trace_data_offset] & 0x1) ? true : false;

    if (not has_payload) {
        return Packet {
            ETM4_PKT_I_CTXT,
            1,
            0,
            0,
            0,
        };
    }

    // A payload is present in the packet. The payload consists of at least an information byte.
    // However, there is no 1-byte information byte.
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;
    if (rest_data_size < 2) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    // Indicates whether the Virtual context identifier section is present in the packet.
    const bool has_virtual_context = (this->trace_data[this->trace_data_offset + 1] & 0b01000000) ? true : false;
    // Indicates whether the Context ID section is present in the packet.
    const bool has_context_id      = (this->trace_data[this->trace_data_offset + 1] & 0b10000000) ? true : false;

    const size_t packet_size = (has_virtual_context and has_context_id) ? 10 :
                               (has_virtual_context or  has_context_id) ?  6 : 2;

    // There is not enough payload following the information byte.
    if (rest_data_size < packet_size) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    const Packet packet = {
        ETM4_PKT_I_CTXT,
        packet_size,
        0,
        0,
        0,
    };
    return packet;
}

Packet Decoder::decodeExceptionPacket()
{
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;

    if (rest_data_size < 2) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    // If c is set, then a second exception information byte follows.
    // Otherwise, if c is not set, there are no more exception information bytes in the packet.
    bool c = (this->trace_data[this->trace_data_offset + 1] & 0b10000000) ? true : false;
    size_t packet_size = c ? 3 : 2;

    // Header is correct, but packet size is incomplete.
    if (rest_data_size < packet_size) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    const Packet packet = {
        ETM4_PKT_I_EXCEPT,
        packet_size,
        0,
        0,
        0,
    };
    return packet;
}

Packet Decoder::decodeAddressShortIS0Packet()
{
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;

    if (rest_data_size < 2) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }


    uint64_t address = this->address_reg;
    address = address & ~0x1FF;
    address = address | ((this->trace_data[this->trace_data_offset + 1] & 0x7F) << 2);

    bool c = (this->trace_data[this->trace_data_offset + 1] & 0b10000000) ? true : false;
    size_t packet_size = c ? 3 : 2;

    // Header is correct, but packet size is incomplete.
    if (rest_data_size < packet_size) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    if (c) {
        address = address & ~0x1FE00;
        address = address | (this->trace_data[this->trace_data_offset + 2] << 9);
    }

    this->address_reg = address;

    const Packet packet = {
        ETM4_PKT_I_ADDR_S_IS0,
        packet_size,
        0,
        0,
        address,
    };
    return packet;
}

Packet Decoder::decodeAddressLong64IS0Packet()
{
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;
    // Header is correct, but packet size is incomplete.
    if (rest_data_size < 9) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    // trace_data[this->trace_data_offset] is header
    const uint64_t address = ((uint64_t)(this->trace_data[this->trace_data_offset + 1] & 0x7F)) << 2 |
                             ((uint64_t)(this->trace_data[this->trace_data_offset + 2] & 0x7F)) << 9 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 3]) << 16 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 4]) << 24 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 5]) << 32 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 6]) << 40 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 7]) << 48 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 8]) << 56;

    this->address_reg = address;

    Packet packet = {
        ETM4_PKT_I_ADDR_L_64IS0,
        9,
        0,
        0,
        address
    };
    return packet;
}

Packet Decoder::decodeAddressLong64IS0WithContextPacket()
{
    const size_t rest_data_size = this->trace_data.size() - this->trace_data_offset;
    // Header is correct, but packet size is incomplete.
    if (rest_data_size < 10) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    const uint64_t address = ((uint64_t)(this->trace_data[this->trace_data_offset + 1] & 0x7F)) << 2 |
                             ((uint64_t)(this->trace_data[this->trace_data_offset + 2] & 0x7F)) << 9 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 3]) << 16 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 4]) << 24 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 5]) << 32 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 6]) << 40 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 7]) << 48 |
                             ((uint64_t)this->trace_data[this->trace_data_offset + 8]) << 56;

    // Indicates whether the Virtual context identifier section is present in the packet.
    const bool has_virtual_context = (this->trace_data[this->trace_data_offset + 9] & 0b01000000) ? true : false;
    // Indicates whether the Context ID section is present in the packet.
    const bool has_context_id      = (this->trace_data[this->trace_data_offset + 9] & 0b10000000) ? true : false;

    const size_t context_packet_size = (has_virtual_context and has_context_id) ? 9 :
                                       (has_virtual_context or  has_context_id) ? 5 : 1;

    // There is not enough payload following the information byte.
    if (rest_data_size < 9 + context_packet_size) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

    address_reg = address;

    const Packet packet = {
        ETM4_PKT_I_ADDR_CTXT_L_64IS0,
        9 + context_packet_size,
        0,
        0,
        address
    };
    return packet;
}

Packet Decoder::decodeAtomF1Packet()
{
    const uint8_t data = this->trace_data[this->trace_data_offset];

    const uint32_t en_bits     = data & 0b1; // 1x (E or N)
    const size_t   en_bits_len = 1;

    Packet packet = {
        ETM4_PKT_I_ATOM_F1,
        1,
        en_bits,
        en_bits_len,
        0
    };
    return packet;
}

Packet Decoder::decodeAtomF2Packet()
{
    const uint8_t data = this->trace_data[this->trace_data_offset];

    const uint32_t en_bits     = data & 0b11; // 2x (E or N)
    const size_t   en_bits_len = 2;

    Packet packet = {
        ETM4_PKT_I_ATOM_F2,
        1,
        en_bits,
        en_bits_len,
        0,
    };
    return packet;
}

Packet Decoder::decodeAtomF3Packet()
{
    const uint8_t data = this->trace_data[this->trace_data_offset];

    const uint32_t en_bits     = data & 0b111; // 3x (E or N)
    const size_t   en_bits_len = 3;

    Packet packet = {
        ETM4_PKT_I_ATOM_F3,
        1,
        en_bits,
        en_bits_len,
        0,
    };
    return packet;
}

Packet Decoder::decodeAtomF4Packet()
{
    const uint8_t data = this->trace_data[this->trace_data_offset];

    static const uint32_t f4_patterns[] = {
        0b1110, // EEEN
        0b0000, // NNNN
        0b1010, // ENEN
        0b0101  // NENE
    };

    const uint32_t en_bits     = f4_patterns[data & 0b11]; // 4 atom pattern
    const size_t   en_bits_len = 4;

    Packet packet = {
        ETM4_PKT_I_ATOM_F4,
        1,
        en_bits,
        en_bits_len,
        0,
    };
    return packet;
}

Packet Decoder::decodeAtomF5Packet()
{
    const uint8_t data = this->trace_data[this->trace_data_offset];
    const uint8_t pattern_idx = ((data & 0b00100000) >> 3) | (data & 0b11);

    uint32_t en_bits     = 0;
    size_t   en_bits_len = 0;
    PacketType type = ETM4_PKT_I_ATOM_F5;

    switch(pattern_idx) {
        case 0b101:
            // 5 atom pattern EEEEN
            en_bits     = 0b11110;
            en_bits_len = 5;
            break;

        case 0b001:
            // 5 atom pattern NNNNN
            en_bits     = 0;
            en_bits_len = 5;
            break;

        case 0b010:
            // 5 atom pattern NENEN
            en_bits     = 0b01010;
            en_bits_len = 5;
            break;

        case 0b011:
            // 5 atom pattern ENENE
            en_bits     = 0b10101;
            en_bits_len = 5;
            break;

        default:
            type        = PKT_UNKNOWN;
            en_bits     = 0;
            en_bits_len = 0;
            break;
    }

    Packet packet = {
        type,
        1,
        en_bits,
        en_bits_len,
        0,
    };

    return packet;
}

Packet Decoder::decodeAtomF6Packet()
{
    const uint8_t data = this->trace_data[trace_data_offset];

    size_t e_cnt = (data & 0b11111) + 3;  // count of E's
    uint32_t en_bits = ((uint32_t)0x1 << e_cnt) - 1; // set pattern to string of E's
    if((data & 0b100000) == 0x00) {   // last atom is E?
        en_bits |= ((uint32_t)0x1 << e_cnt);
    }
    const size_t en_bits_len = e_cnt + 1;
    assert(4 <= en_bits_len and en_bits_len <= 24);

    Packet packet = {
        ETM4_PKT_I_ATOM_F6,
        1,
        en_bits,
        en_bits_len,
        0,
    };
    return packet;
}


std::string atomBitsToString(std::uint32_t en_bits, std::size_t en_bits_len)
{
    std::string bits;
    for (std::size_t i = 0; i < en_bits_len; ++i) {
        bits += (en_bits & (1 << i)) ? "E" : "N";
    }
    return bits;
}

std::string Packet::toString() const
{
    std::stringstream stream;

    switch (this->type) {
        case ETM4_PKT_I_TRACE_INFO:
            stream << "ETM4_PKT_I_TRACE_INFO";
            break;

        case ETM4_PKT_I_TIMESTAMP:
            stream << "ETM4_PKT_I_TIMESTAMP";
            break;

        case ETM4_PKT_I_TRACE_ON:
            stream << "ETM4_PKT_I_TRACE_ON";
            break;

        case ETM4_PKT_I_CTXT:
            stream << "ETM4_PKT_I_CTXT";
            break;

        case ETM4_PKT_I_EXCEPT:
            stream << "ETM4_PKT_I_EXCEPT";
            break;

        case ETM4_PKT_I_ADDR_S_IS0:
            stream << "ETM4_PKT_I_ADDR_S_IS0 Addr="
                   << std::hex << "0x" << this->addr;
            break;

        case ETM4_PKT_I_ADDR_L_64IS0:
            stream << "ETM4_PKT_I_ADDR_L_64IS0 Addr="
                   << std::hex << "0x" << this->addr;
            break;

        case ETM4_PKT_I_ADDR_CTXT_L_64IS0:
            stream << "ETM4_PKT_I_ADDR_CTXT_L_64IS0 Addr="
                   << std::hex << "0x" << this->addr;
            break;

        case ETM4_PKT_I_ATOM_F1:
            stream << "ETM4_PKT_I_ATOM_F1 "
                   << atomBitsToString(this->en_bits, this->en_bits_len);
            break;

        case ETM4_PKT_I_ATOM_F2:
            stream << "ETM4_PKT_I_ATOM_F2 "
                   << atomBitsToString(this->en_bits, this->en_bits_len);
            break;

        case ETM4_PKT_I_ATOM_F3:
            stream << "ETM4_PKT_I_ATOM_F3 "
                   << atomBitsToString(this->en_bits, this->en_bits_len);
            break;

        case ETM4_PKT_I_ATOM_F4:
            stream << "ETM4_PKT_I_ATOM_F4 "
                   << atomBitsToString(this->en_bits, this->en_bits_len);
            break;

        case ETM4_PKT_I_ATOM_F5:
            stream << "ETM4_PKT_I_ATOM_F5 "
                   << atomBitsToString(this->en_bits, this->en_bits_len);
            break;

        case ETM4_PKT_I_ATOM_F6:
            stream << "ETM4_PKT_I_ATOM_F6 "
                   << atomBitsToString(this->en_bits, this->en_bits_len);
            break;

        case ETM4_PKT_I_ASYNC:
            stream << "ETM4_PKT_I_ASYNC";
            break;

        case ETM4_PKT_I_OVERFLOW:
            stream << "ETM4_PKT_I_OVERFLOW";
            break;

        case PKT_UNKNOWN:
            stream << "PKT_UNKNOWN";
            break;

        case PKT_INCOMPLETE:
            stream << "PKT_INCOMPLETE";
            break;

        default:
            break;
    }

    return stream.str();
}
