#include <iostream>
#include <vector>
#include <cassert>

#include "decoder.hpp"
#include "utils.hpp"
#include "deformatter.hpp"

PacketType decodePacketHeader(const std::vector<uint8_t> &trace_data, const size_t offset);

Packet decodeExtensionPacket(const std::vector<uint8_t> &trace_data, const size_t offset);

Packet decodeTraceInfoPacket(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeTimestampPacket(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeTraceOnPacket(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeContextPacket(const std::vector<uint8_t> &trace_data, const size_t offset);

Packet decodeExceptionPacket(const std::vector<uint8_t> &trace_data, const size_t offset);

Packet decodeAddressLong64ISOPacket(const std::vector<uint8_t> &trace_data, const size_t offset);

Packet decodeAtomF1Packet(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeAtomF2Packet(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeAtomF3Packet(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeAtomF4Packet(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeAtomF5Packet(const std::vector<uint8_t> &trace_data, const size_t offset);
Packet decodeAtomF6Packet(const std::vector<uint8_t> &trace_data, const size_t offset);


Packet decodePacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    PacketType type = decodePacketHeader(trace_data, offset);
    Packet result;

    switch (type) {
        case ETM4_PKT_I_EXTENSION:
            result = decodeExtensionPacket(trace_data, offset);
            break;

        case ETM4_PKT_I_TRACE_INFO:
            result = decodeTraceInfoPacket(trace_data, offset);
            break;

        case ETM4_PKT_I_TIMESTAMP:
            result = decodeTimestampPacket(trace_data, offset);
            break;

        case ETM4_PKT_I_TRACE_ON:
            result = decodeTraceOnPacket(trace_data, offset);
            break;

        case ETM4_PKT_I_CTXT:
            result = decodeContextPacket(trace_data, offset);
            break;

        case ETM4_PKT_I_EXCEPT:
            result = decodeExceptionPacket(trace_data, offset);
            break;

        case ETM4_PKT_I_ADDR_L_64IS0:
            result = decodeAddressLong64ISOPacket(trace_data, offset);
            break;

        case ETM4_PKT_I_ATOM_F1:
            result = decodeAtomF1Packet(trace_data, offset);
            break;

        case ETM4_PKT_I_ATOM_F2:
            result = decodeAtomF2Packet(trace_data, offset);
            break;

        case ETM4_PKT_I_ATOM_F3:
            result = decodeAtomF3Packet(trace_data, offset);
            break;

        case ETM4_PKT_I_ATOM_F4:
            result = decodeAtomF4Packet(trace_data, offset);
            break;

        case ETM4_PKT_I_ATOM_F5:
            result = decodeAtomF5Packet(trace_data, offset);
            break;

        case ETM4_PKT_I_ATOM_F6:
            result = decodeAtomF6Packet(trace_data, offset);
            break;

        default:
            result = {
                PKT_UNKNOWN,
                1,
                0,
                0,
                0
            };
            break;
    }

    return result;
}

PacketType decodePacketHeader(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t header = trace_data[offset];
    if (header == 0x0) {
        return ETM4_PKT_I_EXTENSION;
    } else if (header == 0b00000001) {
        return ETM4_PKT_I_TRACE_INFO;
    } else if (header == 0b00000100) {
        return ETM4_PKT_I_TRACE_ON;
    } else if (header == 0b00000010 or header == 0b00000011) { // 0b0000001x
        return ETM4_PKT_I_TIMESTAMP;
    } else if (header == 0x80 or header == 0x81) { // 0b1000000x
        return ETM4_PKT_I_CTXT;
    } else if (header == 0b00000110) {
        return ETM4_PKT_I_EXCEPT;
    } else if (header == 0b11110110 or header == 0b11110111) { // 0b1111011x
        return ETM4_PKT_I_ATOM_F1;
    } else if (0b11011000 <= header and header <= 0b11011011) { // 0b110110xx
        return ETM4_PKT_I_ATOM_F2;
    } else if (0b11111000 <= header and header <= 0b11111111) { // 0b11111xxx
        return ETM4_PKT_I_ATOM_F3;
    } else if (0b11011100 <= header and header <= 0b11011111) { // 0b110111xx
        return ETM4_PKT_I_ATOM_F4;
    } else if ((0b11010101 <= header and header <= 0b11010111) or (header == 0b11110101)){ //  0b11010101 - 0b11010111 and 0b11110101
        return ETM4_PKT_I_ATOM_F5;
    } else if ((0b11000000 <= header and header <= 0b11010100) or (0b11100000 <= header and header <= 0b11110100)) { // 0b11000000 - 0b11010100 and 0b11100000 - 0b11110100
        return ETM4_PKT_I_ATOM_F6;
    } else if (header == 0b10011101) {
        return ETM4_PKT_I_ADDR_L_64IS0;
    } else {
        return PKT_UNKNOWN;
    }
}

Packet decodeExtensionPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    // Check Async packet
    bool is_async = true;
    for (size_t i = 0; i <= 10; i++) {
        if (trace_data[offset + i] != 0) {
            is_async = false;
        }
    }
    if (trace_data[offset + 11] != 0x80) {
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

Packet decodeTraceInfoPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    // TODO
    size_t packet_size = 2;
    while(trace_data[packet_size - 1] & 0b10000000) {
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

Packet decodeTimestampPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const size_t size = (trace_data[offset] & 0x1) ? 11 : 8;

    Packet packet = {
        ETM4_PKT_I_TIMESTAMP,
        size,
        0,
        0,
        0
    };
    return packet;
}

Packet decodeTraceOnPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
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

Packet decodeContextPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const Packet packet = {
        ETM4_PKT_I_CTXT,
        10,
        0,
        0,
        0,
    };
    return packet;
}

Packet decodeExceptionPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    // If c is set, then a second exception information byte follows.
    // Otherwise, if c is not set, there are no more exception information bytes in the packet.
    bool c = (trace_data[offset + 1] & 0b10000000) ? true : false;
    size_t packet_size = c ? 3 : 2;

    const Packet packet = {
        ETM4_PKT_I_EXCEPT,
        packet_size,
        0,
        0,
        0,
    };
    return packet;
}

Packet decodeAddressLong64ISOPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    // trace_data[offset] is header
    const uint64_t address = ((uint64_t)(trace_data[offset + 1] & 0x7F)) << 2 |
                             ((uint64_t)(trace_data[offset + 2] & 0x7F)) << 9 |
                             ((uint64_t)trace_data[offset + 3]) << 16 |
                             ((uint64_t)trace_data[offset + 4]) << 24 |
                             ((uint64_t)trace_data[offset + 5]) << 32 |
                             ((uint64_t)trace_data[offset + 6]) << 40 |
                             ((uint64_t)trace_data[offset + 7]) << 48 |
                             ((uint64_t)trace_data[offset + 8]) << 56;

    Packet packet = {
        ETM4_PKT_I_ADDR_L_64IS0,
        8,
        0,
        0,
        address
    };
    return packet;
}

Packet decodeAtomF1Packet(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t data = trace_data[offset];

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

Packet decodeAtomF2Packet(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t data = trace_data[offset];

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

Packet decodeAtomF3Packet(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t data = trace_data[offset];

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

Packet decodeAtomF4Packet(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t data = trace_data[offset];

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

Packet decodeAtomF5Packet(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t data = trace_data[offset];
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

Packet decodeAtomF6Packet(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t data = trace_data[offset];

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

void printPacket(const Packet packet)
{
    switch (packet.type) {
        case ETM4_PKT_I_TRACE_INFO:
            printf("ETM4_PKT_I_TRACE_INFO\n");
            break;

        case ETM4_PKT_I_TIMESTAMP:
            printf("ETM4_PKT_I_TIMESTAMP\n");
            break;

        case ETM4_PKT_I_TRACE_ON:
            printf("ETM4_PKT_I_TRACE_ON\n");
            break;

        case ETM4_PKT_I_CTXT:
            printf("ETM4_PKT_I_CTXT\n");
            break;

        case ETM4_PKT_I_EXCEPT:
            printf("ETM4_PKT_I_EXCEPT\n");
            break;

        case ETM4_PKT_I_ADDR_L_64IS0:
            printf("ETM4_PKT_I_ADDR_L_64IS0 addr=%lx\n", packet.addr);
            break;

        case ETM4_PKT_I_ATOM_F1:
            printf("ETM4_PKT_I_ATOM_F1 %x\n", packet.en_bits);
            break;

        case ETM4_PKT_I_ATOM_F2:
            printf("ETM4_PKT_I_ATOM_F2 %x\n", packet.en_bits);
            break;

        case ETM4_PKT_I_ATOM_F3:
            printf("ETM4_PKT_I_ATOM_F3 %x\n", packet.en_bits);
            break;

        case ETM4_PKT_I_ATOM_F4:
            printf("ETM4_PKT_I_ATOM_F4 %x\n", packet.en_bits);
            break;

        case ETM4_PKT_I_ATOM_F5:
            printf("ETM4_PKT_I_ATOM_F5 %x\n", packet.en_bits);
            break;

        case ETM4_PKT_I_ATOM_F6:
            printf("ETM4_PKT_I_ATOM_F6 %x\n", packet.en_bits);
            break;

        default:
            break;
    }
}
