#include <iostream>
#include <vector>
#include <cassert>
#include <optional>

#include "decoder.hpp"
#include "utils.hpp"
#include "deformatter.hpp"

Packet decodePacket(const std::vector<uint8_t> &trace_data, const size_t offset);

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


// Trace dataの中から、エッジカバレッジの復元に必要な
//     - Address packet
//     - Atom packet
// を取り出す。
//
// TODO: 現在、Exceptionによって発生するAddress packetは取り出さず、
// deterministicなエッジカバレッジになるようにしてある。
__attribute__((hot))
std::optional<BranchPacket> decodeNextBranchPacket(const std::vector<uint8_t>& trace_data,
    std::size_t &trace_data_offset)
{
    enum State {
        IDLE,
        TRACE,
        EXCEPTION_ADDR1,
        EXCEPTION_ADDR2,
    };

    // Load
    size_t offset = trace_data_offset;

    State state = (offset == 0 ? IDLE : TRACE);

    BranchPacket branch_packet = {
        BRANCH_PKT_END, 0, 0, 0
    };

    const std::size_t size = trace_data.size();
    while (offset < size) {
        Packet packet = decodePacket(trace_data, offset);
        offset += packet.size;

        switch (state) {
            case IDLE: {
                if (packet.type == ETM4_PKT_I_ASYNC) {
                    state = TRACE;
                }
                break;
            }

            case TRACE: {
                switch (packet.type) {
                    case ETM4_PKT_I_ATOM_F1:
                    case ETM4_PKT_I_ATOM_F2:
                    case ETM4_PKT_I_ATOM_F3:
                    case ETM4_PKT_I_ATOM_F4:
                    case ETM4_PKT_I_ATOM_F5:
                    case ETM4_PKT_I_ATOM_F6:
                        branch_packet = BranchPacket {
                            BRANCH_PKT_ATOM,
                            packet.en_bits,
                            packet.en_bits_len,
                            0
                        };
                        goto end;

                    case ETM4_PKT_I_ADDR_L_64IS0:
                        branch_packet = BranchPacket {
                            BRANCH_PKT_ADDRESS,
                            0,
                            0,
                            packet.addr
                        };
                        goto end;

                    // Exception Packetは例外が発生したときに、生成される。
                    // Exceptionパケットに続き、2つのAddress Packetが生成される。
                    // 1つ目はException後に戻るアドレスを示し、
                    // 2つ目は実際にException後に実行が開始されたアドレスを示している。
                    // そのため、ユーザ空間のトレースではこの2つのAddress Packetを無視する。
                    case ETM4_PKT_I_EXCEPT:
                        state = EXCEPTION_ADDR1;
                        break;
                    case ETM4_PKT_I_OVERFLOW:
                        // An Overflow packet is output in the data trace stream whenever the data trace buffer
                        // in the trace unit overflows. This means that part of the data trace stream might be lost,
                        // and tracing is inactive until the overflow condition clears.
                        std::cerr << "Found an overflow packet that indicates that a trace unit buffer overflow has occurred. ";
                        std::cerr << "The trace data may be corrupted." << std::endl;
                        return std::nullopt;
                    default:
                        break;
                }
                break;
            }

            case EXCEPTION_ADDR1: {
                if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                    state = EXCEPTION_ADDR2;
                }
                break;
            }

            case EXCEPTION_ADDR2: {
                if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                    state = TRACE;
                }
                break;
            }

            default:
                __builtin_unreachable();
        }
    }

end:
    // Save
    trace_data_offset = offset;
    return branch_packet;
}


Packet decodePacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const uint8_t header = trace_data[offset];
    Packet result;

    switch (header) {
        // Extension packet header: 0b00000000
        case 0b00000000:
            result = decodeExtensionPacket(trace_data, offset);
            break;

        // Trace Info packet header: 0b00000001
        case 0b00000001:
            result = decodeTraceInfoPacket(trace_data, offset);
            break;

        // Timestamp packet header: 0b0000001x
        case 0b00000010 ... 0b00000011:
            result = decodeTimestampPacket(trace_data, offset);
            break;

        // Trace On packet header: 0b00000100
        case 0b00000100:
            result = decodeTraceOnPacket(trace_data, offset);
            break;

        // Exception packet header: 0b00000110
        case 0b00000110:
            result = decodeExceptionPacket(trace_data, offset);
            break;

        // Context packet header: 0b1000000x
        case 0b10000000 ... 0b10000001:
            result = decodeContextPacket(trace_data, offset);
            break;

        // 64-bit IS0 long Address packet header: 0b10011101
        case 0b10011101:
            result = decodeAddressLong64ISOPacket(trace_data, offset);
            break;

        // Atom 6 packet header:  0b11000000 - 0b11010100
        case 0b11000000 ... 0b11010100:
            result = decodeAtomF6Packet(trace_data, offset);
            break;

        // Atom 5 packet header: 0b11010101 - 0b11010111
        case 0b11010101 ... 0b11010111:
            result = decodeAtomF5Packet(trace_data, offset);
            break;

        // Atom 2 packet header: 0b110110xx
        case 0b11011000 ... 0b11011011:
            result = decodeAtomF2Packet(trace_data, offset);
            break;

        // Atom 4 packet header: 0b110111xx
        case 0b11011100 ... 0b11011111:
            result = decodeAtomF4Packet(trace_data, offset);
            break;

        // Atom 6 packet header: 0b11100000 - 0b11110100
        case 0b11100000 ... 0b11110100:
            result = decodeAtomF6Packet(trace_data, offset);
            break;

        // Atom 5 packet header: 0b11110101
        case 0b11110101:
            result = decodeAtomF5Packet(trace_data, offset);
            break;

        // Atom 1 packet header: 0b1111011x
        case 0b11110110 ... 0b11110111:
            result = decodeAtomF1Packet(trace_data, offset);
            break;

        // Atom 3 packet header: 0b11111xxx
        case 0b11111000 ... 0b11111111:
            result = decodeAtomF3Packet(trace_data, offset);
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

Packet decodeExtensionPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const size_t rest_data_size = trace_data.size() - offset;

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
    if (trace_data[offset + 1] == 0x5) {
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
    // Header is correct, but packet size is incomplete.
    const size_t rest_data_size = trace_data.size() - offset;
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
    const size_t packet_size = (trace_data[offset] & 0x1) ? 11 : 8;

    // Header is correct, but packet size is incomplete.
    const size_t rest_data_size = trace_data.size() - offset;
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
    // This bit indicates if the packet has a payload or not.
    const bool has_payload = (trace_data[offset] & 0x1) ? true : false;

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
    const size_t rest_data_size = trace_data.size() - offset;
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
    const bool has_virtual_context = (trace_data[offset + 1] & 0b01000000) ? true : false;
    // Indicates whether the Context ID section is present in the packet.
    const bool has_context_id      = (trace_data[offset + 1] & 0b10000000) ? true : false;

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

Packet decodeExceptionPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    // If c is set, then a second exception information byte follows.
    // Otherwise, if c is not set, there are no more exception information bytes in the packet.
    bool c = (trace_data[offset + 1] & 0b10000000) ? true : false;
    size_t packet_size = c ? 3 : 2;

    const size_t rest_data_size = trace_data.size() - offset;
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

Packet decodeAddressLong64ISOPacket(const std::vector<uint8_t> &trace_data, const size_t offset)
{
    const size_t rest_data_size = trace_data.size() - offset;
    // Header is correct, but packet size is incomplete.
    if (rest_data_size < 8) {
        return Packet{
            PKT_INCOMPLETE,
            rest_data_size,
            0,
            0,
            0
        };
    }

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
