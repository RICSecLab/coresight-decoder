#pragma once

enum PacketType
{
    // Extension header
    ETM4_PKT_I_EXTENSION,

    // Sync
    ETM4_PKT_I_TRACE_INFO,
    ETM4_PKT_I_TIMESTAMP,
    ETM4_PKT_I_TRACE_ON,

    // Address
    ETM4_PKT_I_CTXT,
    ETM4_PKT_I_ADDR_L_64IS0,

    // Atom
    ETM4_PKT_I_ATOM_F1,
    ETM4_PKT_I_ATOM_F2,
    ETM4_PKT_I_ATOM_F3,
    ETM4_PKT_I_ATOM_F4,
    ETM4_PKT_I_ATOM_F5,
    ETM4_PKT_I_ATOM_F6,

    // Extension packets - follow 0x00 header
    ETM4_PKT_I_ASYNC,

    PKT_UNKNOWN
};

struct Packet
{
    // Packet type
    PacketType type;
    // Packet size
    size_t size;

    // Atom packet
    uint32_t en_bits;
    size_t en_bits_len;

    // Address packet
    uint64_t addr;
};

Packet decodePacket(const std::vector<uint8_t> &trace_data, const size_t offset);
void printPacket(const Packet packet, const std::vector<uint8_t> &trace_data, const size_t offset);
