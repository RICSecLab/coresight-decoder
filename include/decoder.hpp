#pragma once

enum PacketType
{
    // Extension header
    ETM4_PKT_I_EXTENSION,

    // Sync
    ETM4_PKT_I_TRACE_INFO,
    ETM4_PKT_I_TIMESTAMP,
    ETM4_PKT_I_TRACE_ON,

    // Exceptions
    ETM4_PKT_I_EXCEPT,

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
    ETM4_PKT_I_OVERFLOW,

    PKT_UNKNOWN,
    PKT_INCOMPLETE,
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


enum BranchPacketType
{
    BRANCH_PKT_ATOM,
    BRANCH_PKT_ADDRESS,
    BRANCH_PKT_END
};

struct BranchPacket
{
    BranchPacketType type;

    // for ATOM packet (direct branch)
    uint32_t en_bits;
    size_t en_bits_len;

    // for ADDRESS packet (indirect branch)
    uint64_t target_address;
};


__attribute__((hot))
std::optional<BranchPacket> decodeNextBranchPacket(const std::vector<uint8_t>& trace_data,
    std::size_t &trace_data_offset);
void printPacket(const Packet packet);
