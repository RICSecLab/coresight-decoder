#include <iostream>
#include <vector>
#include <cassert>
#include <cstdint>

#include "decoder.hpp"
#include "deformatter.hpp"
#include "disassembler.hpp"
#include "utils.hpp"


struct BranchTrace {
    bool is_atom; // true: Atom packet, false: Address Packet
    bool is_taken; // for Atom packet
    uint64_t target_address; // for Address Packet
};

struct MemoryMap {
    std::vector<uint8_t> binary_data;
    uint64_t start_address;
    uint64_t end_address;
};

std::vector<std::pair<uint64_t, uint64_t>> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle);
std::vector<BranchTrace> processTraceData(const std::vector<uint8_t>& trace_data);
size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const uint64_t address);


int main(int argc, char const *argv[])
{
    checkCapstoneVersion();

    if (argc < 6) {
        std::cerr << "Usage: ./processor [trace_data_filename] [binary_file_num]\
                        [binary_data1_filename] [binary_data1_start_address] [binary_data1_end_address]\
                        [binary_data2_filename] [binary_data2_start_address] [binary_data2_end_address]\
                        ..." << std::endl;
        std::exit(1);
    }

    // Read trace data filename
    const std::string trace_data_filename = argv[1];

    // Read number of binary files
    const int binary_file_num = std::stol(argv[2], nullptr, 10);
    if (binary_file_num <= 0) {
        std::cerr << "Specify 1 or more for the number of binary files." << std::endl;
        std::exit(1);
    }

    // Read trace data
    const std::vector<uint8_t> trace_data = readBinaryFile(trace_data_filename);
    // TODO: Trace ID can be specified by command argument
    const std::vector<uint8_t> deformat_trace_data = deformatTraceData(trace_data, 0x10);

    // Read binary data and entry point
    std::vector<MemoryMap> memory_map; {
        for (int i = 0; i < binary_file_num; i++) {
            // Read binary data
            const std::string binary_data_filename = argv[3 + i * 3];
            const std::vector<uint8_t> data = readBinaryFile(binary_data_filename);

            // Read start/end address
            const std::uint64_t start_address = std::stol(argv[3 + i * 3 + 1], nullptr, 16);
            const std::uint64_t end_address   = std::stol(argv[3 + i * 3 + 2], nullptr, 16);

            memory_map.emplace_back(
                MemoryMap {
                    data,
                    start_address,
                    end_address,
                }
            );
        }
    }

    csh handle;
    disassembleInit(&handle);

    std::vector<std::pair<uint64_t, uint64_t>> edges = process(deformat_trace_data, memory_map, handle);
    for (const auto& edge : edges) {
        std::cout << std::hex << edge.first << " -> " << edge.second << std::endl;
    }

    disassembleDelete(&handle);
    return 0;
}

std::vector<std::pair<uint64_t, uint64_t>> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle)
{
    std::vector<BranchTrace> bts = processTraceData(trace_data);
    assert(bts.front().is_atom == false);

    std::vector<std::pair<uint64_t, uint64_t>> edges;
    uint64_t address = bts.front().target_address;

    for (size_t i = 1; i < bts.size(); i++) {
        uint64_t next_address = 0;

        if (bts[i].is_atom) { // Atom packet
            const size_t index = getMemoryMapIndex(memory_map, address);
            const uint64_t offset = address - memory_map[index].start_address;
            cs_insn *insn = disassembleNextBranchInsn(&handle, memory_map[index].binary_data, offset);

            // Indirect branch命令のとき、Atom packet(E)とAddress packetが生成される。
            // そのため、Atom packetを一つ消費した後に、Address packetを処理する。
            if (isIndirectBranch(insn)) {
                assert(bts[i].is_taken == true);
                i++;
                if (i >= bts.size()) {
                    std::cerr << "This trace data is incomplete. There is no Address packet following Atom packet." << std::endl;
                    std::exit(1);
                }
                assert(bts[i].is_atom == false);
                next_address = bts[i].target_address;
            } else {
                if (bts[i].is_taken) { // taken
                    next_address = memory_map[index].start_address + getAddressFromInsn(insn);

                } else { // not taken
                    next_address = memory_map[index].start_address + insn->address + insn->size;
                }
            }

            // release the cache memory when done
            cs_free(insn, 1);
        } else { // Address packet
            next_address = bts[i].target_address;
        }

        edges.emplace_back(std::make_pair(address, next_address));
        address = next_address;
    }
    return edges;
}

std::vector<BranchTrace> processTraceData(const std::vector<uint8_t>& trace_data)
{
    enum State {
        IDLE,
        TRACE
    };

    size_t offset = 0;
    State state = IDLE;

    std::vector<BranchTrace> bts;

    while (offset < trace_data.size()) {
        Packet packet = decodePacket(trace_data, offset);

        if (packet.type == ETM4_PKT_I_ASYNC) {
            state = TRACE;
        }

        if (state == TRACE) {
            switch (packet.type) {
                case ETM4_PKT_I_ATOM_F1:
                case ETM4_PKT_I_ATOM_F2:
                case ETM4_PKT_I_ATOM_F3:
                case ETM4_PKT_I_ATOM_F4:
                case ETM4_PKT_I_ATOM_F5:
                case ETM4_PKT_I_ATOM_F6:
                    for (size_t i = 0; i < packet.en_bits_len; ++i) {
                        BranchTrace bt;
                        if (packet.en_bits & (1 << i)) { // E
                            bt.is_atom      = true;
                            bt.is_taken       = true;
                            bt.target_address = 0;
                        } else { // N
                            bt.is_atom      = true;
                            bt.is_taken       = false;
                            bt.target_address = 0;
                        }
                        bts.emplace_back(bt);
                    }
                    break;
                case ETM4_PKT_I_ADDR_L_64IS0: {
                    BranchTrace bt {
                        false,
                        false,
                        packet.addr
                    };
                    bts.emplace_back(bt);
                    break;
                }
                default:
                    break;
            }
        }

        offset += packet.size;
    }

    return bts;
}

size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const uint64_t address)
{
    for (size_t i = 0; i < memory_map.size(); i++) {
        if (memory_map[i].start_address <= address and address < memory_map[i].end_address) {
            return i;
        }
    }
    std::cerr << "Failed to find any binary data that matched the address: " << std::hex << address << std::endl;
    std::exit(1);
}
