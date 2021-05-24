#include <iostream>
#include <vector>
#include <cassert>
#include <cstdint>

#include "decoder.hpp"
#include "deformatter.hpp"
#include "disassembler.hpp"
#include "utils.hpp"


struct BranchTrace {
    bool is_direct;
    bool is_taken;
    uint64_t target_address;
};


std::vector<std::pair<uint64_t, uint64_t>> process(const std::vector<uint8_t>& trace_data, const std::vector<uint8_t>& binary_data,
    const uint64_t entry_address, const csh &handle);
std::vector<BranchTrace> processTraceData(const std::vector<uint8_t>& trace_data);


int main(int argc, char const *argv[])
{
    if (argc != 4) {
        std::cerr << "Usage: ./processor [trace_data_filename] [binary_data_filename] [binary_entry_address]" << std::endl;
        std::exit(1);
    }

    const std::string trace_data_filename = argv[1];
    const std::string binary_data_filename = argv[2];
    const uint64_t entry_address = std::stol(argv[3], nullptr, 16);

    // Read trace data
    const std::vector<uint8_t> trace_data = readBinaryFile(trace_data_filename);
    const std::vector<uint8_t> deformat_trace_data = deformatTraceData(trace_data);

    // Read binary data
    const std::vector<uint8_t> binary_data = readBinaryFile(binary_data_filename);

    csh handle;
    disassembleInit(&handle);

    std::vector<std::pair<uint64_t, uint64_t>> edges = process(deformat_trace_data, binary_data, entry_address, handle);
    for (const auto& edge : edges) {
        std::cout << std::hex << edge.first << " -> " << edge.second << std::endl;
    }

    disassembleDelete(&handle);
    return 0;
}

std::vector<std::pair<uint64_t, uint64_t>> process(const std::vector<uint8_t>& trace_data, const std::vector<uint8_t>& binary_data,
    const uint64_t entry_address, const csh &handle)
{
    std::vector<BranchTrace> bts = processTraceData(trace_data);
    assert(bts.front().is_direct == false);

    std::vector<std::pair<uint64_t, uint64_t>> edges;
    uint64_t address = bts.front().target_address - entry_address;

    for (size_t i = 1; i < bts.size(); i++) {
        uint64_t next_address = 0;

        if (bts[i].is_direct) { // direct branch
            cs_insn *insn = disassembleNextBranchInsn(&handle, binary_data, address);
            if (bts[i].is_taken) { // taken
                next_address = getAddressFromInsn(insn);
            } else { // not taken
                next_address = insn->address + insn->size;
            }
            // release the cache memory when done
            cs_free(insn, 1);
        } else { // indirect branch
            next_address = bts[i].target_address - entry_address;
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
                            bt.is_direct      = true;
                            bt.is_taken       = true;
                            bt.target_address = 0;
                        } else { // N
                            bt.is_direct      = true;
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
