#include <iostream>
#include <vector>
#include <cassert>
#include <cstdint>
#include <cstring>

#include "decoder.hpp"
#include "deformatter.hpp"
#include "disassembler.hpp"
#include "utils.hpp"
#include "common.hpp"
#include "bitmap.hpp"


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

std::vector<Coverage> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle,
    const uint64_t lower_address_range, const uint64_t uppper_address_range);
std::vector<BranchTrace> processTraceData(const std::vector<uint8_t>& trace_data);
size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const uint64_t address);


int main(int argc, char const *argv[])
{
    checkCapstoneVersion();

    if (argc < 7) {
        std::cerr << "Usage: " << argv[0] << "[trace_data_filename] [trace_id] [binary_file_num] "
                  << "[binary_data1_filename] [binary_data1_start_address] [binary_data1_end_address] ... "
                  << "[binary_dataN_filename] [binary_dataN_start_address] [binary_dataN_end_address] [OPTIONS]" << std::endl
                  << "OPTIONS:" << std::endl
                  << "\t--raw_address_mode     : Use raw address as output for edge coverage, not offset in binary." << std::endl
                  << "\t--address-range=L,R    : Specify the range of addresses to be saved as edge coverage." << std::endl
                  << "\t                         L and R are hexadecimal values, and the address range is [l, r]." << std::endl
                  << "\t--bitmap-mode          : Enable bitmap calculation." << std::endl
                  << "\t--bitmap-size=size     : Specify the bitmap size in hexadecimal. The default size is 0x10000." << std::endl
                  << "\t--bitmap-filename=name : Specify the file name to save the bitmap. The default name is edge_coverage_bitmap.out"
                  << std::endl;
        std::exit(1);
    }

    // Read trace data filename
    const std::string trace_data_filename = argv[1];

    // Read trace ID
    const uint8_t trace_id = std::stol(argv[2], nullptr, 16);

    // Read number of binary files
    const int binary_file_num = std::stol(argv[3], nullptr, 10);
    if (binary_file_num <= 0) {
        std::cerr << "Specify 1 or more for the number of binary files." << std::endl;
        std::exit(1);
    }
    if (argc < binary_file_num * 3 + 4) {
        std::cerr << "Fewer arguments for binary file information." << std::endl;
        std::exit(1);
    }

    // Read trace data
    const std::vector<uint8_t> trace_data = readBinaryFile(trace_data_filename);
    const std::vector<uint8_t> deformat_trace_data = deformatTraceData(trace_data, trace_id);

    // Read binary data and entry point
    std::vector<MemoryMap> memory_map; {
        for (int i = 0; i < binary_file_num; i++) {
            // Read binary data
            const std::string binary_data_filename = argv[4 + i * 3];
            const std::vector<uint8_t> data = readBinaryFile(binary_data_filename);

            // Read start/end address
            const std::uint64_t start_address = std::stol(argv[4 + i * 3 + 1], nullptr, 16);
            const std::uint64_t end_address   = std::stol(argv[4 + i * 3 + 2], nullptr, 16);

            memory_map.emplace_back(
                MemoryMap {
                    data,
                    start_address,
                    end_address,
                }
            );
        }
    }

    // Read options
    bool raw_address_mode = false;
    uint64_t lower_address_range = 0x0;
    uint64_t upper_address_range = UINT64_MAX;
    bool bitmap_mode = false;
    uint64_t bitmap_size = BITMAP_SIZE;
    std::string bitmap_filename = BITMAP_FILENAME;
    for (int i = binary_file_num * 3 + 4; i < argc; ++i) {
        uint64_t t1 = 0, t2 = 0;
        size_t size;
        char buf[64];
        if (strcmp(argv[i], "--raw-address-mode") == 0) {
            raw_address_mode = true;
        } else if (sscanf(argv[i], "--address-range=%lx,%lx", &t1, &t2) == 2) {
            lower_address_range = t1;
            upper_address_range = t2;
        } else if (strcmp(argv[i], "--bitmap-mode") == 0) {
            bitmap_mode = true;
        } else if (sscanf(argv[i], "--bitmap-size=%lx", &size) == 1) {
            // TODO: Check if it is an invalid size
            bitmap_size = size;
        } else if (sscanf(argv[i], "--bitmap-filename=%s", buf)) {
            bitmap_filename = std::string(buf);
        } else {
            std::cerr << "Invalid option: " << argv[i] << std::endl;
            std::exit(1);
        }
    }

    csh handle;
    disassembleInit(&handle);

    // Calculate edge coverage from trace data and binary data
    const std::vector<Coverage> coverage = process(deformat_trace_data, memory_map, handle, lower_address_range, upper_address_range);

    // Create a bitmap from edge coverage for fuzzing and save the bitmap
    if (bitmap_mode) {
        const std::vector<uint8_t> bitmap = createBitmap(coverage, bitmap_size);
        writeBinaryFile(bitmap, bitmap_filename);
    }

    // Print edge coverage
    DEBUG("Edge Coverage");
    for (size_t i = 0; i < coverage.size() - 1; i++) {
        if (raw_address_mode) {
            std::cout << std::hex << "0x" << coverage[i].address;
            std::cout << " -> ";
            std::cout << std::hex << "0x" << coverage[i + 1].address << std::endl;
        } else {
            std::cout << std::hex << "0x" << coverage[i].binary_offset << " [" << argv[4 + coverage[i].binary_file_index * 3] << "]";
            std::cout << " -> ";
            std::cout << std::hex << "0x" << coverage[i + 1].binary_offset << " [" << argv[4 + coverage[i + 1].binary_file_index * 3] << "]" << std::endl;
        }
    }

    disassembleDelete(&handle);
    return 0;
}

std::vector<Coverage> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle,
    const uint64_t lower_address_range, const uint64_t upper_address_range)
{
    // Trace dataの中から、エッジカバレッジの復元に必要なパケットのみを取り出す。
    std::vector<BranchTrace> bts = processTraceData(trace_data);

    // btsの先頭データは必ずAddress packetである。
    // そうでないと、トレース開始アドレスがわからない。
    assert(bts.front().is_atom == false);

    std::vector<Coverage> coverage;

    // The address where the trace was started
    uint64_t address = bts.front().target_address;

    for (size_t i = 1; i < bts.size(); i++) {

        if (bts[i].is_atom) { // Atom packet

            const size_t index = getMemoryMapIndex(memory_map, address);
            const uint64_t offset = address - memory_map[index].start_address;

            // Save coverage information
            if (lower_address_range <= address and address < upper_address_range) {
                coverage.emplace_back(
                    Coverage {
                        address,
                        offset,
                        index,
                    }
                );
            }

            cs_insn *insn = disassembleNextBranchInsn(&handle, memory_map[index].binary_data, offset);

            // Calculate the next address to save as edge coverage (address -> next_address)
            uint64_t next_address = 0;

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
                    if (isISBInstruction(insn)) {
                        next_address = address + insn->size;
                    } else {
                        next_address = memory_map[index].start_address + getAddressFromInsn(insn);
                    }
                } else { // not taken
                    next_address = memory_map[index].start_address + insn->address + insn->size;
                }
            }

            // Update
            address = next_address;

            // release the cache memory when done
            cs_free(insn, 1);
        } else { // Address packet
            // Address packetは下記の3つの場合に生成される。
            //     1. トレース開始時に、トレース開始アドレスを示すために生成される。
            //     2. Indirect branchのときに、Atom pakcet(E)に続き、生成される。
            //     3. トレースが途切れたときに、Trace On packetに続き、生成される。
            // 3.のとき、
            //     3.1 トレースが再開されたアドレスを示すAddress packetの場合と、
            //     3.2 トレースが途切れる前のAtom(E)に続く、Address packetの場合がある。
            // 3.1の場合は必要ないので無視する。
        }
    }
    return coverage;
}

// Trace dataの中から、エッジカバレッジの復元に必要な
//     - Address packet
//     - Atom packet
// を取り出す。
//
// TODO: 現在、Exceptionによって発生するAddress packetは取り出さす、
// deterministicなエッジカバレッジになるようにしてある。
std::vector<BranchTrace> processTraceData(const std::vector<uint8_t>& trace_data)
{
    enum State {
        IDLE,
        TRACE,
        EXCEPTION_ADDR1,
        EXCEPTION_ADDR2,
    };

    size_t offset = 0;
    State state = IDLE;

    std::vector<BranchTrace> bts;

    while (offset < trace_data.size()) {
        Packet packet = decodePacket(trace_data, offset);

        if (state == IDLE) {
            if (packet.type == ETM4_PKT_I_ASYNC) {
                state = TRACE;
            }
        } else if (state == TRACE) {
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
                // Exception Packetは例外が発生したときに、生成される。
                // Exceptionパケットに続き、2つのAddress Packetが生成される。
                // 1つ目はException後に戻るアドレスを示し、
                // 2つ目は実際にException後に実行が開始されたアドレスを示している。
                // そのため、ユーザ空間のトレースではこの2つのAddress Packetを無視する。
                case ETM4_PKT_I_EXCEPT:
                    state = EXCEPTION_ADDR1;
                    break;
                default:
                    break;
            }
        } else if (state == EXCEPTION_ADDR1) {
            if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                state = EXCEPTION_ADDR2;
            }
        } else if (state == EXCEPTION_ADDR2) {
            if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                state = TRACE;
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
