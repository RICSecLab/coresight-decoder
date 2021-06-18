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


std::vector<Trace> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle,
    const uint64_t lower_address_range, const uint64_t uppper_address_range);


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
        char buf[256];
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
    const std::vector<Trace> coverage = process(deformat_trace_data, memory_map, handle, lower_address_range, upper_address_range);

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
            std::cout << std::hex << "0x" << coverage[i].offset << " [" << argv[4 + coverage[i].index * 3] << "]";
            std::cout << " -> ";
            std::cout << std::hex << "0x" << coverage[i + 1].offset << " [" << argv[4 + coverage[i + 1].index * 3] << "] ";
            std::cout << std::hex << "bitmap key: 0x" << generateBitmapKey(coverage[i].offset, coverage[i + 1].offset, bitmap_size) << std::endl;
        }
    }

    disassembleDelete(&handle);
    return 0;
}

std::vector<Trace> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle,
    const uint64_t lower_address_range, const uint64_t upper_address_range)
{
    // Trace dataの中から、エッジカバレッジの復元に必要なパケットのみを取り出す。
    std::vector<BranchPacket> branch_packets = decodeTraceData(trace_data);

    // btsの先頭データは必ずAddress packetである。
    // そうでないと、トレース開始アドレスがわからない。
    assert(branch_packets.front().type == BRANCH_PKT_ADDRESS);

    std::vector<Trace> coverage;

    // The address where the trace was started
    Trace trace = createTrace(memory_map, branch_packets.front().target_address);

    for (size_t pkt_index = 1; pkt_index < branch_packets.size(); pkt_index++) {

        if (branch_packets[pkt_index].type == BRANCH_PKT_ATOM) { // Atom packet
            // TODO: 同じアドレスとBranchPacketに対する以下の処理は、キャッシュ化することができる。
            // これにより、高速化出来る
            const BranchPacket atom_packet = branch_packets[pkt_index];
            for (size_t i = 0; i < atom_packet.en_bits_len; ++i) {
                // Save trace information
                if (lower_address_range <= trace.address and trace.address < upper_address_range) {
                    coverage.emplace_back(trace);
                }

                // TODO: 同じaddressに対するこの処理は、キャッシュ化することができる。
                // これにより、高速化出来る
                BranchInsn insn = getNextBranchInsn(handle, trace.address, memory_map);

                // Calculate the next address to save as edge coverage (address -> next_address)
                Trace next_trace;

                bool is_taken = atom_packet.en_bits & (1 << i);

                // Indirect branch命令のとき、Atom packet(E)とAddress packetが生成される。
                // そのため、Atom packetを一つ消費した後に、Address packetを処理する。
                if (insn.type == INDIRECT_BRANCH) {
                    assert(is_taken == true);
                    pkt_index++;
                    if (pkt_index >= branch_packets.size()) {
                        std::cerr << "This trace data is incomplete. There is no Address packet following Atom packet." << std::endl;
                        std::exit(1);
                    }
                    assert(branch_packets[pkt_index].type == BRANCH_PKT_ADDRESS);
                    next_trace = createTrace(memory_map, branch_packets[pkt_index].target_address);
                } else {
                    if (is_taken) { // taken
                        next_trace.address = insn.taken_address;
                        next_trace.offset  = insn.taken_offset;
                    } else { // not taken
                        next_trace.address = insn.not_taken_address;
                        next_trace.offset  = insn.not_taken_offset;
                    }
                    next_trace.index = insn.index;
                }

                // Update
                trace = next_trace;
            }
        } else if (branch_packets[pkt_index].type == BRANCH_PKT_ADDRESS) { // Address packet
            // Address packetは下記の3つの場合に生成される。
            //     1. トレース開始時に、トレース開始アドレスを示すために生成される。
            //     2. Indirect branchのときに、Atom pakcet(E)に続き、生成される。
            //     3. トレースが途切れたときに、Trace On packetに続き、生成される。
            // 3.のとき、
            //     3.1 トレースが再開されたアドレスを示すAddress packetの場合と、
            //     3.2 トレースが途切れる前のAtom(E)に続く、Address packetの場合がある。
            // 3.1の場合は必要ないので無視する。
        } else {
            std::cerr << "Unknown branch packet." << std::endl;
            std::exit(1);
        }
    }
    return coverage;
}
