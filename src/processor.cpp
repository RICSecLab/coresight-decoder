#include <iostream>
#include <vector>
#include <cassert>
#include <cstdint>
#include <cstring>

#include "process.hpp"
#include "decoder.hpp"
#include "deformatter.hpp"
#include "disassembler.hpp"
#include "utils.hpp"
#include "common.hpp"
#include "bitmap.hpp"
#include "cache.hpp"

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
    bool cache_mode = false;
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
        } else if (strcmp(argv[i], "--cache-mode") == 0) {
            cache_mode = true;
        } else {
            std::cerr << "Invalid option: " << argv[i] << std::endl;
            std::exit(1);
        }
    }

    csh handle;
    disassembleInit(&handle);

    // Calculate edge coverage from trace data and binary data
    const std::vector<Trace> coverage = process(deformat_trace_data, memory_map, handle, lower_address_range, upper_address_range, cache_mode);

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
