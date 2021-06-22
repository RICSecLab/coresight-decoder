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

#include "cs-decoder.h"

int write_bitmap(const char *trace_data_filename, const char trace_id,
    const int binary_file_num, struct bin_addr_range *binary_files,
    void *bitmap_addr, const int bitmap_size)
{
    checkCapstoneVersion();

    if (binary_file_num <= 0) {
        std::cerr << "Specify 1 or more for the number of binary files." << std::endl;
        return -1;
    }

    // Read trace data
    const std::vector<uint8_t> trace_data = readBinaryFile(trace_data_filename);
    const std::vector<uint8_t> deformat_trace_data = deformatTraceData(trace_data, trace_id);

    // Read binary data and entry point
    std::vector<MemoryMap> memory_map; {
        for (int i = 0; i < binary_file_num; i++) {
            // Read binary data
            const std::string binary_data_filename = binary_files[i].path;
            const std::vector<uint8_t> data = readBinaryFile(binary_data_filename);

            // Read start/end address
            const std::uint64_t start_address = binary_files[i].start;
            const std::uint64_t end_address   = binary_files[i].end;

            memory_map.emplace_back(
                MemoryMap {
                    data,
                    start_address,
                    end_address,
                }
            );
        }
    }

    uint64_t lower_address_range = 0x0;
    uint64_t upper_address_range = UINT64_MAX;
    bool cache_mode = false;

    csh handle;
    disassembleInit(&handle);

    // Calculate edge coverage from trace data and binary data
    const std::vector<Trace> coverage = process(deformat_trace_data, memory_map, handle, lower_address_range, upper_address_range, cache_mode);

    // Create a bitmap from edge coverage for fuzzing and save the bitmap
    const std::vector<uint8_t> bitmap = createBitmap(coverage, bitmap_size);
    std::copy(bitmap.begin(), bitmap.end(), (uint8_t *)bitmap_addr);

    disassembleDelete(&handle);

    return 0;
}
