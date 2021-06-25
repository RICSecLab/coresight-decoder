#include <iostream>
#include <vector>
#include <unordered_map>
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

#include "libcsdec.h"


libcsdec_t libcsdec_init(
    const int binary_file_num, const char *binary_file_path[],
    const void *bitmap_addr, const int bitmap_size, const bool cache_mode)
{
    if (binary_file_num <= 0) {
        std::cerr << "Specify 1 or more for the number of binary files" << std::endl;
        return nullptr;
    }

    checkCapstoneVersion();

    std::unordered_map<std::string, std::vector<std::uint8_t>> binary_files; {
        for (int i = 0; i < binary_file_num; i++) {
            const std::vector<uint8_t> binary_data = readBinaryFile(binary_file_path[i]);
            binary_files.insert(std::make_pair(binary_file_path[i], binary_data));
        }
    }

    // Create an object that holds the parameters determined before execution.
    ProcessParam *param = new ProcessParam {
        binary_files,
        bitmap_addr,
        bitmap_size,
        cache_mode
    };
    return (libcsdec_t)param;
}


libcsdec_result_t libcsdec_write_bitmap(const libcsdec_t libcsdec,
    const char *trace_data_filename, const char trace_id,
    const int memory_map_num, const struct libcsdec_memory_map libcsdec_memory_map[])
{
    if (memory_map_num <= 0) {
        std::cerr << "Specify 1 or more for the number of memory maps" << std::endl;
        return DECODE_ERROR;
    }

    // Cast
    ProcessParam *param = (ProcessParam*)libcsdec;

    // Read trace data
    const std::vector<uint8_t> trace_data = readBinaryFile(trace_data_filename);
    const std::vector<uint8_t> deformat_trace_data = deformatTraceData(trace_data, trace_id);

    // Read binary data and entry point
    std::vector<MemoryMap> memory_map; {
        for (int i = 0; i < memory_map_num; i++) {
            // Read binary data
            const std::string binary_data_filename = libcsdec_memory_map[i].path;
            const addr_t start_address = libcsdec_memory_map[i].start;
            const addr_t end_address = libcsdec_memory_map[i].end;

            memory_map.emplace_back(
                MemoryMap {
                    binary_data_filename,
                    start_address,
                    end_address,
                }
            );
        }
    }

    csh handle;
    disassembleInit(&handle);

    // Calculate edge coverage from trace data and binary data
    const std::vector<Trace> coverage = process(*param, deformat_trace_data, memory_map, handle);

    // Create a bitmap from edge coverage for fuzzing and save the bitmap
    const std::vector<uint8_t> bitmap = createBitmap(coverage, param->bitmap_size);
    std::copy(bitmap.begin(), bitmap.end(), (uint8_t *)param->bitmap_addr);

    disassembleDelete(&handle);

    return DECODE_SUCCESS;
}
