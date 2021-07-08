#include <iostream>
#include <vector>
#include <cassert>
#include <cstdint>
#include <cstring>

#include <linux/limits.h>

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
                  << "\t--trace-binary-filename=name : Specifies the name of the binary file to trace." << std::endl
                  << "\t                               This option may be used multiple times to specify multiple binary files." << std::endl
                  << "\t--bitmap-mode                : Enable bitmap calculation." << std::endl
                  << "\t--bitmap-size=size           : Specify the bitmap size in hexadecimal. The default size is 0x10000." << std::endl
                  << "\t--bitmap-filename=name       : Specify the file name to save the bitmap. The default name is edge_coverage_bitmap.out" << std::endl
                  << "\t--cache-mode                 : Enable cache mode. This mode speeds up the decoding process by saving the disassemble" << std::endl
                  << "\t                               and trace results in the software cache."
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
    const std::vector<uint8_t> deformat_trace_data = deformatTraceData((std::uint8_t*)trace_data.data(), trace_data.size(), trace_id);

    // Read options
    bool bitmap_mode = false;
    uint64_t bitmap_size = BITMAP_SIZE;
    std::string bitmap_filename = BITMAP_FILENAME;
    std::vector<std::string> trace_binary_filenames;
    bool cache_mode = false;
    for (int i = binary_file_num * 3 + 4; i < argc; ++i) {
        size_t size;
        char buf[PATH_MAX];
        if (sscanf(argv[i], "--trace-binary-filename=%s", buf)) {
            trace_binary_filenames.emplace_back(std::string(buf));
        } else if (strcmp(argv[i], "--bitmap-mode") == 0) {
            bitmap_mode = true;
        } else if (sscanf(argv[i], "--bitmap-size=%lx", &size) == 1) {
            // TODO: Check if it is an invalid size
            bitmap_size = size;
        } else if (sscanf(argv[i], "--bitmap-filename=%s", buf) == 1) {
            bitmap_filename = std::string(buf);
        } else if (strcmp(argv[i], "--cache-mode") == 0) {
            cache_mode = true;
        } else {
            std::cerr << "Invalid option: " << argv[i] << std::endl;
            std::exit(1);
        }
    }

    BinaryFiles binary_files; {
        for (const std::string &filename : trace_binary_filenames) {
            binary_files.emplace(filename);
        }
    }

    MemoryMaps memory_maps; {
        for (int i = 0; i < binary_file_num; i++) {
            // Read binary data
            const std::string path = argv[4 + i * 3];

            // Read start/end address
            const std::uint64_t start_address = std::stol(argv[4 + i * 3 + 1], nullptr, 16);
            const std::uint64_t end_address   = std::stol(argv[4 + i * 3 + 2], nullptr, 16);

            memory_maps.emplace_back(MemoryMap(
                binary_files, path,
                start_address, end_address
            ));
        }
    }

    csh handle;
    disassembleInit(&handle);

    Cache cache;

    ProcessParam param {
        std::move(binary_files),
        nullptr,
        (int)bitmap_size,
        cache_mode,
        cache
    };

    // Calculate edge coverage from trace data and binary data
    const ProcessResult result = process(param, deformat_trace_data, memory_maps, handle);
    if (result.type != PROCESS_SUCCESS) {
        std::cerr << "Failed to run process()." << std::endl;
        std::exit(1);
    }

    // Create a bitmap from edge coverage for fuzzing and save the bitmap
    if (bitmap_mode) {
        std::vector<uint8_t> bitmap(bitmap_size);
        std::uint8_t *bitmap_address = bitmap.data();
        writeBitmap(result.traces, bitmap_address, bitmap_size);
        writeBinaryFile(bitmap, bitmap_filename);
    }

    printTraceLocations(result.traces, memory_maps);

    disassembleDelete(&handle);
    return 0;
}
