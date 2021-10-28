/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

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
        std::cerr << "Usage: " << argv[0] << " [trace_data_filename] [trace_id] [binary_file_num] "
                  << "[binary_data1_filename] [binary_data1_start_address] [binary_data1_end_address] ... "
                  << "[binary_dataN_filename] [binary_dataN_start_address] [binary_dataN_end_address] [OPTIONS]" << std::endl
                  << "OPTIONS:" << std::endl
                  << "\t--bitmap-size=size     : Specify the bitmap size in hexadecimal. The default size is 0x10000." << std::endl
                  << "\t--bitmap-filename=name : Specify the file name to save the bitmap. The default name is edge_coverage_bitmap.out" << std::endl
                  << "\t--bitmap-type={edge,path} : Specify the coverage type. The default type is edge." << std::endl
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

    // Read options
    uint64_t bitmap_size = BITMAP_SIZE;
    std::string bitmap_filename = BITMAP_FILENAME;
    std::string bitmap_type = "edge";
    std::vector<std::string> trace_binary_filenames;
    for (int i = binary_file_num * 3 + 4; i < argc; ++i) {
        size_t size;
        char buf[PATH_MAX];
        if (sscanf(argv[i], "--bitmap-size=%lx", &size) == 1) {
            // TODO: Check if it is an invalid size
            bitmap_size = size;
        } else if (sscanf(argv[i], "--bitmap-filename=%s", buf) == 1) {
            bitmap_filename = std::string(buf);
        } else if (sscanf(argv[i], "--bitmap-type=%s", buf) == 1) {
            bitmap_type = std::string(buf);
        } else {
            std::cerr << "Invalid option: " << argv[i] << std::endl;
            std::exit(1);
        }
    }

    std::vector<MemoryImage> memory_images; {
        for (int id = 0; id < binary_file_num; ++id) {
            // TODO:
            const std::string path = argv[4 + id * 3];
            std::vector<uint8_t> data = readBinaryFile(path);

            // TODO: push_back
            memory_images.push_back(
                MemoryImage(std::move(data), (size_t)id)
            );
        }
    }

    std::vector<MemoryMap> memory_maps; {
        for (int id = 0; id < binary_file_num; id++) {
            // Read start/end address
            const std::uint64_t start_address = std::stol(argv[4 + id * 3 + 1], nullptr, 16);
            const std::uint64_t end_address   = std::stol(argv[4 + id * 3 + 2], nullptr, 16);

            memory_maps.emplace_back(
                MemoryMap(start_address, end_address, id)
            );
        }
    }

    // Create bitmap area
    std::vector<uint8_t> bitmap(bitmap_size);

    // Read trace data
    const std::vector<uint8_t> trace_data = readBinaryFile(trace_data_filename);

    ProcessResultType run_result = ProcessResultType::PROCESS_SUCCESS;
    ProcessResultType result = ProcessResultType::PROCESS_SUCCESS;
    if (bitmap_type == "edge") {
        Process process(
            std::move(memory_images),
            Bitmap(bitmap.data(), bitmap_size),
            Cache()
        );
        process.reset(std::move(memory_maps), trace_id);

        // Calculate edge coverage from trace data and binary data
        run_result = process.run(trace_data.data(), trace_data.size());
        result = process.final();
    } else if (bitmap_type == "path") {
        PathProcess process(
            std::move(memory_images),
            Bitmap(bitmap.data(), bitmap_size)
        );
        process.reset(std::move(memory_maps), trace_id);

        // Calculate edge coverage from trace data and binary data
        run_result = process.run(trace_data.data(), trace_data.size());
        result = process.final();
    } else {
        std::cerr << "Invalid bitmap type: " << bitmap_type << std::endl;
        std::exit(1);
    }

    if (run_result != ProcessResultType::PROCESS_SUCCESS) {
        std::cerr << "Failed to run process()." << std::endl;
        std::exit(1);
    }

    if (result != ProcessResultType::PROCESS_SUCCESS) {
        std::cerr << "Failed to run final()." << std::endl;
        std::exit(1);
    }

    // Write bitmap to the file
    writeBinaryFile(bitmap, bitmap_filename);

    return 0;
}
