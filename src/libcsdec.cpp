#include <iostream>
#include <vector>
#include <unordered_map>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>

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
    void *bitmap_addr, const int bitmap_size, const bool cache_mode)
{
    if (binary_file_num <= 0) {
        std::cerr << "Specify 1 or more for the number of binary files" << std::endl;
        return nullptr;
    }

    checkCapstoneVersion();

    BinaryFiles binary_files; {
        for (int i = 0; i < binary_file_num; i++) {
            binary_files.emplace(binary_file_path[i]);
        }
    }

    std::unique_ptr<Process> param = std::make_unique<Process>(
        std::move(binary_files),
        Bitmap(
            reinterpret_cast<std::uint8_t*>(bitmap_addr),
            static_cast<std::size_t>(bitmap_size)
        ),
        cache_mode,
        Cache()
    );

    // Release ownership and pass it to the C API side.
    // Therefore, do not free param here.
    return reinterpret_cast<Process*>(param.release());
}


libcsdec_result_t libcsdec_write_bitmap(const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size,
    const char trace_id, const int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[])
{
    if (memory_map_num <= 0) {
        std::cerr << "Specify 1 or more for the number of memory maps" << std::endl;
        return LIBCSDEC_ERROR;
    }

    // Cast
    Process *process = reinterpret_cast<Process*>(libcsdec);

    // Read binary data and entry point
    MemoryMaps memory_maps; {
        for (int i = 0; i < memory_map_num; i++) {
            const std::string path = std::string(libcsdec_memory_map[i].path);
            memory_maps.emplace_back(MemoryMap(
                process->binary_files, path,
                libcsdec_memory_map[i].start, libcsdec_memory_map[i].end
            ));
        }
    }

    // Calculate edge coverage from trace data and binary data
    const ProcessResultType result = process->run(
        ProcessState(std::move(memory_maps)),
        reinterpret_cast<const std::uint8_t*>(trace_data_addr),
        trace_data_size, trace_id
    );

    switch (result) {
        case ProcessResultType::PROCESS_SUCCESS:
            return LIBCEDEC_SUCCESS;
        case ProcessResultType::PROCESS_ERROR_OVERFLOW_PACKET:
            return LIBCSDEC_ERROR_OVERFLOW_PACKET;
        case ProcessResultType::PROCESS_ERROR_TRACE_DATA_INCOMPLETE:
            return LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE;
        default:
            __builtin_unreachable();
    }

    return LIBCSDEC_ERROR;
}
