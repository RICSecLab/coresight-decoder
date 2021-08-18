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


libcsdec_result_t covert_result_type(ProcessResultType result);


libcsdec_t libcsdec_init_edge(
    const int binary_file_num, const char *binary_file_path[],
    void *bitmap_addr, const int bitmap_size)
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

    std::unique_ptr<Process> process = std::make_unique<Process>(
        std::move(binary_files),
        Bitmap(
            reinterpret_cast<std::uint8_t*>(bitmap_addr),
            static_cast<std::size_t>(bitmap_size)
        ),
        Cache()
    );

    // Release ownership and pass it to the C API side.
    // Therefore, do not free it here.
    return reinterpret_cast<Process*>(process.release());
}


libcsdec_result_t libcsdec_reset_edge(
    const libcsdec_t libcsdec,
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
                process->data.binary_files, path,
                libcsdec_memory_map[i].start, libcsdec_memory_map[i].end
            ));
        }
    }

    process->reset(std::move(memory_maps), trace_id);
    return LIBCEDEC_SUCCESS;
}


libcsdec_result_t libcsdec_run_edge(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const std::size_t trace_data_size)
{
    // Cast
    Process *process = reinterpret_cast<Process*>(libcsdec);

    ProcessResultType result = process->run(
        reinterpret_cast<const std::uint8_t*>(trace_data_addr), trace_data_size);
    return covert_result_type(result);
}


libcsdec_result_t libcsdec_finish_edge(const libcsdec_t libcsdec)
{
    // Cast
    Process *process = reinterpret_cast<Process*>(libcsdec);

    ProcessResultType result = process->final();
    return covert_result_type(result);
}




libcsdec_t libcsdec_init_path(
    void *bitmap_addr, const int bitmap_size)
{
    std::unique_ptr<PTrixProcess> process = std::make_unique<PTrixProcess>(
        Bitmap(
            reinterpret_cast<std::uint8_t*>(bitmap_addr),
            static_cast<std::size_t>(bitmap_size)
        )
    );

    // Release ownership and pass it to the C API side.
    // Therefore, do not free it here.
    return reinterpret_cast<PTrixProcess*>(process.release());
}


libcsdec_result_t libcsdec_reset_path(
    const libcsdec_t libcsdec,
    const char trace_id, const int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[])
{
    if (memory_map_num <= 0) {
        std::cerr << "Specify 1 or more for the number of memory maps" << std::endl;
        return LIBCSDEC_ERROR;
    }

    // Cast
    PTrixProcess *process = reinterpret_cast<PTrixProcess*>(libcsdec);

    // Read binary data and entry point
    MemoryMaps memory_maps; {
        for (int i = 0; i < memory_map_num; i++) {
            const std::string path = std::string(libcsdec_memory_map[i].path);
            memory_maps.emplace_back(MemoryMap(
                libcsdec_memory_map[i].start, libcsdec_memory_map[i].end
            ));
        }
    }

    process->reset(std::move(memory_maps), trace_id);
    return LIBCEDEC_SUCCESS;
}


libcsdec_result_t libcsdec_run_path(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const std::size_t trace_data_size)
{
    // Cast
    PTrixProcess *process = reinterpret_cast<PTrixProcess*>(libcsdec);

    ProcessResultType result = process->run(
        reinterpret_cast<const std::uint8_t*>(trace_data_addr), trace_data_size);
    return covert_result_type(result);
}


libcsdec_result_t libcsdec_finish_path(const libcsdec_t libcsdec)
{
    // Cast
    PTrixProcess *process = reinterpret_cast<PTrixProcess*>(libcsdec);

    ProcessResultType result = process->final();
    return covert_result_type(result);
}




libcsdec_result_t covert_result_type(ProcessResultType result)
{
    switch (result) {
        case ProcessResultType::PROCESS_SUCCESS:
            return LIBCEDEC_SUCCESS;
        case ProcessResultType::PROCESS_ERROR_OVERFLOW_PACKET:
            return LIBCSDEC_ERROR_OVERFLOW_PACKET;
        case ProcessResultType::PROCESS_ERROR_TRACE_DATA_INCOMPLETE:
            return LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE;
        case ProcessResultType::PROCESS_ERROR_PAGE_FAULT:
            return LIBCSDEC_ERROR_PAGE_FAULT;
        default:
            __builtin_unreachable();
    }

    return LIBCSDEC_ERROR;
}
