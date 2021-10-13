/** @file
    libcsdec C wrapper library implementation.
**/
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

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


/**
    Initializes persistent objects for edge coverage mode and returns the pointer.

    @param  bitmap_addr                             The bitmap address.
    @param  bitmap_size                             The size of the bitmap.

    @return                                         The pointer to the object used by libcsdec.
**/
libcsdec_t libcsdec_init_edge(void *bitmap_addr, const int bitmap_size)
{
    checkCapstoneVersion();

    std::unique_ptr<Process> process = std::make_unique<Process>(
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


/**
    Resets the deocder to the initial state for edge coverage mode. This function should be called before starting a new decode session.

    @param  libcsdec                                The decoding session context.
    @param  trace_id                                The trace ID.
    @param  memory_map_num                          The number of the memory map entries.
    @param  libcsdec_memory_map                     The array of all traced memory map infomation.

    @retval LIBCSDEC_SUCCESS                        Reset succeeded.
    @retval LIBCSDEC_ERROR                          Reset failed. Invalid memory map.
**/
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

    MemoryMaps memory_maps; {
        for (int i = 0; i < memory_map_num; i++) {
            const std::string path = std::string(libcsdec_memory_map[i].path);

            // If this binary file has not been loaded yet, load it.
            if (process->data.binary_files.find(path) == process->data.binary_files.end()) {
                process->data.binary_files.emplace(path);
            }

            memory_maps.emplace_back(MemoryMap(
                process->data.binary_files, path,
                libcsdec_memory_map[i].start, libcsdec_memory_map[i].end
            ));
        }
    }

    process->reset(std::move(memory_maps), trace_id);
    return LIBCSDEC_SUCCESS;
}


/**
    Decodes given trace data and generates the edge coverage bitmap. The trace data can be fragment as the deocder can process afterwards using the subsequent trace data.

    @param  libcsdec                                The decoding session context.
    @param  trace_data_addr                         The trace data address.
    @param  trace_data_size                         The size of the trace data.

    @retval LIBCSDEC_SUCCESS                        Decode succeeded.
    @retval LIBCSDEC_ERROR                          Decode failed.
    @retval LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE    Decode failed due to the trace data is incomplete.
    @retval LIBCSDEC_ERROR_PAGE_FAULT               Decode failed due to the address does not exist in the memory map.
**/
libcsdec_result_t libcsdec_run_edge(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size)
{
    // Cast
    Process *process = reinterpret_cast<Process*>(libcsdec);

    ProcessResultType result = process->run(
        reinterpret_cast<const std::uint8_t*>(trace_data_addr), trace_data_size);
    return covert_result_type(result);
}


/**
    Finalizes the deocding session for the edge coverage mode. This function should be called after the end of each decoding session. It checks if the decoder is not in invalid state.

    @param  libcsdec                                The decoding session context.

    @retval LIBCSDEC_SUCCESS                        Finalize succeeded.
    @retval LIBCSDEC_ERROR                          Finalize failed.
    @retval LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE    Finalize failed due to the trace data is incomplete.
**/
libcsdec_result_t libcsdec_finish_edge(const libcsdec_t libcsdec)
{
    // Cast
    Process *process = reinterpret_cast<Process*>(libcsdec);

    ProcessResultType result = process->final();
    return covert_result_type(result);
}




/**
    Initializes persistent objects for path coverage mode and returns the pointer.

    @param  bitmap_addr                             The bitmap address.
    @param  bitmap_size                             The size of the bitmap.

    @return                                         The pointer to the object used by libcsdec.
**/
libcsdec_t libcsdec_init_path(
    void *bitmap_addr, const int bitmap_size)
{
    std::unique_ptr<PathProcess> process = std::make_unique<PathProcess>(
        Bitmap(
            reinterpret_cast<std::uint8_t*>(bitmap_addr),
            static_cast<std::size_t>(bitmap_size)
        )
    );

    // Release ownership and pass it to the C API side.
    // Therefore, do not free it here.
    return reinterpret_cast<PathProcess*>(process.release());
}


/**
    Resets the deocder to the initial state for path coverage mode. This function should be called before starting a new decode session.

    @param  libcsdec                                The decoding session context.
    @param  trace_id                                The trace ID.
    @param  memory_map_num                          The number of the memory map entries.
    @param  libcsdec_memory_map                     The array of all traced memory map infomation.

    @retval LIBCSDEC_SUCCESS                        Reset succeeded.
    @retval LIBCSDEC_ERROR                          Reset failed. Invalid memory map.
**/
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
    PathProcess *process = reinterpret_cast<PathProcess*>(libcsdec);

    MemoryMaps memory_maps; {
        for (int i = 0; i < memory_map_num; i++) {
            const std::string path = std::string(libcsdec_memory_map[i].path);
            memory_maps.emplace_back(MemoryMap(
                libcsdec_memory_map[i].start, libcsdec_memory_map[i].end
            ));
        }
    }

    process->reset(std::move(memory_maps), trace_id);
    return LIBCSDEC_SUCCESS;
}


/**
    Decodes given trace data and generates the path coverage bitmap. The trace data can be fragment as the deocder can process afterwards using the subsequent trace data.

    @param  libcsdec                                The decoding session context.
    @param  trace_data_addr                         The trace data address.
    @param  trace_data_size                         The size of the trace data.

    @retval LIBCSDEC_SUCCESS                        Decode succeeded.
    @retval LIBCSDEC_ERROR                          Decode failed.
    @retval LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE    Decode failed due to the trace data is incomplete.
    @retval LIBCSDEC_ERROR_PAGE_FAULT               Decode failed due to the address does not exist in the memory map.
**/
libcsdec_result_t libcsdec_run_path(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size)
{
    // Cast
    PathProcess *process = reinterpret_cast<PathProcess*>(libcsdec);

    ProcessResultType result = process->run(
        reinterpret_cast<const std::uint8_t*>(trace_data_addr), trace_data_size);
    return covert_result_type(result);
}


/**
    Finalizes the deocding session for the path coverage mode. This function should be called after the end of each decoding session. It checks if the decoder is not in invalid state.

    @param  libcsdec                                The decoding session context.

    @retval LIBCSDEC_SUCCESS                        Finalize succeeded.
    @retval LIBCSDEC_ERROR                          Finalize failed.
    @retval LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE    Finalize failed due to the trace data is incomplete.
**/
libcsdec_result_t libcsdec_finish_path(const libcsdec_t libcsdec)
{
    // Cast
    PathProcess *process = reinterpret_cast<PathProcess*>(libcsdec);

    ProcessResultType result = process->final();
    return covert_result_type(result);
}




libcsdec_result_t covert_result_type(ProcessResultType result)
{
    switch (result) {
        case ProcessResultType::PROCESS_SUCCESS:
            return LIBCSDEC_SUCCESS;
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
