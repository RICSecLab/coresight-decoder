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


libcsdec_t libcsdec_init_edge(void *bitmap_addr, const int bitmap_size,
    int memory_image_num, libcsdec_memory_image libcsdec_memory_image[])
{
    checkCapstoneVersion();

    std::vector<MemoryImage> memory_images; {
        for (int i = 0; i < memory_image_num; ++i) {
            assert(memory_images[i].id == std::size_t(i));

            std::vector<std::uint8_t> data(
                reinterpret_cast<std::uint8_t*>(libcsdec_memory_image[i].data) + 0,
                reinterpret_cast<std::uint8_t*>(libcsdec_memory_image[i].data) + memory_image_num
            );
            memory_images.emplace_back(
                MemoryImage(std::move(data), memory_images[i].id)
            );
        }
    }

    std::unique_ptr<Process> process = std::make_unique<Process>(
        std::move(memory_images),
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

    std::vector<MemoryMap> memory_maps; {
        for (int i = 0; i < memory_map_num; i++) {
            memory_maps.emplace_back(
                MemoryMap (
                    libcsdec_memory_map[i].start, libcsdec_memory_map[i].end,
                    libcsdec_memory_map[i].id
                )
            );
        }
    }

    process->reset(std::move(memory_maps), trace_id);
    return LIBCSDEC_SUCCESS;
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
    void *bitmap_addr, const int bitmap_size,
    int memory_image_num, libcsdec_memory_image libcsdec_memory_image[])
{
    checkCapstoneVersion();

    std::vector<MemoryImage> memory_images; {
        for (int i = 0; i < memory_image_num; ++i) {
            assert(memory_images[i].id == std::size_t(i));

            std::vector<std::uint8_t> data(
                reinterpret_cast<std::uint8_t*>(libcsdec_memory_image[i].data) + 0,
                reinterpret_cast<std::uint8_t*>(libcsdec_memory_image[i].data) + memory_image_num
            );
            memory_images.emplace_back(
                MemoryImage(std::move(data), memory_images[i].id)
            );
        }
    }

    std::unique_ptr<PathProcess> process = std::make_unique<PathProcess>(
        std::move(memory_images),
        Bitmap(
            reinterpret_cast<std::uint8_t*>(bitmap_addr),
            static_cast<std::size_t>(bitmap_size)
        )
    );

    // Release ownership and pass it to the C API side.
    // Therefore, do not free it here.
    return reinterpret_cast<PathProcess*>(process.release());
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
    PathProcess *process = reinterpret_cast<PathProcess*>(libcsdec);

    std::vector<MemoryMap> memory_maps; {
        for (int i = 0; i < memory_map_num; i++) {
            memory_maps.emplace_back(
                MemoryMap (
                    libcsdec_memory_map[i].start, libcsdec_memory_map[i].end,
                    libcsdec_memory_map[i].id
                )
            );
        }
    }

    process->reset(std::move(memory_maps), trace_id);
    return LIBCSDEC_SUCCESS;
}


libcsdec_result_t libcsdec_run_path(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const std::size_t trace_data_size)
{
    // Cast
    PathProcess *process = reinterpret_cast<PathProcess*>(libcsdec);

    ProcessResultType result = process->run(
        reinterpret_cast<const std::uint8_t*>(trace_data_addr), trace_data_size);
    return covert_result_type(result);
}


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
