#pragma once

#include "common.hpp"
#include "trace.hpp"
#include "cache.hpp"

struct ProcessParam {
    const std::unordered_map<std::string, std::vector<std::uint8_t>> binary_files;

    const void* bitmap_addr;
    const int bitmap_size;

    const bool cache_mode;
    Cache cache;
};

enum ProcessResultType {
    PROCESS_SUCCESS,
    PROCESS_ERROR_OVERFLOW_PACKET,
    PROCESS_ERROR_TRACE_DATA_INCOMPLETE,
};

struct ProcessResult {
    std::vector<Trace> traces;
    ProcessResultType type;
};


ProcessResult process(ProcessParam &param, const std::vector<uint8_t>& trace_data,
    const std::vector<MemoryMap> &memory_map, const csh &handle);
