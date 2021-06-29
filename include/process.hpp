#pragma once

#include "common.hpp"
#include "disassembler.hpp"
#include "trace.hpp"


enum ProcessResultType {
    PROCESS_SUCCESS,
    PROCESS_ERROR_OVERFLOW_PACKET,
    PROCESS_ERROR_TRACE_DATA_INCOMPLETE,
};

struct ProcessResult {
    std::vector<Trace> traces;
    ProcessResultType type;
};


ProcessResult process(const ProcessParam &param, const std::vector<uint8_t>& trace_data,
    const std::vector<MemoryMap> &memory_map, const csh &handle);
