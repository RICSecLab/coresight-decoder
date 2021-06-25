#pragma once

#include "common.hpp"
#include "disassembler.hpp"
#include "trace.hpp"


std::vector<Trace> process(const ProcessParam &param, const std::vector<uint8_t>& trace_data,
    const std::vector<MemoryMap> &memory_map, const csh &handle);
