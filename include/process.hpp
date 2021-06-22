#pragma once

#include "common.hpp"
#include "disassembler.hpp"

std::vector<Trace> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle,
    const uint64_t lower_address_range, const uint64_t uppper_address_range, const bool cache_mode);
