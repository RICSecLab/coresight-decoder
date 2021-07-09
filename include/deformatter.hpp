#pragma once

__attribute__((hot))
std::vector<std::uint8_t> deformatTraceData(const std::uint8_t *data, std::size_t data_size,
        std::uint8_t target_trace_id);
