#pragma once

std::vector<uint8_t> deformatTraceData(const std::uint8_t *data, const std::size_t data_size,
    const uint8_t target_trace_id);
