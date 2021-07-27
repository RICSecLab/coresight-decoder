#pragma once

struct Deformatter
{
    std::uint8_t trace_id;
    std::uint8_t target_trace_id;

    std::vector<std::uint8_t> deformat_data;

    // Disable copy constructor.
    Deformatter(const Deformatter&) = delete;
    Deformatter& operator=(const Deformatter&) = delete;

    Deformatter() = default;

    void deformatTraceData(
        const std::uint8_t *data, const std::size_t data_size);
    void reset(std::uint8_t target_trace_id);
};
