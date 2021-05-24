#include <vector>
#include <cstdint>

#include "deformatter.hpp"

std::vector<uint8_t> deformat_trace_data(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> deformat_data;
    for (size_t data_idx = 0; data_idx < data.size(); data_idx += 16) {
        for (int frame_byte = 0; frame_byte < 15; ++frame_byte) {
            if (frame_byte % 2 == 0) {
                if (data[data_idx + frame_byte] & 1) { // ID
                    // TODO:
                } else { // Data
                    uint8_t auxiliary = (data[data_idx + 15] >> (frame_byte / 2)) & 1;
                    deformat_data.emplace_back(data[data_idx + frame_byte] | auxiliary);
                }
            } else {
                deformat_data.emplace_back(data[data_idx + frame_byte]);
            }
        }
    }
    return deformat_data;
}
