#include <vector>
#include <cstdint>

#include "deformatter.hpp"


// フォーマッタはトレースIDをトレースデータに埋め込むために使用される。
// そのため、フォーマッタに従い、指定されたトレースIDのトレースデータのみを
// 取り出す必要がある。
//
// 参考: ARM CoreSight Architecture Specification v3.0 - Chapter D4 Trace Formatter
// https://developer.arm.com/documentation/ihi0029/e

__attribute__((hot))
std::vector<std::uint8_t> deformatTraceData(const std::uint8_t *data, const std::size_t data_size,
    const std::uint8_t target_trace_id) {
    std::vector<uint8_t> deformat_data;
    deformat_data.reserve(data_size);

    uint8_t trace_id = 0;
    for (size_t data_idx = 0; data_idx < data_size; data_idx += 16) {
        for (int frame_byte = 0; frame_byte <= 14; ++frame_byte) {
            uint8_t new_trace_id = trace_id;

            // ID or Data (frame_byte = 0, 2, 4, 8, 10, 12, 14)
            if (data[data_idx + frame_byte] & 1) { // ID
                new_trace_id = data[data_idx + frame_byte] >> 1;
                uint8_t auxiliary = (data[data_idx + 15] >> (frame_byte / 2)) & 1;
                if (auxiliary == 0) {
                    // The new trace ID takes effect immediately.
                    trace_id = new_trace_id;
                }
            } else { // Data
                if (trace_id == target_trace_id) {
                    uint8_t auxiliary = (data[data_idx + 15] >> (frame_byte / 2)) & 1;
                    deformat_data.emplace_back(data[data_idx + frame_byte] | auxiliary);
                }
            }

            // Data (frame_byte = 1, 3, 5, 7, 9, 11, 13)
            frame_byte++;
            if (frame_byte <= 13){
                if (trace_id == target_trace_id) {
                    deformat_data.emplace_back(data[data_idx + frame_byte]);
                }
            }

            // Next byte corresponds to the new ID
            trace_id = new_trace_id;
        }
    }

    // NRVO（Named Return Value Optimization）が有効にならず、
    // コピーコンストラクタが呼ばれているため、明示的にmoveをしている。
    return std::move(deformat_data);
}
