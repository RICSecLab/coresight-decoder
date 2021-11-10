/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <cstdint>
#include <vector>

#include "deformatter.hpp"

// Extract only the trace data corresponding to the specified trace ID.
// Reference: ARM CoreSight Architecture Specification v3.0 - Chapter D4 Trace
// Formatter https://developer.arm.com/documentation/ihi0029/e
void Deformatter::deformatTraceData(const std::uint8_t *data,
                                    const std::size_t data_size,
                                    std::vector<std::uint8_t> &deformat_data) {
  for (size_t data_idx = 0; data_idx < data_size; data_idx += 16) {
    for (int frame_byte = 0; frame_byte <= 14; ++frame_byte) {
      uint8_t new_trace_id = this->trace_id;

      // ID or Data (frame_byte = 0, 2, 4, 8, 10, 12, 14)
      if (data[data_idx + frame_byte] & 1) { // ID
        new_trace_id = data[data_idx + frame_byte] >> 1;
        uint8_t auxiliary = (data[data_idx + 15] >> (frame_byte / 2)) & 1;
        if (auxiliary == 0) {
          // The new trace ID takes effect immediately.
          this->trace_id = new_trace_id;
        }
      } else { // Data
        if (this->trace_id == this->target_trace_id) {
          uint8_t auxiliary = (data[data_idx + 15] >> (frame_byte / 2)) & 1;
          deformat_data.emplace_back(data[data_idx + frame_byte] | auxiliary);
        }
      }

      // Data (frame_byte = 1, 3, 5, 7, 9, 11, 13)
      frame_byte++;
      if (frame_byte <= 13) {
        if (this->trace_id == this->target_trace_id) {
          deformat_data.emplace_back(data[data_idx + frame_byte]);
        }
      }

      // Next byte corresponds to the new ID
      this->trace_id = new_trace_id;
    }
  }
}

void Deformatter::reset(const std::uint8_t target_trace_id) {
  this->trace_id = 0;
  this->target_trace_id = target_trace_id;
}
