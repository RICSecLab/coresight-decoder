#pragma once

#include "common.hpp"
#include "trace.hpp"

#define BITMAP_SIZE 0x10000
#define BITMAP_FILENAME "edge_coverage_bitmap.out"

std::vector<uint8_t> createBitmap(const std::vector<Trace> &traces, size_t bitmap_size);
uint64_t generateBitmapKey(const addr_t from_offset, const size_t from_index, const addr_t to_offset, const size_t to_index, const size_t bitmap_size);
uint64_t generateBitmapKey(const Location& from_location, const Location& to_location, const size_t bitmap_size);
