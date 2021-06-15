#pragma once

#include "common.hpp"

#define BITMAP_SIZE 0x10000
#define BITMAP_FILENAME "edge_coverage_bitmap.out"

std::vector<uint8_t> createBitmap(const std::vector<Coverage> &coverage, size_t bitmap_size);
uint64_t generateBitmapKey(const uint64_t from, const uint64_t to, const size_t bitmap_size);
