#pragma once

#include "common.hpp"

#define BITMAP_SIZE 0x10000

std::vector<uint8_t> createBitmap(const std::vector<Coverage> &coverage, size_t bitmap_size);
