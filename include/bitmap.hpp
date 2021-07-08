#pragma once

#include "common.hpp"

#define BITMAP_SIZE 0x10000
#define BITMAP_FILENAME "edge_coverage_bitmap.out"


struct Bitmap
{
    // Bitmapを書き込むためのアドレス
    const std::uint8_t* data;
    // Bitmapのサイズ
    const std::size_t size;

    Bitmap(const uint8_t* data, std::size_t size);

    void resetBitmap() const;
    void incrementBitmap(std::size_t key) const;
};

std::uint64_t generateBitmapKey(const Location& from_location, const Location& to_location,
    std::size_t bitmap_size);
