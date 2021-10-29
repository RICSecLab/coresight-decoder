/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

#include "common.hpp"

#define BITMAP_SIZE 0x10000
#define BITMAP_FILENAME "edge_coverage_bitmap.out"


struct Bitmap
{
    // Address for writing the bitmap
    std::uint8_t* const data;
    // Size of the bitmap
    const std::size_t size;

    Bitmap(uint8_t* data, std::size_t size);

    void reset() const;
};

std::uint64_t generateBitmapKey(const Location& from_location, const Location& to_location,
    std::size_t bitmap_size);
