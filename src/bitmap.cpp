/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

#include "bitmap.hpp"
#include "trace.hpp"

Bitmap::Bitmap(uint8_t* data, std::size_t size)
    : data(data), size(size) {}

void Bitmap::reset() const
{
    // Fill the bitmap with zeros.
    std::fill(this->data, this->data + this->size, 0);
}


std::uint64_t generateBitmapKey(const Location& from_location, const Location& to_location,
    const std::size_t bitmap_size)
{
    //ELF上のオフセットの値をハッシュ関数を通して、ランダムな値に変換し、
    // それを用いて、bitmapのキーを計算する。
    //
    // aflのtechnical_details.txtに書いてある通り、AFLのカバレッジの計算は以下のようである。
    //     cur_location = <COMPILE_TIME_RANDOM>;
    //     shared_mem[cur_location ^ prev_location]++;
    //     prev_location = cur_location >> 1;
    //
    const std::uint64_t to_h   = std::hash<Location>()(from_location);
    const std::uint64_t from_h = std::hash<Location>()(to_location);
    return (to_h ^ (from_h >> 1)) & (bitmap_size - 1);
}
