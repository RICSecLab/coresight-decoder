/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "bitmap.hpp"
#include "trace.hpp"

Bitmap::Bitmap(uint8_t *data, std::size_t size) : data(data), size(size) {}

void Bitmap::reset() const {
  // Fill the bitmap with zeros.
  std::fill(this->data, this->data + this->size, 0);
}

std::uint64_t generateBitmapKey(const Location &from_location,
                                const Location &to_location,
                                const std::size_t bitmap_size) {
  const std::uint64_t to_h = std::hash<Location>()(from_location);
  const std::uint64_t from_h = std::hash<Location>()(to_location);
  return (to_h ^ (from_h >> 1U)) & (bitmap_size - 1);
}
