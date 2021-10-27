/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <iostream>
#include <cassert>

#include "trace.hpp"
#include "bitmap.hpp"


AtomTrace::AtomTrace(const Location &location)
    : has_pending_address_packet(false) {
    this->locations.emplace_back(location);
}

void AtomTrace::addLocation(const Location &location)
{
    this->locations.emplace_back(location);
}

// ELFファイル上のオフセットとして記録してあるエッジカバレッジから、bitmapを計算する。
void AtomTrace::calculateBitmapKeys(const std::size_t bitmap_size)
{
    // Direct Branchのトレースから、bitmapキーを作成する
    for (std::size_t i = 0, len = this->locations.size() - 1; i < len; ++i) {
        const Location from_location = this->locations[i];
        const Location to_location   = this->locations[i + 1];
        const std::size_t key = generateBitmapKey(from_location, to_location, bitmap_size);
        this->bitmap_keys.emplace_back(key);
    }
}

void AtomTrace::writeBitmapKeys(const Bitmap &bitmap) const
{
    // Direct branchのbitmapをコピーする
    for (const std::uint64_t key : this->bitmap_keys) {
        // bitmapのキーの値から、対応する位置の値を増やす。
        bitmap.data[key]++;
    }
}

void AtomTrace::setPendingAddressPacket()
{
    this->has_pending_address_packet = true;
}

void AtomTrace::printTraceLocations(const std::vector<MemoryMap> &memory_map) const
{
    for (std::size_t i = 0, len = this->locations.size() - 1; i < len; i++) {
        const Location prev_location = this->locations[i];
        const Location next_location = this->locations[i + 1];

        std::cout << std::hex << "0x" << prev_location.offset << " ["
                  << memory_map[prev_location.id].id << "]";
        std::cout << " -> ";
        std::cout << std::hex << "0x" << next_location.offset << " ["
                  << memory_map[next_location.id].id << "]";
        std::cout << std::endl;
    }
}


AddressTrace::AddressTrace(const Location &src_location, const Location &dest_location)
    : src_location(src_location), dest_location(dest_location), bitmap_key(0) {}

// ELFファイル上のオフセットとして記録してあるエッジカバレッジから、bitmapを計算する。
void AddressTrace::calculateBitmapKey(const std::size_t bitmap_size)
{
    const Location from_location = this->src_location;
    const Location to_location   = this->dest_location;
    const std::size_t key = generateBitmapKey(from_location, to_location, bitmap_size);
    this->bitmap_key = key;
}

void AddressTrace::writeBitmapKey(const Bitmap &bitmap) const
{
    // Indirect branchのbitmapをコピーする
    bitmap.data[this->bitmap_key]++;
}

void AddressTrace::printTraceLocation(const std::vector<MemoryMap> &memory_map) const
{
    const Location prev_location = this->src_location;
    const Location next_location = this->dest_location;

    std::cout << std::hex << "0x" << prev_location.offset << " ["
              << memory_map[prev_location.id].id << "]";
    std::cout << " -> ";
    std::cout << std::hex << "0x" << next_location.offset << " ["
              << memory_map[next_location.id].id << "]";
    std::cout << std::endl;
}
