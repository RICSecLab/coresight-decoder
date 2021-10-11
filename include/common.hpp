/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

#ifdef DEBUG_BUILD
# define DEBUG(fmt, ...) do {fprintf(stderr, fmt, ##__VA_ARGS__);} while (0)
#else
# define DEBUG(fmt, ...)
#endif

#include <vector>
#include <string>
#include <set>
#include <optional>

using addr_t = std::uint64_t;
using image_id_t = std::size_t;
using binary_data_t = std::vector<std::uint8_t>;


struct MemoryImage {
    const binary_data_t data;
    const image_id_t id;

    MemoryImage(std::uint8_t* data, std::size_t data_size, image_id_t id);
    MemoryImage(binary_data_t &&data, image_id_t id);
};

struct MemoryMap {
    const addr_t start_address;
    const addr_t end_address;
    const image_id_t id;

    MemoryMap(addr_t start_address, addr_t end_address, image_id_t id);
};

struct Location {
    addr_t offset;
    image_id_t id;

    Location() = default;
    Location(addr_t offset, image_id_t id);

    bool operator==(const Location &right) const;
};


namespace std {
    template <>
    struct hash<Location> {
        std::size_t operator()(const Location &key) const;
    };
}


std::optional<image_id_t> getImageId(
    const std::vector<MemoryMap> &memory_map, const addr_t address);

// Calculate the Location (the number of the memory image and the offset on that image)
// from the address.
std::optional<Location> getLocation(
    const std::vector<MemoryMap> &memory_map, addr_t address);
