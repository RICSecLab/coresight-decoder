/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <iostream>
#include <cassert>

#include "common.hpp"
#include "utils.hpp"


MemoryImage::MemoryImage(std::uint8_t* data, std::size_t data_size, image_id_t id)
    : data(std::vector<std::uint8_t>(data + 0, data + data_size)), id(id) {}

MemoryImage::MemoryImage(binary_data_t &&data, image_id_t id)
    : data(std::move(data)), id(id) {}

MemoryMap::MemoryMap(addr_t start_address, addr_t end_address, image_id_t id)
    : start_address(start_address), end_address(end_address), id(id) {}

Location::Location(addr_t offset, image_id_t id)
    : offset(offset), id(id) {}


bool Location::operator==(const Location &right) const {
    return offset == right.offset and id == right.id;
}

std::size_t std::hash<Location>::operator()(const Location &key) const
{
    const addr_t h1 = std::hash<addr_t>()(key.offset);
    const std::size_t h2 = std::hash<std::size_t>()(key.id);

    return h1 ^ h2;
}


std::optional<image_id_t> getImageId(
    const std::vector<MemoryMap> &memory_maps, const addr_t address)
{
    for (size_t i = 0; i < memory_maps.size(); i++) {
        if (memory_maps[i].start_address <= address and address < memory_maps[i].end_address) {
            return memory_maps[i].id;
        }
    }

    DEBUG("Jumped to an address outside the trace area: 0x%lx\n", address);
    return std::nullopt;
}

std::optional<Location> getLocation(const std::vector<MemoryMap> &memory_maps, const addr_t address)
{
    // Checks if the specified address exists on the memory map.
    std::optional<image_id_t> optional = getImageId(memory_maps, address);
    if (not optional.has_value()) {
        return std::nullopt;
    }

    const image_id_t id = optional.value();
    const addr_t offset = address - memory_maps[id].start_address;

    return Location(offset, id);
}
