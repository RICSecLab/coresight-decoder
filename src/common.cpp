#include <iostream>
#include <cassert>

#include "common.hpp"
#include "utils.hpp"


BinaryFile::BinaryFile(const std::string &path)
    : path(path), data(std::move(readBinaryFile(path))) {}

bool operator<(const BinaryFile& lhs, const std::string& rhs)
{
    return lhs.path < rhs;
}

bool operator<(const std::string& lhs, const BinaryFile& rhs)
{
    return lhs < rhs.path;
}

bool operator<(const BinaryFile& lhs, const BinaryFile& rhs)
{
    return lhs.path < rhs.path;
}

const BinaryFile* getBinaryFilePtr(const BinaryFiles &binary_files, const std::string &path)
{
    const auto itr = binary_files.find(path);
    if (itr != binary_files.end()) {
        return &*itr;
    } else {
        return nullptr;
    }
}


MemoryMap::MemoryMap(const BinaryFiles &binary_files, const std::string &path,
    addr_t start_address, addr_t end_address)
    : binary_file(getBinaryFilePtr(binary_files, path)),
      start_address(start_address), end_address(end_address) {}

MemoryMap::MemoryMap(addr_t start_address, addr_t end_address)
    : binary_file(nullptr),
      start_address(start_address), end_address(end_address) {}

const std::string MemoryMap::getBinaryPath() const
{
    assert(this->binary_file != nullptr);
    return this->binary_file->path;
}

const binary_data_t& MemoryMap::getBinaryData() const
{
    assert(this->binary_file != nullptr);
    return this->binary_file->data;
}

std::optional<file_index_t> getMemoryMapIndex(
    const std::vector<MemoryMap> &memory_map, const addr_t address)
{
    for (size_t i = 0; i < memory_map.size(); i++) {
        if (memory_map[i].start_address <= address and address < memory_map[i].end_address) {
            return i;
        }
    }

    DEBUG("Jumped to an address outside the trace area: 0x%lx\n", address);
    return std::nullopt;
}

bool checkTraceRange(const MemoryMaps &memory_map, const Location &location)
{
    return memory_map[location.index].binary_file != nullptr;
}


Location::Location(addr_t offset, file_index_t index)
    : offset(offset), index(index) {}

bool Location::operator==(const Location &right) const {
    return offset == right.offset and index == right.index;
}

std::optional<Location> getLocation(const std::vector<MemoryMap> &memory_map, const addr_t address)
{
    // 指定されたアドレスがメモリマップ上に存在するから調べる。
    // ない場合、その領域はトレースする必要がない。
    std::optional<file_index_t> optional = getMemoryMapIndex(memory_map, address);
    if (not optional.has_value()) {
        return std::nullopt;
    }

    const file_index_t index = optional.value();
    const addr_t offset = address - memory_map[index].start_address;

    return Location(offset, index);
}


std::size_t std::hash<Location>::operator()(const Location &key) const
{
    const addr_t h1 = std::hash<addr_t>()(key.offset);
    const std::size_t h2 = std::hash<std::size_t>()(key.index);

    return h1 ^ h2;
}
