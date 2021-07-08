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

std::size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const addr_t address)
{
    for (size_t i = 0; i < memory_map.size(); i++) {
        if (memory_map[i].start_address <= address and address < memory_map[i].end_address) {
            return i;
        }
    }
    std::cerr << "Failed to find any binary data that matched the address: "
              << std::hex << address << std::endl;
    std::exit(1);
}


Location::Location(addr_t offset, file_index_t index)
    : offset(offset), index(index) {}

Location::Location(const std::vector<MemoryMap> &memory_map, const addr_t address)
{
    const size_t index = getMemoryMapIndex(memory_map, address);
    const addr_t offset = address - memory_map[index].start_address;

    this->offset = offset;
    this->index = index;
}

bool Location::operator==(const Location &right) const {
    return offset == right.offset and index == right.index;
}

std::size_t std::hash<Location>::operator()(const Location &key) const
{
    const addr_t h1 = std::hash<addr_t>()(key.offset);
    const std::size_t h2 = std::hash<std::size_t>()(key.index);

    return h1 ^ h2;
}
