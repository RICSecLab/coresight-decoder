#pragma once

#ifdef DEBUG_BUILD
# define DEBUG(fmt, ...) do {fprintf(stderr, fmt, ##__VA_ARGS__);} while (0)
#else
# define DEBUG(fmt, ...)
#endif

#include <vector>
#include <string>
#include <set>

using addr_t = std::uint64_t;
using file_index_t = std::size_t;
using binary_data_t = std::vector<uint8_t>;


struct BinaryFile {
    const std::string path;
    const binary_data_t data;

    // Disable copy constructor.
    BinaryFile(const BinaryFile&) = delete;
    BinaryFile& operator=(const BinaryFile&) = delete;

    BinaryFile(const std::string &path);
};

// Transparent comparison for BinaryFile.
bool operator<(const BinaryFile& lhs, const std::string& rhs);
bool operator<(const std::string& lhs, const BinaryFile& rhs);
bool operator<(const BinaryFile& lhs, const BinaryFile& rhs);

// Cache for binary files in the area to be traced.
using BinaryFiles = std::set<BinaryFile, std::less<>>;

// Find a BinaryFile with a matching file path in BinaryFiles.
// If not found, return nullptr.
const BinaryFile* getBinaryFilePtr(const BinaryFiles &binary_files, const std::string &path);


struct MemoryMap {
    const BinaryFile *binary_file;
    const addr_t start_address;
    const addr_t end_address;

    MemoryMap(const BinaryFiles &binary_files, const std::string &path,
        const addr_t start_address, const addr_t end_address);

    const std::string getBinaryPath() const;
    const binary_data_t& getBinaryData() const;
};

using MemoryMaps = std::vector<MemoryMap>;

std::size_t getMemoryMapIndex(const MemoryMaps &memory_maps, const uint64_t address);


struct Location {
    addr_t offset;
    file_index_t index;

    Location() = default;
    Location(const addr_t offset, const file_index_t index);
    Location(const std::vector<MemoryMap> &memory_map, const addr_t address);

    bool operator==(const Location &right) const;
};

namespace std {
    template <>
    struct hash<Location> {
        std::size_t operator()(const Location &key) const;
    };
}
