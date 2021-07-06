#pragma once

#ifdef DEBUG_BUILD
# define DEBUG(fmt, ...) do {fprintf(stderr, fmt, ##__VA_ARGS__);} while (0)
#else
# define DEBUG(fmt, ...)
#endif

#include <vector>
#include <unordered_map>

using addr_t = std::uint64_t;
using binary_data_t = std::vector<uint8_t>;

struct MemoryMap {
    const std::string binary_data_filename;
    const binary_data_t *binary_data;
    const addr_t start_address;
    const addr_t end_address;

    MemoryMap(const std::string &binary_data_filename,
        const std::unordered_map<std::string, std::vector<std::uint8_t>> &binary_files,
        const addr_t start_address, const addr_t end_address);
};

struct Location {
    addr_t offset;
    std::size_t index;

    Location() = default;
    Location(const Location &location);
    Location(const addr_t offset, const std::size_t index);
    Location(const std::vector<MemoryMap> &memory_map, const addr_t address);
};

namespace std {
template <>
struct hash<Location> {
    size_t operator()(const Location &key) const {
        std::size_t h1 = std::hash<addr_t>()(key.offset);
        std::size_t h2 = std::hash<std::size_t>()(key.index);

        return h1 ^ h2;
    }
};
}

size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const uint64_t address);
