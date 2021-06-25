#pragma once

#ifdef DEBUG_BUILD
# define DEBUG(fmt, ...) do {fprintf(stderr, fmt, ##__VA_ARGS__);} while (0)
#else
# define DEBUG(fmt, ...)
#endif

#include <vector>
#include <unordered_map>

using addr_t = std::uint64_t;


struct Trace {
    addr_t address;
    addr_t offset;
    size_t index;
};

struct MemoryMap {
    std::string binary_data_filename;
    addr_t start_address;
    addr_t end_address;
};

struct ProcessParam {
    const std::unordered_map<std::string, std::vector<std::uint8_t>> binary_files;

    const void* bitmap_addr;
    const int bitmap_size;

    const bool cache_mode;
};


Trace createTrace(const std::vector<MemoryMap> &memory_map, const addr_t address);
size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const uint64_t address);
