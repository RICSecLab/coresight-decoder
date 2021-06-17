#pragma once

#ifdef DEBUG_BUILD
# define DEBUG(fmt, ...) do {fprintf(stderr, fmt, ##__VA_ARGS__);} while (0)
#else
# define DEBUG(fmt, ...)
#endif


using addr_t = std::uint64_t;


struct Coverage {
    uint64_t address;
    uint64_t binary_offset;
    size_t binary_file_index;
};

struct MemoryMap {
    std::vector<uint8_t> binary_data;
    uint64_t start_address;
    uint64_t end_address;
};


size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const uint64_t address);
