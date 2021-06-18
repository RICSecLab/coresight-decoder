#pragma once

#ifdef DEBUG_BUILD
# define DEBUG(fmt, ...) do {fprintf(stderr, fmt, ##__VA_ARGS__);} while (0)
#else
# define DEBUG(fmt, ...)
#endif


using addr_t = std::uint64_t;


struct Trace {
    addr_t address;
    addr_t offset;
    size_t index;
};

struct MemoryMap {
    std::vector<uint8_t> binary_data;
    uint64_t start_address;
    uint64_t end_address;
};


Trace createTrace(const std::vector<MemoryMap> &memory_map, const addr_t address);
size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const uint64_t address);
