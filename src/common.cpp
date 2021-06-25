#include <vector>
#include <iostream>

#include "common.hpp"


Location::Location(const Location &location)
    : offset(location.offset), index(location.index) {}

Location::Location(const addr_t offset, const std::size_t index)
{
    this->offset = offset;
    this->index = index;
}

Location::Location(const std::vector<MemoryMap> &memory_map, const addr_t address)
{
    const size_t index = getMemoryMapIndex(memory_map, address);
    const addr_t offset = address - memory_map[index].start_address;

    this->offset = offset;
    this->index = index;
}

size_t getMemoryMapIndex(const std::vector<MemoryMap> &memory_map, const addr_t address)
{
    for (size_t i = 0; i < memory_map.size(); i++) {
        if (memory_map[i].start_address <= address and address < memory_map[i].end_address) {
            return i;
        }
    }
    std::cerr << "Failed to find any binary data that matched the address: " << std::hex << address << std::endl;
    std::exit(1);
}
