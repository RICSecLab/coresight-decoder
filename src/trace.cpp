#include <iostream>
#include <cassert>

#include "trace.hpp"
#include "bitmap.hpp"


AtomTrace::AtomTrace(const Location &location)
    : has_pending_address_packet(false) {
    this->locations.emplace_back(location);
}

void AtomTrace::addLocation(const Location &location)
{
    this->locations.emplace_back(location);
}

void AtomTrace::calculateBitmapKeys(const std::size_t bitmap_size)
{
    // Direct Branchのトレースから、bitmapキーを作成する
    for (std::size_t i = 0, len = this->locations.size() - 1; i < len; ++i) {
        const Location from_location = this->locations[i];
        const Location to_location   = this->locations[i + 1];
        const std::size_t key = generateBitmapKey(from_location, to_location, bitmap_size);
        this->bitmap_keys.emplace_back(key);
    }
}

void AtomTrace::setPendingAddressPacket()
{
    this->has_pending_address_packet = true;
}


AddressTrace::AddressTrace(const Location &src_location, const Location &dest_location)
    : src_location(src_location), dest_location(dest_location), bitmap_key(0) {}

void AddressTrace::calculateBitmapKey(const std::size_t bitmap_size)
{
    const Location from_location = this->src_location;
    const Location to_location   = this->dest_location;
    const std::size_t key = generateBitmapKey(from_location, to_location, bitmap_size);
    this->bitmap_key = key;
}


Trace::Trace(const AtomTrace &trace)
    : type(TRACE_ATOM_TYPE), atom_trace(trace), address_trace(AddressTrace()) {}

Trace::Trace(const AddressTrace &trace)
    : type(TRACE_ADDRESS_TYPE), atom_trace(AtomTrace()), address_trace(trace) {}


void printTraceLocations(const std::vector<Trace> &traces, const std::vector<MemoryMap> &memory_map)
{
    // Print edge coverage
    for (const Trace &trace : traces) {
        if (trace.type == TRACE_ATOM_TYPE) {
            const AtomTrace atom_trace = trace.atom_trace;

            for (std::size_t i = 0, len = atom_trace.locations.size() - 1; i < len; i++) {
                const Location prev_location = atom_trace.locations[i];
                const Location next_location = atom_trace.locations[i + 1];

                std::cout << std::hex << "0x" << prev_location.offset << " ["
                          << memory_map[prev_location.index].getBinaryPath() << "]";
                std::cout << " -> ";
                std::cout << std::hex << "0x" << next_location.offset << " ["
                          << memory_map[next_location.index].getBinaryPath() << "]";
                std::cout << std::endl;
            }
        } else if (trace.type == TRACE_ADDRESS_TYPE) {
            const AddressTrace address_trace = trace.address_trace;

            const Location prev_location = address_trace.src_location;
            const Location next_location = address_trace.dest_location;

            std::cout << std::hex << "0x" << prev_location.offset << " ["
                      << memory_map[prev_location.index].getBinaryPath() << "]";
            std::cout << " -> ";
            std::cout << std::hex << "0x" << next_location.offset << " ["
                      << memory_map[next_location.index].getBinaryPath() << "]";
            std::cout << std::endl;
        } else {
            __builtin_unreachable();
        }
    }
}
