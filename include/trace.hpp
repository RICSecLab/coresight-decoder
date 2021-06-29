#pragma once

#include "common.hpp"


// locations: loc_1, loc_2, ... , loc_n-1, loc_n
// trace: loc_1 -> loc_2 -> ... -> loc_n-1 -> loc_n
// bitmap_keys: hash(loc_1, loc_2), hash(loc_2, loc_3), ... , hash(loc_n-1, loc_n)
// bitmap_key:  hash(loc_n, loc_n+1)
struct AtomTrace {
    std::vector<Location> locations;
    std::vector<std::size_t> bitmap_keys;
    bool has_pending_address_packet;

    AtomTrace() = default;
    AtomTrace(const Location &location);

    void addLocation(const Location &location);
    void calculateBitmapKeys(const std::size_t bitmap_size);
    void setPendingAddressPacket();
};


// trace: src_loation -> dest_location
// bitmap_key: hash(src_location, dest_location)
struct AddressTrace {
    Location src_location;
    Location dest_location; // branch destination address by indirect branch
    std::size_t bitmap_key;

    AddressTrace() = default;
    AddressTrace(const Location &src_location, const Location &dest_location);
    void calculateBitmapKey(const std::size_t bitmap_size);
};


enum TraceType {
    TRACE_ATOM_TYPE,
    TRACE_ADDRESS_TYPE
};

struct Trace {
    const TraceType type;
    const AtomTrace atom_trace;
    const AddressTrace address_trace;

    Trace(const AtomTrace &trace);
    Trace(const AddressTrace &trace);
};


void printTraceLocations(const std::vector<Trace> &traces, const std::vector<MemoryMap> &memory_map);
