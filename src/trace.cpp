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
    for (std::size_t i = 0; i < this->locations.size() - 1; ++i) {
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
