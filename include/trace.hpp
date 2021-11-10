/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

#include "bitmap.hpp"
#include "common.hpp"

struct AtomTrace {
  std::vector<Location> locations;
  std::vector<std::size_t> bitmap_keys;
  bool has_pending_address_packet;

  AtomTrace() = default;
  AtomTrace(const Location &location);

  void addLocation(const Location &location);
  void calculateBitmapKeys(std::size_t bitmap_size);
  void writeBitmapKeys(const Bitmap &bitmap) const;
  void setPendingAddressPacket();
  void printTraceLocations(const std::vector<MemoryMap> &memory_map) const;
};

struct AddressTrace {
  Location src_location;
  Location dest_location;
  std::size_t bitmap_key;

  AddressTrace() = default;
  AddressTrace(const Location &src_location, const Location &dest_location);

  void calculateBitmapKey(std::size_t bitmap_size);
  void writeBitmapKey(const Bitmap &bitmap) const;
  void printTraceLocation(const std::vector<MemoryMap> &memory_map) const;
};
