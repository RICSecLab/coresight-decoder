/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cache.hpp"
#include "common.hpp"
#include "decoder.hpp"
#include "deformatter.hpp"
#include "disassembler.hpp"
#include "process.hpp"
#include "trace.hpp"
#include "utils.hpp"

void Process::reset(std::vector<MemoryMap> &&memory_maps,
                    const std::uint8_t target_trace_id) {
  this->data.bitmap.reset();
  this->deformatter.reset(target_trace_id);
  this->decoder.reset();
  this->state.reset(std::move(memory_maps));
}

ProcessResultType Process::final() {
  // If the area to be traced is limited on the tracer side, this condition may
  // not be satisfied. if (state.has_pending_address_packet) {
  //     // This trace data is incomplete. There is no Address packet following
  //     Atom packet. return
  //     ProcessResultType::PROCESS_ERROR_TRACE_DATA_INCOMPLETE;
  // }

  return ProcessResultType::PROCESS_SUCCESS;
}

ProcessResultType Process::run(const std::uint8_t *trace_data_addr,
                               const std::size_t trace_data_size) {
  // Read trace data and deformat trace data.
  this->deformatter.deformatTraceData(trace_data_addr, trace_data_size,
                                      decoder.trace_data);

  const std::size_t size = this->decoder.trace_data.size();
  while (this->decoder.trace_data_offset < size) {
    const Packet packet = this->decoder.decodePacket();
    DEBUG("%s\n", packet.toString().c_str());

    // The length of the packet data is insufficient and decoding cannot be
    // performed correctly at this time. In this case, the decoding process is
    // put to rest and new data is received.
    if (packet.type == PKT_INCOMPLETE) {
      return ProcessResultType::PROCESS_SUCCESS;
    }

    this->decoder.trace_data_offset += packet.size;

    switch (this->decoder.state) {
    case DecodeState::START:
    case DecodeState::RESTART: {
      switch (packet.type) {
      case ETM4_PKT_I_ATOM_F1:
      case ETM4_PKT_I_ATOM_F2:
      case ETM4_PKT_I_ATOM_F3:
      case ETM4_PKT_I_ATOM_F4:
      case ETM4_PKT_I_ATOM_F5:
      case ETM4_PKT_I_ATOM_F6: {
        // The first branch packet is always an address pocket.
        // Otherwise, the trace start address is not known.
        std::cerr << "The first branch packet is always an address pocket."
                  << std::endl;
        std::exit(EXIT_FAILURE);
      }

      case ETM4_PKT_I_ADDR_S_IS0:
      case ETM4_PKT_I_ADDR_L_64IS0:
      case ETM4_PKT_I_ADDR_CTXT_L_64IS0: {
        const std::optional<Location> optional_start_location =
            getLocation(this->state.memory_maps, packet.addr);

        // The trace is starting from an address that is not on the memory map.
        if (not optional_start_location.has_value()) {
          return ProcessResultType::PROCESS_ERROR_PAGE_FAULT;
        }

        const std::optional<AddressTrace> optional_trace =
            processAddressPacket(packet);

        if (optional_trace.has_value()) {
          AddressTrace trace = optional_trace.value();

          trace.calculateBitmapKey(this->data.bitmap.size);
          trace.writeBitmapKey(this->data.bitmap);
#if defined(PRINT_EDGE_COV)
          trace.printTraceLocation(state.memory_maps);
#endif
        }

        this->decoder.state = DecodeState::TRACE;
        break;
      }

      default:
        break;
      }
      break;
    }

    case DecodeState::TRACE: {
      switch (packet.type) {
      case ETM4_PKT_I_ATOM_F1:
      case ETM4_PKT_I_ATOM_F2:
      case ETM4_PKT_I_ATOM_F3:
      case ETM4_PKT_I_ATOM_F4:
      case ETM4_PKT_I_ATOM_F5:
      case ETM4_PKT_I_ATOM_F6: {
        // When processing an atom packet, there is an unprocessed indirect
        // branch instruction. If there is an unprocessed indirect branch
        // instruction, there must be an address packet, not an atom packet.
        // When this error occurs, there is probably a bug in this program
        // itself.
        assert(this->state.has_pending_address_packet == false);
        assert(this->state.prev_location.has_value() == true);

#if defined(CACHE_MODE)
        const TraceKey trace_key(this->state.prev_location.value(),
                                 packet.en_bits, packet.en_bits_len);

        // Check for edge coverage in the cache, calculated from the same trace
        // data and starting address. If it exists, we can skip the decoding
        // process of a atom packet.
        if (this->data.cache.isCachedTrace(trace_key)) {
          AtomTrace trace = this->data.cache.getTraceCache(trace_key);

          this->state.prev_location = trace.locations.back();
          this->state.has_pending_address_packet =
              trace.has_pending_address_packet;

          trace.writeBitmapKeys(this->data.bitmap);
#if defined(PRINT_EDGE_COV)
          trace.printTraceLocations(this->state.memory_maps);
#endif
        } else {
          AtomTrace trace = processAtomPacket(packet);

          trace.writeBitmapKeys(this->data.bitmap);
#if defined(PRINT_EDGE_COV)
          trace.printTraceLocations(this->state.memory_maps);
#endif

          this->data.cache.addTraceCache(trace_key, trace);
        }
#else
        AtomTrace trace = processAtomPacket(packet);
        // Write bitmap
        trace.writeBitmapKeys(this->data.bitmap);
#if defined(PRINT_EDGE_COV)
        trace.printTraceLocations(state.memory_maps);
#endif
#endif
        break;
      }

      case ETM4_PKT_I_ADDR_S_IS0:
      case ETM4_PKT_I_ADDR_L_64IS0:
      case ETM4_PKT_I_ADDR_CTXT_L_64IS0: {
        // An address packet is generated in the following three cases:
        //   1. Generated to indicate the trace start address at the start of
        //      the trace.
        //   2. Generated following an atom packet (E) at an indirect branch
        //      instructions.
        //   3. Generated following an trace on packet.
        //
        // An address packet has either meaning:
        //   a. Indicates the address where the trace starts and resumes.
        //   b. Indicates the branch destination of an immediately preceding
        //      indirect branch instruction.
        //
        // In the case of b, there is no need to decode it, so ignore it.

        if (state.has_pending_address_packet) {
          // Check if the destination address jumped by the indirect branch is
          // on the memory map.
          const std::optional<AddressTrace> optional_trace =
              processAddressPacket(packet);

          if (optional_trace.has_value()) {
            AddressTrace trace = optional_trace.value();

            trace.calculateBitmapKey(this->data.bitmap.size);
            trace.writeBitmapKey(this->data.bitmap);
#if defined(PRINT_EDGE_COV)
            trace.printTraceLocation(state.memory_maps);
#endif
          }
        }
        break;
      }

      // An exception packet is generated when an exception occurs. Following
      // the exception packet, two address packets are generated. The first
      // shows the address to return after the exception, and the second shows
      // the address where execution actually resumed after the exception.
      // Therefore, the user space trace ignores these two address packets.
      case ETM4_PKT_I_EXCEPT: {
        this->decoder.state = DecodeState::EXCEPTION_ADDR1;
        break;
      }

      case ETM4_PKT_I_OVERFLOW: {
        // An Overflow packet is output in the data trace stream whenever the
        // data trace buffer in the trace unit overflows. This means that part
        // of the data trace stream might be lost, and tracing is inactive until
        // the overflow condition clears. An Overflow packet is intentionally
        // ignored.
      }

      // A trace on packet indicates a discontinuity in the trace stream. After
      // the trace on packet is generated, the trace unit generates an address
      // packet to indicate the start of the trace before generating the next
      // atom and exception packet.
      case ETM4_PKT_I_TRACE_ON:
        this->decoder.state = DecodeState::RESTART;
        break;

      default:
        break;
      }
      break;
    }

    case DecodeState::EXCEPTION_ADDR1: {
      if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
        this->decoder.state = DecodeState::EXCEPTION_ADDR2;
      }
      break;
    }

    case DecodeState::EXCEPTION_ADDR2: {
      if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
        this->decoder.state = DecodeState::TRACE;
      }
      break;
    }

    default:
      __builtin_unreachable();
    }
  }

  return ProcessResultType::PROCESS_SUCCESS;
}

AtomTrace Process::processAtomPacket(const Packet &atom_packet) {
  assert(state.prev_location.has_value() == true);

  AtomTrace trace = AtomTrace(state.prev_location.value());

  for (std::size_t i = 0; i < atom_packet.en_bits_len; ++i) {
    const Location base_location = state.prev_location.value();

    const BranchInsn insn = processNextBranchInsn(base_location);

    bool is_taken = atom_packet.en_bits & (1 << i);

    // In the case of an indirect branch instruction, an atom packet (E) and an
    // address packet are generated. Therefore, after consuming the atom packet,
    // the address packet is processed.
    if (insn.type == INDIRECT_BRANCH) {
      // The atom packet generated by an indirect branch instruction is E
      assert(is_taken == true);
      // The next packet generated after the atom packet is an address packet.
      // Therefore, this is the end of the atom packet.
      assert(i == atom_packet.en_bits_len - 1);

      // Next, it is expected that an address packet, which indicates the jump
      // destination address of the indirect branch, will be processed.
      this->state.has_pending_address_packet = true;
      trace.setPendingAddressPacket();
    } else {
      const addr_t next_offset =
          (is_taken) ? insn.taken_offset : insn.not_taken_offset;
      const addr_t next_id = insn.id;
      const Location next_location = Location(next_offset, next_id);

      // Add branch destination address by direct branch
      trace.addLocation(next_location);
      this->state.prev_location = next_location;
    }
  }

  // Create bitmap keys from the trace generated by the Direct Branch
  trace.calculateBitmapKeys(this->data.bitmap.size);

  return trace;
}

std::optional<AddressTrace>
Process::processAddressPacket(const Packet &address_packet) {
  const std::optional<Location> optional_dest_location =
      getLocation(state.memory_maps, address_packet.addr);

  // The memory image corresponding to the target address does not exist.
  if (not optional_dest_location.has_value()) {
    this->state.prev_location = std::nullopt;
    this->state.has_pending_address_packet = false;
    return std::nullopt;
  }

  if (state.prev_location.has_value() &&
      this->state.has_pending_address_packet) {
    const Location src_location = state.prev_location.value();
    const Location dest_location = optional_dest_location.value();

    // Set branch destination address by indirect branch.
    AddressTrace trace(src_location, dest_location);

    this->state.prev_location = dest_location;
    this->state.has_pending_address_packet = false;

    return trace;
  } else {
    const Location dest_location = optional_dest_location.value();

    this->state.prev_location = dest_location;
    this->state.has_pending_address_packet = false;

    return std::nullopt;
  }
}

BranchInsn Process::processNextBranchInsn(const Location &base_location) {
  // Find the next branch instruction.
  BranchInsn insn{};
  {
#if defined(CACHE_MODE)
    // Create a key to access the cache.
    const Location insn_key(base_location.offset, base_location.id);

    // Access the cache and check if the same offset of the same memory image
    // has already been disassembled.
    //  If the data exists in the cache, there is no need to disassemble it.
    if (this->data.cache.isCachedBranchInsn(insn_key)) {
      // Since the results of the disassembly are already in the cache, read the
      // data from the cache.
      insn = this->data.cache.getBranchInsnCache(insn_key);
    } else {
      // Disassemble the instruction sequence and find a branch instruction.
      insn = getNextBranchInsn(this->data.handle, base_location,
                               this->data.memory_images);
      // Add the result of disassembling the branch instruction to the cache
      this->data.cache.addBranchInsnCache(insn_key, insn);
    }
#else
    // Disassemble the instruction sequence and find a branch instruction.
    insn = getNextBranchInsn(this->data.handle, base_location,
                             this->data.memory_images);
#endif
  }
  return insn;
}

// SDBM Hash Function ref: http://www.cse.yorku.ca/~oz/hash.html
std::uint64_t hashBuffer(std::uint64_t hash, char *buf, std::size_t size) {
  for (std::size_t i = 0; i < size; i++) {
    hash = (std::uint64_t)buf[i] + (hash << 6) + (hash << 16) - hash;
  }
  return hash;
}

std::uint64_t hashString(std::uint64_t hash, std::string &str) {
  return hashBuffer(hash, (char *)str.c_str(), str.size());
}

std::uint64_t hashLocation(std::uint64_t hash, const Location &loc) {
  hash = hashBuffer(hash, (char *)&loc.offset, sizeof(loc.offset));
  hash = hashBuffer(hash, (char *)&loc.id, sizeof(loc.id));
  return hash;
}

// XXX: In the PTrix paper, the Algorithm 2 is used to map hash values to
// index so that they are mapped into [0, bitmap_size) with uniform
// distribution. However, this algorithm is NOT implemented in their source
// code. Instead, the mapping is done by referring the random value map or
// just masking like:
//
// ```
// return ((u32)val) & ((u32)(val>>32)) & BIT_RANGE;
// ```
//
// It's hard to determine what the implementation should be, but mapping
// hashes to index values with uniform distribution is most important.
// Therefore, we use xorshift64 pseudorandom number generator.
std::uint64_t mapHash(std::uint64_t hash, std::size_t bitmap_size) {
  std::uint64_t x = hash;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;

  // Assuming bitmap_size is power of 2.
  return x & (bitmap_size - 1);
}

ProcessResultType PathProcess::run(const std::uint8_t *trace_data_addr,
                                   const std::size_t trace_data_size) {
  this->deformatter.deformatTraceData(trace_data_addr, trace_data_size,
                                      decoder.trace_data);

  const std::size_t size = this->decoder.trace_data.size();

  while (this->decoder.trace_data_offset < size) {
    const Packet packet = this->decoder.decodePacket();
    DEBUG("%s\n", packet.toString().c_str());

    // The length of the packet data is insufficient and decoding cannot be
    // performed correctly at this time. In this case, the decoding process is
    // put to rest and new data is received.
    if (packet.type == PKT_INCOMPLETE) {
      return ProcessResultType::PROCESS_SUCCESS;
    }

    this->decoder.trace_data_offset += packet.size;

    switch (this->decoder.state) {
    case DecodeState::START:
    case DecodeState::TRACE: {
      switch (packet.type) {
      case ETM4_PKT_I_ATOM_F1:
      case ETM4_PKT_I_ATOM_F2:
      case ETM4_PKT_I_ATOM_F3:
      case ETM4_PKT_I_ATOM_F4:
      case ETM4_PKT_I_ATOM_F5:
      case ETM4_PKT_I_ATOM_F6: {
        // Convert EN bits to binary string.
        std::size_t size =
            std::min(packet.en_bits_len, MAX_ATOM_LEN - this->ctx_en_bits_len);
        for (std::size_t i = 0; i < size; ++i) {
          this->ctx_en_bits += (packet.en_bits & (1 << i)) ? '1' : '0';
        }
        this->ctx_en_bits_len += size;
        break;
      }

      case ETM4_PKT_I_ADDR_S_IS0:
      case ETM4_PKT_I_ADDR_L_64IS0:
      case ETM4_PKT_I_ADDR_CTXT_L_64IS0: {
        const std::optional<Location> optional_target_location =
            getLocation(this->memory_maps, packet.addr);
        if (not optional_target_location.has_value()) {
          return ProcessResultType::PROCESS_ERROR_PAGE_FAULT;
        }

        const Location target_location = optional_target_location.value();

        if (this->ctx_en_bits_len != 0) {
          DEBUG("Update hash by EN bits: %s\n", this->ctx_en_bits.c_str());
          this->ctx_hash = hashString(this->ctx_hash, ctx_en_bits);
          this->ctx_en_bits = "";
          this->ctx_en_bits_len = 0;
        }

        DEBUG("Update hash by Address: (%ld, 0x%lx)\n", target_location.id,
              target_location.offset);
        this->ctx_hash = hashLocation(this->ctx_hash, target_location);

        // XXX: We experimentally found that updating the bitmap
        // only when the address count hits MAX_ADDRESS_LEN
        // does not increase coverage. We modified the algorithm
        // to update the bitmap every Address packet processing.
        std::size_t index = mapHash(this->ctx_hash, this->bitmap.size);
        this->bitmap.data[index]++;

        // Reset hash.
        this->ctx_hash = 0;
        break;
      }

      case ETM4_PKT_I_EXCEPT:
        this->decoder.state = DecodeState::EXCEPTION_ADDR1;
        break;

      case ETM4_PKT_I_TRACE_ON:
        this->decoder.state = DecodeState::WAIT_ADDR_AFTER_TRACE_ON;
        break;

      default:
        break;
      }
      break;
    }

    case DecodeState::EXCEPTION_ADDR1: {
      if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
        this->decoder.state = DecodeState::EXCEPTION_ADDR2;
      }
      break;
    }

    case DecodeState::EXCEPTION_ADDR2: {
      if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
        this->decoder.state = DecodeState::TRACE;
      }
      break;
    }

    case DecodeState::WAIT_ADDR_AFTER_TRACE_ON: {
      if (packet.type == ETM4_PKT_I_ADDR_S_IS0 ||
          packet.type == ETM4_PKT_I_ADDR_L_64IS0 ||
          packet.type == ETM4_PKT_I_ADDR_CTXT_L_64IS0) {
        this->decoder.state = DecodeState::TRACE;
      }
      break;
    }

    default:
      __builtin_unreachable();
    }
  }

  return ProcessResultType::PROCESS_SUCCESS;
}

void PathProcess::reset(std::vector<MemoryMap> &&memory_maps,
                        std::uint8_t target_trace_id) {
  this->bitmap.reset();
  this->deformatter.reset(target_trace_id);
  this->decoder.reset();
  this->memory_maps = std::move(memory_maps);

  this->ctx_en_bits = "";
  this->ctx_en_bits_len = 0;
  this->ctx_hash = 0;
}

ProcessResultType PathProcess::final() {
  return ProcessResultType::PROCESS_SUCCESS;
}
