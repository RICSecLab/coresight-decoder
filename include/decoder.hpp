/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

enum class PacketType {
  // Extension header
  ETM4_PKT_I_EXTENSION,

  // Sync
  ETM4_PKT_I_TRACE_INFO,
  ETM4_PKT_I_TIMESTAMP,
  ETM4_PKT_I_TRACE_ON,

  // Exceptions
  ETM4_PKT_I_EXCEPT,

  // Address and Context
  ETM4_PKT_I_CTXT,
  ETM4_PKT_I_ADDR_S_IS0,
  ETM4_PKT_I_ADDR_L_64IS0,
  ETM4_PKT_I_ADDR_CTXT_L_64IS0,

  // Atom
  ETM4_PKT_I_ATOM_F1,
  ETM4_PKT_I_ATOM_F2,
  ETM4_PKT_I_ATOM_F3,
  ETM4_PKT_I_ATOM_F4,
  ETM4_PKT_I_ATOM_F5,
  ETM4_PKT_I_ATOM_F6,

  // Extension packets - follow 0x00 header
  ETM4_PKT_I_ASYNC,
  ETM4_PKT_I_OVERFLOW,

  PKT_UNKNOWN,
  PKT_INCOMPLETE,
};

struct Packet {
  PacketType type;
  std::size_t size;

  // Atom packet
  std::uint32_t en_bits;
  std::size_t en_bits_len;

  // Address packet
  std::uint64_t addr;

  std::string toString() const;
};

enum class DecodeState {
  START,
  RESTART,
  TRACE,
  EXCEPTION_ADDR1,
  EXCEPTION_ADDR2,
  WAIT_ADDR_AFTER_TRACE_ON
};

struct Decoder {
  std::vector<std::uint8_t> trace_data;
  std::size_t trace_data_offset;
  DecodeState state;

  std::uint64_t address_reg;

  Packet decodePacket();
  void reset();

private:
  Packet decodeExtensionPacket();

  Packet decodeTraceInfoPacket();
  Packet decodeTimestampPacket();
  Packet decodeTraceOnPacket();
  Packet decodeContextPacket();

  Packet decodeExceptionPacket();

  Packet decodeAddressShortIS0Packet();
  Packet decodeAddressLong64IS0Packet();
  Packet decodeAddressLong64IS0WithContextPacket();

  Packet decodeAtomF1Packet();
  Packet decodeAtomF2Packet();
  Packet decodeAtomF3Packet();
  Packet decodeAtomF4Packet();
  Packet decodeAtomF5Packet();
  Packet decodeAtomF6Packet();
};
