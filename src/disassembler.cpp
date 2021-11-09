/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "disassembler.hpp"

#if CS_API_MAJOR < 4
#error Unsupported capstone version (capstone engine v4 is required)!
#endif

cs_insn *disassembleNextBranchInsn(const csh *handle,
                                   const std::vector<std::uint8_t> &code,
                                   const std::uint64_t offset);
std::uint64_t getAddressFromInsn(const cs_insn *insn);
BranchType decodeInstOpecode(const cs_insn *insn);

// According to the Arm Embedded Trace Macrocell Architecture Specification
// ETMv4.0 to ETMv4.6 F.1 Branch instructions, a list of branch instructions is
// as follows. Currently, some instructions are not supported.
//
// A64 instruction set, direct branches:
//     - B
//     - B.cond
//     - CBZ/CBNZ
//     - TBZ/BNZ
//     - BL
//     - ISB
//
// A64 instruction set, indirect branches:
//     - RET
//     - BR
//     - BLR
//

static const std::uint16_t direct_branch_opcode[] = {
    // unconditional direct branch
    ARM64_INS_B, // B, B.cond
    ARM64_INS_BL,

    // conditional branch
    ARM64_INS_CBZ,
    ARM64_INS_CBNZ,
    ARM64_INS_TBZ,
    ARM64_INS_TBNZ,
};

static const std::uint16_t indirect_branch_opcode[] = {
    ARM64_INS_BR,
    ARM64_INS_BLR,
    ARM64_INS_RET,
};

static const std::uint16_t isb_branch_opcode[] = {
    ARM64_INS_ISB,
};

void disassembleInit(csh *handle) {
  // Initialize capstone
  cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, handle);
  if (err != CS_ERR_OK) {
    std::cerr << "Failed on cs_open() with error returned: " << err
              << std::endl;
    std::exit(1);
  }
}

void disassembleDelete(csh *handle) { cs_close(handle); }

BranchInsn getNextBranchInsn(const csh &handle, const Location &location,
                             const std::vector<MemoryImage> &memory_images) {
  // Find the first branch instruction after the address indicated by location.
  cs_insn *insn = disassembleNextBranchInsn(
      &handle, memory_images[location.id].data, location.offset);

  const BranchType type = decodeInstOpecode(insn);
  const addr_t offset = insn->address;

  const addr_t taken_offset =
      (type == BranchType::DIRECT_BRANCH)
          ? getAddressFromInsn(insn)
          : (type == BranchType::ISB_BRANCH) ? insn->address + insn->size : 0;
  const addr_t not_taken_offset =
      (type == BranchType::DIRECT_BRANCH) ? offset + insn->size : 0;

  const BranchInsn branch_insn{
      type, offset, taken_offset, not_taken_offset, location.id,
  };

  // release the cache memory when done
  cs_free(insn, 1);

  return branch_insn;
}

// https://www.capstone-engine.org/iteration.html
cs_insn *disassembleNextBranchInsn(const csh *handle,
                                   const std::vector<std::uint8_t> &code,
                                   const std::uint64_t offset) {
  const std::uint8_t *code_ptr = &code[0] + offset;
  std::size_t code_size = code.size() - offset;

  // address of first instruction to be disassembled
  std::uint64_t address = offset;

  // allocate memory cache for 1 instruction, to be used by cs_disasm_iter
  // later.
  cs_insn *insn = cs_malloc(*handle);

  // disassemble one instruction a time & store the result into @insn variable
  // above
  while (cs_disasm_iter(*handle, &code_ptr, &code_size, &address, insn)) {
    DEBUG("ADDRESS: 0x%08lx INSTRUCTION_ID: %3d INSTRUCTION: %s %s\n",
          insn->address, insn->id, insn->mnemonic, insn->op_str);
    // analyze disassembled instruction in @insn variable
    // NOTE: @code_ptr, @code_size & @address variables are all updated
    // to point to the next instruction after each iteration.
    BranchType type = decodeInstOpecode(insn);

    switch (type) {
    case BranchType::DIRECT_BRANCH:
      DEBUG("Found the direct branch instruction\n");
      return insn;
    case BranchType::INDIRECT_BRANCH:
      DEBUG("Found the indirect branch instruction\n");
      return insn;
    case BranchType::ISB_BRANCH:
      DEBUG("Found the isb instruction\n");
      return insn;
    default:
      // Not branch instruction
      break;
    }
  }

  // release the cache memory when done
  cs_free(insn, 1);

  std::cerr << "Cannot find branch instruction" << std::endl;
  std::exit(1);
}

std::uint64_t getAddressFromInsn(const cs_insn *insn) {
  // The operand of the instruction is stored in insn->op_str.
  // The format of op_str varies depending on the type of branch instruction.
  //   - In the case of bl and b.ne instructions, op_str is "#0x1b40".
  //   - In the case of cbz and cbnz instructions, op_str is "x0, #0x1c08".
  //   - In the case of tbz and tbnz instructions, op_str is "w24, #0x1d,
  //     #0xb01c".

  // Find the index of the last '#' and read the end of it as a hexadecimal
  // address.
  std::size_t address_index = std::strlen(insn->op_str) - 1;
  while (insn->op_str[address_index] != '#') {
    address_index--;
  }
  address_index++;

  const std::uint64_t address =
      std::stol(insn->op_str + address_index, nullptr, 16);
  return address;
}

BranchType decodeInstOpecode(const cs_insn *insn) {
  for (const std::uint16_t opcode : direct_branch_opcode) {
    if (insn->id == opcode) {
      return BranchType::DIRECT_BRANCH;
    }
  }

  for (const std::uint16_t opcode : indirect_branch_opcode) {
    if (insn->id == opcode) {
      return BranchType::INDIRECT_BRANCH;
    }
  }

  for (const std::uint16_t opcode : isb_branch_opcode) {
    if (insn->id == opcode) {
      return BranchType::ISB_BRANCH;
    }
  }

  return BranchType::NOT_BRANCH;
}

// Check the version of the Capstone library.
// There is a bug in older versions, which has been resolved in tag:v4.0 and
// later. https://github.com/aquynh/capstone/pull/1213
void checkCapstoneVersion() {
  int major = 0, minor = 0;
  cs_version(&major, &minor);
  if (major < 4) {
    std::cerr
        << "Unsupported capstone version (capstone engine v4 is required)."
        << std::endl;
    std::exit(1);
  }
}
