/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>

#include "disassembler.hpp"


#if CS_API_MAJOR < 4
#error Unsupported capstone version (capstone engine v4 is required)!
#endif

cs_insn* disassembleNextBranchInsn(const csh* handle, const std::vector<uint8_t> &code, const uint64_t offset);
uint64_t getAddressFromInsn(const cs_insn *insn);
BranchType decodeInstOpecode(const cs_insn *insn);


// Arm Embedded Trace Macrocell Architecture Specification ETMv4.0 to ETMv4.6
// F.1 Branch instructionsを参考に、必要になる分岐命令を選ぶ。
//
// A64 instruction set, direct branches:
//     - B
//     - B.cond
//     - CBZ/CBNZ
//     - TBZ/BNZ
//     - BL
//     - ISB
// ※WFI, WFEはThunderX2のTRCIDR2.WFXMODEが0なので、分岐命令に分類されない。
//
//
// A64 instruction set, indirect branches:
//     - RET
//     - BR
//     - BLR
// ※ERETはユーザ空間のプログラムでは呼ばれないため、とりあえず外している。
// ※ERETAA/ERETAB, RETAA/RETAB, BRAA/BRAB, BRAAZ/BRABZ, BLRAA/BLRAB, BLRAAZ/BLRABZは
// ThunderX2がポインタ認証未対応のため、外している。
//
// 参考: https://www.mztn.org/dragon/arm6408cond.html

static const uint16_t direct_branch_opcode[] = {
    // unconditional direct branch
    ARM64_INS_B, // B, B.cond
    ARM64_INS_BL,

    // conditional branch
    ARM64_INS_CBZ,
    ARM64_INS_CBNZ,
    ARM64_INS_TBZ,
    ARM64_INS_TBNZ,
};

static const uint16_t indirect_branch_opcode[] = {
    ARM64_INS_BR,
    ARM64_INS_BLR,
    ARM64_INS_RET,
};

static const uint16_t isb_branch_opcode[] = {
    ARM64_INS_ISB,
};


void disassembleInit(csh* handle)
{
    // Initialize capstone
    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, handle);
    if (err != CS_ERR_OK) {
        std::cerr << "Failed on cs_open() with error returned: " << err << std::endl;
        std::exit(1);
    }
}

void disassembleDelete(csh* handle)
{
    cs_close(handle);
}

// base_address以降のアドレスで、最も近い分岐命令を探す
BranchInsn getNextBranchInsn(const csh &handle, const Location &location, const std::vector<MemoryMap> &memory_map)
{
    cs_insn *insn = disassembleNextBranchInsn(&handle,
        memory_map[location.index].getBinaryData(), location.offset);

    const BranchType type = decodeInstOpecode(insn);

    const addr_t offset  = insn->address;

    // 分岐命令のtaken時に、分岐先のアドレスを計算する
    const addr_t taken_offset  = (type == DIRECT_BRANCH) ? getAddressFromInsn(insn) :
                                 (type == ISB_BRANCH) ? insn->address + insn->size : 0;

    // Conditonal branchのとき、分岐命令でnot takenがある。
    // それ以外の場合、分岐命令でnot takenの場合はない。
    const addr_t not_taken_offset  = (type == DIRECT_BRANCH) ? offset + insn->size : 0;

    const BranchInsn branch_insn {
        type,
        offset,
        taken_offset,
        not_taken_offset,
        location.index,
    };

    // release the cache memory when done
    cs_free(insn, 1);

    return branch_insn;
}

// https://www.capstone-engine.org/iteration.html
cs_insn* disassembleNextBranchInsn(const csh* handle, const std::vector<uint8_t> &code, const uint64_t offset)
{
    const uint8_t *code_ptr = &code[0] + offset;
    size_t code_size = code.size() - offset;
    uint64_t address = offset; // address of first instruction to be disassembled

    // allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
    cs_insn *insn = cs_malloc(*handle);

    // disassemble one instruction a time & store the result into @insn variable above
    while(cs_disasm_iter(*handle, &code_ptr, &code_size, &address, insn)) {
        DEBUG("ADDRESS: 0x%08lx INSTRUCTION_ID: %3d INSTRUCTION: %s %s\n", insn->address, insn->id, insn->mnemonic, insn->op_str);
        // analyze disassembled instruction in @insn variable
        // NOTE: @code_ptr, @code_size & @address variables are all updated
        // to point to the next instruction after each iteration.
        BranchType type = decodeInstOpecode(insn);

        switch (type) {
            case DIRECT_BRANCH:
                DEBUG("Found the direct branch instruction\n");
                return insn;
            case INDIRECT_BRANCH:
                DEBUG("Found the indirect branch instruction\n");
                return insn;
            case ISB_BRANCH:
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


uint64_t getAddressFromInsn(const cs_insn *insn)
{
    // insn->op_strに命令のオペランドが格納されている。
    // op_strのフォーマットは分岐命令の種類によって異なる。
    //     ex) blやb.ne命令のop_str  -> #0x1b40
    //     ex) cbzやcbnz命令のop_str -> x0, #0x1c08
    //     ex) tbzやtbnz命令のop_str -> w24, #0x1d, #0xb01c
    // 一番最後の'#'のインデックスを求めて、その後ろを16進数のアドレスとして読みとる。

    size_t address_index = std::strlen(insn->op_str) - 1;
    while (insn->op_str[address_index] != '#') {
        address_index--;
    }
    address_index++;

    const uint64_t address = std::stol(insn->op_str + address_index, nullptr, 16);
    return address;
}

BranchType decodeInstOpecode(const cs_insn *insn)
{
    for (size_t i = 0; i < sizeof(direct_branch_opcode) / sizeof(uint16_t); ++i) {
        if (insn->id == direct_branch_opcode[i]) {
            return DIRECT_BRANCH;
        }
    }

    for (size_t i = 0; i < sizeof(indirect_branch_opcode) / sizeof(uint16_t); ++i) {
        if (insn->id == indirect_branch_opcode[i]) {
            return INDIRECT_BRANCH;
        }
    }

    for (size_t i = 0; i < sizeof(isb_branch_opcode) / sizeof(uint16_t); ++i) {
        if (insn->id == isb_branch_opcode[i]) {
            return ISB_BRANCH;
        }
    }

    return NOT_BRANCH;
}

// Capstoneライブラリのバージョンを確認する。
// 古いバージョンにはバグがあり、tag:v4.0以降では解決されている。
// https://github.com/aquynh/capstone/pull/1213
void checkCapstoneVersion() {
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    if (major < 4) {
        std::cerr << "Unsupported capstone version (capstone engine v4 is required)." << std::endl;
        std::exit(1);
    }
}
