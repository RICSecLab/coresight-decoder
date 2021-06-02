#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>

#include "common.hpp"
#include "disassembler.hpp"


#if CS_API_MAJOR < 4
#error Unsupported capstone version (capstone engine v4 is required)!
#endif


// https://www.mztn.org/dragon/arm6408cond.html
static const uint16_t branch_opcode[] = {
    // conditional branch
    ARM64_INS_CBZ,
    ARM64_INS_CBNZ,
    ARM64_INS_TBZ,
    ARM64_INS_TBNZ,

    // unconditional direct branch
    ARM64_INS_B,
    ARM64_INS_BL,

    // indirect branch
    ARM64_INS_BR,
    ARM64_INS_BLR,
    ARM64_INS_RET,
    ARM64_INS_ERET,
};

static const uint16_t indirect_branch_opcode[] = {
    // indirect branch
    ARM64_INS_BR,
    ARM64_INS_BLR,
    ARM64_INS_RET,
    ARM64_INS_ERET,
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

// https://www.capstone-engine.org/iteration.html
cs_insn* disassembleNextBranchInsn(const csh* handle, const std::vector<uint8_t> code, const uint64_t offset)
{
    const uint8_t *code_ptr = &code[0] + offset;
    size_t code_size = code.size() - offset;
    uint64_t address = offset; // address of first instruction to be disassembled

    // allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
    cs_insn *insn = cs_malloc(*handle);

    // disassemble one instruction a time & store the result into @insn variable above
    while(cs_disasm_iter(*handle, &code_ptr, &code_size, &address, insn)) {
        DEBUG("ADDRESS: %08lx INSTRUCTION: %s %s\n", insn->address, insn->mnemonic, insn->op_str);
        // analyze disassembled instruction in @insn variable
        // NOTE: @code_ptr, @code_size & @address variables are all updated
        // to point to the next instruction after each iteration.
        for (size_t i = 0; i < sizeof(branch_opcode) / sizeof(uint16_t); ++i) {
            if (insn->id == branch_opcode[i]) {
                DEBUG("Found the branch instruction\n");
                return insn;
            }
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

bool isIndirectBranch(const cs_insn *insn)
{
     for (size_t i = 0; i < sizeof(indirect_branch_opcode) / sizeof(uint16_t); ++i) {
        if (insn->id == indirect_branch_opcode[i]) {
            return true;
        }
    }
    return false;
}

// Capstoneライブラリのバージョンを確認する。
// 古いバージョンにはバグがあり、tag:v4.0以降では解決されている。
// https://github.com/aquynh/capstone/pull/1213
void checkCapstoneVersion() {
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    if (major < 4) {
        std::cerr << "Unsupported capstone version (capstone engine v4 is required).";
        std::exit(1);
    }
}
