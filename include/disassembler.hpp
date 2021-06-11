#pragma once

#include <capstone/platform.h>
#include <capstone/capstone.h>


void disassembleInit(csh* handle);
void disassembleDelete(csh* handle);
cs_insn* disassembleNextBranchInsn(const csh* handle, const std::vector<uint8_t> code, const uint64_t offset);
uint64_t getAddressFromInsn(const cs_insn *insn);
bool isIndirectBranch(const cs_insn *insn);
bool isISBInstruction(const cs_insn *insn);
void checkCapstoneVersion();
