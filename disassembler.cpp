#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <capstone/platform.h>
#include <capstone/capstone.h>


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

void disassemble_init(csh* handle)
{
    // Initialize capstone
    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, handle);
    if (err != CS_ERR_OK) {
        std::cerr << "Failed on cs_open() with error returned: " << err << std::endl;
        std::exit(1);
    }
}

void disassemble_delete(csh* handle)
{
    cs_close(handle);
}


// https://www.capstone-engine.org/iteration.html
cs_insn* disassemble_next_branch_insn(const csh* handle, const std::vector<uint8_t> code, const uint64_t offset)
{
    const uint8_t *code_ptr = &code[0] + offset;
    size_t code_size = code.size() - offset;
    uint64_t address = offset; // address of first instruction to be disassembled

    // allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
    cs_insn *insn = cs_malloc(*handle);

    // disassemble one instruction a time & store the result into @insn variable above
    while(cs_disasm_iter(*handle, &code_ptr, &code_size, &address, insn)) {
        std::cout << "MNEMONIC: " << insn->mnemonic << " ADDRESS: " << std::hex << insn->address << std::endl;
        // analyze disassembled instruction in @insn variable
        // NOTE: @code_ptr, @code_size & @address variables are all updated
        // to point to the next instruction after each iteration.
        for (size_t i = 0; i < sizeof(branch_opcode) / sizeof(uint16_t); ++i) {
            if (insn->id == branch_opcode[i]) {
                std::cout << "OP_STR: " << insn->op_str << std::endl;
                return insn;
            }
        }
    }

    // release the cache memory when done
    cs_free(insn, 1);

    std::cerr << "Cannot find branch instruction" << std::endl;
    std::exit(1);
}

uint64_t get_next_branch_target_addr(const csh* handle, const std::vector<uint8_t> code, const uint64_t offset)
{
    cs_insn *insn = disassemble_next_branch_insn(handle, code, offset);

    // insn->op_str is #Addr format. ex) 0x72c -> #72c
    uint64_t addr = std::stol(insn->op_str + 1, nullptr, 16);

    // release the cache memory when done
    cs_free(insn, 1);

    return addr;
}

std::vector<uint8_t> read_binary_file(const char* filename)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    std::vector<uint8_t> result(pos);

    ifs.seekg(0, std::ios::beg);
    ifs.read((char*)&result[0], pos);

    return result;
}

int main(int argc, char const *argv[])
{
    std::string filename = argv[1];
    const std::vector<uint8_t> code = read_binary_file(argv[1]);

    csh handle;
    disassemble_init(&handle);

    uint64_t addr = 0x72c;
    for (int i = 0; i < 10; i++) {
        std::cout << "START:" << std::hex << addr << std::endl;
        addr = get_next_branch_target_addr(&handle, code, addr);
    }
    disassemble_delete(&handle);

    return 0;
}
