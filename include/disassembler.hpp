/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

#include <capstone/platform.h>
#include <capstone/capstone.h>

#include "common.hpp"

enum BranchType {
    DIRECT_BRANCH,
    INDIRECT_BRANCH,
    ISB_BRANCH,
    NOT_BRANCH,
};

struct BranchInsn {
    BranchType type;

    addr_t offset;

    addr_t taken_offset;
    addr_t not_taken_offset;

    size_t index;
};


void disassembleInit(csh* handle);
void disassembleDelete(csh* handle);
BranchInsn getNextBranchInsn(const csh &handle, const Location &location, const std::vector<MemoryMap> &memory_map);
void checkCapstoneVersion();
