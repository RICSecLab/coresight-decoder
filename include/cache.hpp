#pragma once

#include <tuple>
#include <unordered_map>
#include <functional>

#include "common.hpp"
#include "disassembler.hpp"


struct BranchInsnKey {
    addr_t offset;
    std::size_t index;

    bool operator==(const BranchInsnKey &key) const {
        return offset == key.offset and index == key.index;
    }
};

namespace std {
template <>
struct hash<BranchInsnKey> {
    size_t operator()(const BranchInsnKey &key) const {
        std::size_t h1 = std::hash<addr_t>()(key.offset);
        std::size_t h2 = std::hash<std::size_t>()(key.index);

        return h1 ^ h2;
    }
};
}

struct Cache {
    std::unordered_map<BranchInsnKey, BranchInsn> branch_insn_cache;
};


BranchInsn getBranchInsnCache(const Cache &cache, const BranchInsnKey &key);
void addBranchInsnCache(Cache &cache, const BranchInsnKey &key, const BranchInsn &branch_insn);
bool isCachedBranchInsn(const Cache &cache, const BranchInsnKey &key);
