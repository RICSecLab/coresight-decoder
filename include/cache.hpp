#pragma once

#include <tuple>
#include <unordered_map>
#include <functional>

#include "common.hpp"
#include "disassembler.hpp"
#include "trace.hpp"


struct TraceKey {
    addr_t offset;
    std::size_t index;

    std::uint32_t en_bits;
    std::size_t en_bits_len;

    bool operator==(const TraceKey &key) const {
        return offset == key.offset and index == key.index and
               en_bits == key.en_bits and en_bits_len == key.en_bits_len;
    }
};

namespace std {
template <>
struct hash<TraceKey> {
    size_t operator()(const TraceKey &key) const {
        std::size_t h1 = std::hash<addr_t>()(key.offset);
        std::size_t h2 = std::hash<std::size_t>()(key.index);
        std::size_t h3 = std::hash<std::uint32_t>()(key.en_bits);
        std::size_t h4 = std::hash<std::size_t>()(key.en_bits_len);

        return h1 ^ h2 ^ h3 ^ h4;
    }
};
}

struct Cache {
    std::unordered_map<Location, BranchInsn> branch_insn_cache;
    std::unordered_map<TraceKey, AtomTrace> trace_cache;
};


BranchInsn getBranchInsnCache(const Cache &cache, const Location &key);
void addBranchInsnCache(Cache &cache, const Location &key, const BranchInsn &branch_insn);
bool isCachedBranchInsn(const Cache &cache, const Location &key);

AtomTrace getTraceCache(const Cache &cache, const TraceKey &key);
void addTraceCache(Cache &cache, const TraceKey &key, const AtomTrace &trace);
bool isCachedTrace(const Cache &cache, const TraceKey &key);
