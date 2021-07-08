#pragma once

#include <tuple>
#include <unordered_map>
#include <functional>

#include "common.hpp"
#include "disassembler.hpp"
#include "trace.hpp"


struct TraceKey {
    const Location location;

    const std::uint32_t en_bits;
    const std::size_t en_bits_len;

    TraceKey(const Location &location,
        std::uint32_t en_bits, std::size_t en_bits_len);

    bool operator==(const TraceKey &key) const;
};

namespace std {
    template <>
    struct hash<TraceKey> {
        std::size_t operator()(const TraceKey &key) const;
    };
}


struct Cache {
    std::unordered_map<Location, BranchInsn> branch_insn_cache;
    std::unordered_map<TraceKey, AtomTrace> trace_cache;

    BranchInsn getBranchInsnCache(const Location &key) const;
    void addBranchInsnCache(const Location &key, const BranchInsn &branch_insn);
    bool isCachedBranchInsn(const Location &key) const;

    AtomTrace getTraceCache(const TraceKey &key) const;
    void addTraceCache(const TraceKey &key, const AtomTrace &trace);
    bool isCachedTrace(const TraceKey &key) const;
};
