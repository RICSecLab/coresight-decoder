#include "cache.hpp"


TraceKey::TraceKey(const Location &location,
    std::uint32_t en_bits, std::size_t en_bits_len)
	: location(location), en_bits(en_bits), en_bits_len(en_bits_len) {}

bool TraceKey::operator==(const TraceKey &key) const
{
    return this->location == key.location and
           this->en_bits == key.en_bits and this->en_bits_len == key.en_bits_len;
}

std::size_t std::hash<TraceKey>::operator()(const TraceKey &key) const {
    const std::size_t h1 = std::hash<Location>()(key.location);
    const std::size_t h2 = std::hash<std::uint32_t>()(key.en_bits);
    const std::size_t h3 = std::hash<std::size_t>()(key.en_bits_len);

    return h1 ^ h2 ^ h3;
}


// 一度ディスアセンブルした分岐命令をキャッシュする。
// keyが示す命令から一番近い分岐命令の情報をキャッシュしている。
// key:
//     - バイナリファイル内のオフセット
//     - バイナリファイルのインデックス
// value:
//     - BranchInsn
BranchInsn Cache::getBranchInsnCache(const Location &key) const
{
    return this->branch_insn_cache.at(key);
}

void Cache::addBranchInsnCache(const Location &key, const BranchInsn &branch_insn)
{
    this->branch_insn_cache.emplace(key, branch_insn);
}

bool Cache::isCachedBranchInsn(const Location &key) const
{
    return this->branch_insn_cache.count(key) > 0;
}


// 一度デコードしたAtom Packetのトレース情報をキャッシュする。
// key:
//     - バイナリファイル内のオフセット
//     - バイナリファイルのインデックス
//     - トレースデータのAtomパケットの情報
// value:
//     - AtomTrace
AtomTrace Cache::getTraceCache(const TraceKey &key) const
{
    return this->trace_cache.at(key);
}

void Cache::addTraceCache(const TraceKey &key, const AtomTrace &trace)
{
    this->trace_cache.emplace(key, trace);
}

bool Cache::isCachedTrace(const TraceKey &key) const
{
    return this->trace_cache.count(key) > 0;
}
