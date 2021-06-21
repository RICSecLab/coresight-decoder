#include "cache.hpp"


// 一度ディスアセンブルした分岐命令をキャッシュする。
// keyが示す命令から一番近い分岐命令の情報をキャッシュしている。
// key:
//     - バイナリファイル内のオフセット
//     - バイナリファイルのインデックス
// value:
//     - BranchInsn
BranchInsn getBranchInsnCache(const Cache &cache, const BranchInsnKey &key)
{
    return cache.branch_insn_cache.at(key);
}

void addBranchInsnCache(Cache &cache, const BranchInsnKey &key, const BranchInsn &branch_insn)
{
    cache.branch_insn_cache.insert(std::make_pair(key, branch_insn));
}

bool isCachedBranchInsn(const Cache &cache, const BranchInsnKey &key)
{
    return cache.branch_insn_cache.count(key) > 0;
}
