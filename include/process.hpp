#pragma once

#include "common.hpp"
#include "trace.hpp"
#include "cache.hpp"

struct ProcessParam {
    // トレースする領域のバイナリファイルを保存
    const BinaryFiles binary_files;

    // エッジカバレッジの計算結果を書き出すための
    // bitmapのアドレスとサイズ
    const void* bitmap_addr;
    const int bitmap_size;

    // ディスアセンブル結果とトレースデータのデコード結果をキャッシュし、
    // 将来のデコード時に使えるようにすることで、実行速度を高速化している。
    const bool cache_mode;
    Cache cache;

    ProcessParam(BinaryFiles &&binary_files,
        const void* bitmap_addr, const int bitmap_size,
        const bool cache_mode, Cache cache);
};

enum ProcessResultType {
    PROCESS_SUCCESS,
    PROCESS_ERROR_OVERFLOW_PACKET,
    PROCESS_ERROR_TRACE_DATA_INCOMPLETE,
};

struct ProcessResult {
    std::vector<Trace> traces;
    ProcessResultType type;
};


ProcessResult process(ProcessParam &param, const std::vector<uint8_t>& trace_data,
    const std::vector<MemoryMap> &memory_map, const csh &handle);
