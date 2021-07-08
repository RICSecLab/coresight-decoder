#pragma once

#include "common.hpp"
#include "trace.hpp"
#include "cache.hpp"

struct ProcessParam {
    // トレースする領域のバイナリファイルを保存
    const BinaryFiles binary_files;

    // エッジカバレッジの計算結果を書き出すための
    // bitmapのアドレスとサイズ
    const Bitmap bitmap;

    // ディスアセンブル結果とトレースデータのデコード結果をキャッシュし、
    // 将来のデコード時に使えるようにすることで、実行速度を高速化している。
    const bool cache_mode;
    Cache cache;

    const bool print_edge_cov_mode;

    ProcessParam(BinaryFiles &&binary_files, const Bitmap &bitmap,
        const bool cache_mode, Cache &&cache, bool print_edge_cov_mode);
};

enum ProcessResultType {
    PROCESS_SUCCESS,
    PROCESS_ERROR_OVERFLOW_PACKET,
    PROCESS_ERROR_TRACE_DATA_INCOMPLETE,
};

ProcessResultType process(ProcessParam &param, const std::vector<uint8_t>& trace_data,
    const std::vector<MemoryMap> &memory_map, const csh &handle);
