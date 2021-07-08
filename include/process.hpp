#pragma once

#include "common.hpp"
#include "trace.hpp"
#include "cache.hpp"
#include "decoder.hpp"
#include "deformatter.hpp"


enum class ProcessResultType {
    PROCESS_SUCCESS,
    PROCESS_ERROR_OVERFLOW_PACKET,
    PROCESS_ERROR_TRACE_DATA_INCOMPLETE,
};

enum class TraceStateType {
    TRACE_ON,
    TRACE_OUT_OF_RANGE,
    TRACE_RESTART,
};


struct ProcessState {
    TraceStateType trace_state;

    Location prev_location;
    bool has_pending_address_packet;
    std::size_t trace_data_offset;
    bool is_first_branch_packet;

    MemoryMaps memory_maps;

    // Disable copy constructor.
    ProcessState(const ProcessState&) = delete;
    ProcessState& operator=(const ProcessState&) = delete;

    ProcessState(MemoryMaps &&memory_maps)
        : trace_state(TraceStateType::TRACE_ON), prev_location(Location()),
          has_pending_address_packet(false), trace_data_offset(0),
          is_first_branch_packet(true), memory_maps(std::move(memory_maps)) {}
};


struct Process {
    // トレースする領域のバイナリファイルを保存
    const BinaryFiles binary_files;

    // エッジカバレッジの計算結果を書き出すための
    // bitmapのアドレスとサイズ
    const Bitmap bitmap;

    // ディスアセンブル結果とトレースデータのデコード結果をキャッシュし、
    // 将来のデコード時に使えるようにすることで、実行速度を高速化している。
    const bool cache_mode;
    Cache cache;

    // エッジカバレッジを標準出力に出力するかどうかを示すフラグ
    const bool print_edge_cov_mode;

    // Capstoneにアクセスするためのハンドラ
    csh handle;

    // Disable copy constructor.
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    Process(BinaryFiles &&binary_files, const Bitmap &bitmap,
        const bool cache_mode, Cache &&cache, bool print_edge_cov_mode)
        : binary_files(std::move(binary_files)), bitmap(bitmap),
          cache_mode(cache_mode), cache(std::move(cache)),
          print_edge_cov_mode(print_edge_cov_mode)
    {
        csh handle;
        disassembleInit(&handle);
        this->handle = handle;
    };

    ~Process()
    {
        disassembleDelete(&this->handle);
    }

    ProcessResultType run(ProcessState state,
        const std::uint8_t* trace_data_addr, std::size_t trace_data_size,
        std::uint8_t trace_id);
    AtomTrace processAtomPacket(ProcessState &state, const BranchPacket &atom_packet);
    AddressTrace processAddressPacket(ProcessState &state, const BranchPacket &address_packet);
    BranchInsn processNextBranchInsn(const ProcessState &state, const Location &base_location);
};
