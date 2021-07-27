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
    PROCESS_ERROR_PAGE_FAULT,
};

enum class TraceStateType {
    TRACE_ON,
    TRACE_OUT_OF_RANGE,
    TRACE_RESTART,
};


// デコード処理に永続的に使われるデータ
struct ProcessData {
    // トレースする領域のバイナリファイルを保存
    const BinaryFiles binary_files;

    // エッジカバレッジの計算結果を書き出すための
    // bitmapのアドレスとサイズ
    const Bitmap bitmap;

    // ディスアセンブル結果とトレースデータのデコード結果をキャッシュし、
    // 将来のデコード時に使えるようにすることで、実行速度を高速化している。
    Cache cache;

    // Capstoneにアクセスするためのハンドラ
    csh handle;

    // Disable copy constructor.
    ProcessData(const ProcessData&) = delete;
    ProcessData& operator=(const ProcessData&) = delete;

    ProcessData(BinaryFiles &&binary_files, const Bitmap &bitmap, Cache &&cache)
        : binary_files(std::move(binary_files)), bitmap(bitmap), cache(std::move(cache))
    {
        csh handle;
        disassembleInit(&handle);
        this->handle = handle;
    };

    ~ProcessData()
    {
        disassembleDelete(&this->handle);
    }
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

    ProcessState() = default;

    void reset(MemoryMaps &&memory_maps) {
        this->trace_state = TraceStateType::TRACE_ON;
        this->prev_location = Location();
        this->has_pending_address_packet = false;
        this->trace_data_offset = 0;
        this->is_first_branch_packet = true;
        this->memory_maps = std::move(memory_maps);
    }
};


struct Process {
    ProcessData data;
    ProcessState state;

    Deformatter deformatter;
    Decoder decoder;

    Process(BinaryFiles &&binary_files, const Bitmap &bitmap, Cache &&cache)
        : data(ProcessData(std::move(binary_files), bitmap, std::move(cache))) {}

    void reset(MemoryMaps &&memory_maps, std::uint8_t target_trace_id);
    ProcessResultType final();
    ProcessResultType run(const std::uint8_t* trace_data_addr, std::size_t trace_data_size);

    AtomTrace processAtomPacket(const BranchPacket &atom_packet);
    std::optional<AddressTrace> processAddressPacket(
        const BranchPacket &address_packet);
    BranchInsn processNextBranchInsn(const Location &base_location);
};


ProcessResultType run_ptrix(
    const std::uint8_t* trace_data_addr, const size_t trace_data_size,
    const std::uint8_t trace_id,
    const std::vector<MemoryMap> &memory_maps, Bitmap &bitmap);
