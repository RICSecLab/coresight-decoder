/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

#include <bitset>

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


// デコード処理に永続的に使われるデータ
struct ProcessData {
    // トレースする領域のバイナリファイルを保存
    BinaryFiles binary_files;

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

    ProcessData(const Bitmap &bitmap, Cache &&cache)
        : bitmap(bitmap), cache(std::move(cache))
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
    std::optional<Location> prev_location;
    bool has_pending_address_packet;

    MemoryMaps memory_maps;

    // Disable copy constructor.
    ProcessState(const ProcessState&) = delete;
    ProcessState& operator=(const ProcessState&) = delete;

    ProcessState() = default;

    void reset(MemoryMaps &&memory_maps) {
        this->prev_location = std::nullopt;
        this->has_pending_address_packet = false;
        this->memory_maps = std::move(memory_maps);
    }
};


struct Process {
    ProcessData data;
    ProcessState state;

    Deformatter deformatter;
    Decoder decoder;

    Process(const Bitmap &bitmap, Cache &&cache)
        : data(bitmap, std::move(cache)) {}

    void reset(MemoryMaps &&memory_maps, std::uint8_t target_trace_id);
    ProcessResultType final();
    ProcessResultType run(const std::uint8_t* trace_data_addr, std::size_t trace_data_size);

private:
    AtomTrace processAtomPacket(const Packet &atom_packet);
    std::optional<AddressTrace> processAddressPacket(
        const Packet &address_packet);
    BranchInsn processNextBranchInsn(const Location &base_location);
};


struct PathProcess {
    Deformatter deformatter;
    Decoder decoder;

    Bitmap bitmap;
    MemoryMaps memory_maps;

    std::bitset<MAX_ATOM_LEN> ctx_en_bits;
    std::size_t ctx_en_bits_len;
    std::size_t ctx_address_cnt;
    std::uint64_t ctx_hash;

    PathProcess(const Bitmap &bitmap)
        : bitmap(bitmap) {}

    void reset(MemoryMaps &&memory_maps, std::uint8_t target_trace_id);
    ProcessResultType final();
    ProcessResultType run(
        const std::uint8_t* trace_data_addr, const size_t trace_data_size);
};
