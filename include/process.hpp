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
    std::vector<MemoryImage> memory_images;

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

    ProcessData(std::vector<MemoryImage> &&memory_images,
        const Bitmap &bitmap, Cache &&cache)
        : memory_images(std::move(memory_images)), bitmap(bitmap), cache(std::move(cache))
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

    std::vector<MemoryMap> memory_maps;

    // Disable copy constructor.
    ProcessState(const ProcessState&) = delete;
    ProcessState& operator=(const ProcessState&) = delete;

    ProcessState() = default;

    void reset(std::vector<MemoryMap> &&memory_maps) {
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

    Process(std::vector<MemoryImage> &&memory_images, const Bitmap &bitmap, Cache &&cache)
        : data(std::move(memory_images), bitmap, std::move(cache)) {}

    void reset(std::vector<MemoryMap> &&memory_maps, std::uint8_t target_trace_id);
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

    std::vector<MemoryImage> memory_images;
    std::vector<MemoryMap> memory_maps;

    Bitmap bitmap;

    std::string ctx_en_bits;
    std::size_t ctx_en_bits_len;
    std::size_t ctx_address_cnt;
    std::uint64_t ctx_hash;

    PathProcess(std::vector<MemoryImage> &&memory_images, const Bitmap &bitmap)
        : memory_images(std::move(memory_images)), bitmap(bitmap) {}

    void reset(std::vector<MemoryMap> &&memory_maps, std::uint8_t target_trace_id);
    ProcessResultType final();
    ProcessResultType run(
        const std::uint8_t* trace_data_addr, const size_t trace_data_size);
};
