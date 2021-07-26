#include <iostream>
#include <vector>
#include <cassert>
#include <cstdint>

#include "process.hpp"
#include "decoder.hpp"
#include "deformatter.hpp"
#include "disassembler.hpp"
#include "utils.hpp"
#include "common.hpp"
#include "cache.hpp"
#include "trace.hpp"


ProcessResultType Process::run(ProcessState state,
    const std::uint8_t* trace_data_addr, const std::size_t trace_data_size,
    const std::uint8_t trace_id)
{
    // Reset bitmap
    this->bitmap.resetBitmap();

    // Read trace data and deformat trace data.
    const std::vector<std::uint8_t> trace_data =
        deformatTraceData(trace_data_addr, trace_data_size, trace_id);

    const std::size_t size = trace_data.size();
    while (state.trace_data_offset < size) {
        const std::optional<BranchPacket> optional_branch_packet =
            decodeNextBranchPacket(trace_data, state.trace_data_offset);

        // An error occurred during the trace data decoding process
        // Currently, the decoder only fails if it finds an overflow packet.
        if (not optional_branch_packet.has_value()) {
            return ProcessResultType::PROCESS_ERROR_OVERFLOW_PACKET;
        }

        const BranchPacket branch_packet = optional_branch_packet.value();

        if (state.is_first_branch_packet) {
            // The first branch packet is always an address pocket.
            // Otherwise, the trace start address is not known.
            assert(branch_packet.type == BRANCH_PKT_ADDRESS);

            // トレースの開始アドレスがメモリマップ上にあるか調べる。
            // もしなければ、エラーを返す。
            const std::optional<Location> optional_start_location =
                getLocation(state.memory_maps, branch_packet.target_address);
            if (not optional_start_location.has_value()) {
                return ProcessResultType::PROCESS_ERROR_PAGE_FAULT;
            }

            const Location start_location = optional_start_location.value();

            state.prev_location = start_location;
            state.trace_state = checkTraceRange(state.memory_maps, start_location)
                ? TraceStateType::TRACE_ON : TraceStateType::TRACE_OUT_OF_RANGE;
            state.is_first_branch_packet = false;
        }

        if (branch_packet.type == BRANCH_PKT_ATOM) { // Atom packet
            if (state.trace_state == TraceStateType::TRACE_OUT_OF_RANGE) {
                continue;
            }

            // Atomパケットの処理時に、未処理のIndirect Branchがある。
            // 本来であれば、Atomパケットではなく、Addressパケットがあるはずである。
            // このエラーが発生するとき、おそらくこのプログラム自体にバグがある。
            assert(state.has_pending_address_packet == false);

            // Cacheにアクセスして、既に同じトレースデータと開始アドレスから、
            // エッジカバレッジを復元したことがあるか調べる。
            // もし既にキャッシュに存在するなら、そのデータを使うことで高速化できる。
            #if defined(CACHE_MODE)
                // Create a key for cache.
                const TraceKey trace_key (
                    state.prev_location,
                    branch_packet.en_bits,
                    branch_packet.en_bits_len
                );

                if (cache.isCachedTrace(trace_key)) {
                    AtomTrace trace = cache.getTraceCache(trace_key);
                    // Update state
                    state.prev_location = trace.locations.back();
                    state.has_pending_address_packet = trace.has_pending_address_packet;

                    // Write bitmap
                    trace.writeBitmapKeys(this->bitmap);
                    #if defined(PRINT_EDGE_COV)
                        trace.printTraceLocations(state.memory_maps);
                    #endif
                } else {
                    AtomTrace trace = processAtomPacket(state, branch_packet);

                    // Write bitmap
                    trace.writeBitmapKeys(this->bitmap);
                    #if defined(PRINT_EDGE_COV)
                        trace.printTraceLocations(state.memory_maps);
                    #endif

                    // Add trace to cache
                    cache.addTraceCache(trace_key, trace);
                }
            #else
                AtomTrace trace = processAtomPacket(state, branch_packet);
                // Write bitmap
                trace.writeBitmapKeys(this->bitmap);
                #if defined(PRINT_EDGE_COV)
                    trace.printTraceLocations(state.memory_maps);
                #endif
            #endif
        } else if (branch_packet.type == BRANCH_PKT_ADDRESS) { // Address packet
            // Address packetは下記の3つの場合に生成される。
            //     1. トレース開始時に、トレース開始アドレスを示すために生成される。
            //     2. Indirect branchのときに、Atom pakcet(E)に続き、生成される。
            //     3. トレースが途切れたときに、Trace On packetに続き、生成される。
            // 3.のとき、
            //     3.1 トレースが再開されたアドレスを示すAddress packetの場合と、
            //     3.2 トレースが途切れる前のAtom(E)に続く、Address packetの場合がある。
            // 3.1の場合は必要ないので無視する。

            // 3.1の場合 has_pending_address_packet == false

            if (state.has_pending_address_packet or
                state.trace_state == TraceStateType::TRACE_OUT_OF_RANGE) {
                // 間接分岐でジャンプした先のアドレスがメモリマップ上にあるか調べる。
                // もしなければ、エラーを返す。
                const std::optional<AddressTrace> optional_trace =
                    processAddressPacket(state, branch_packet);
                if (not optional_trace.has_value()) {
                    return ProcessResultType::PROCESS_ERROR_PAGE_FAULT;
                }

                const AddressTrace trace = optional_trace.value();

                // Save trace
                if (state.trace_state == TraceStateType::TRACE_ON) {
                    // Write bitmap
                    trace.writeBitmapKey(this->bitmap);
                    #if defined(PRINT_EDGE_COV)
                        trace.printTraceLocation(state.memory_maps);
                    #endif
                }
                if (state.trace_state == TraceStateType::TRACE_RESTART) {
                    state.trace_state = TraceStateType::TRACE_ON;
                }
            }
        } else if (branch_packet.type == BRANCH_PKT_END) {
            break;
        } else {
            // Unknown branch packet.
            __builtin_unreachable();
        }
    }

    if (state.has_pending_address_packet) {
        // This trace data is incomplete. There is no Address packet following Atom packet.
        return ProcessResultType::PROCESS_ERROR_TRACE_DATA_INCOMPLETE;
    }

    return ProcessResultType::PROCESS_SUCCESS;
}

AtomTrace Process::processAtomPacket(ProcessState &state, const BranchPacket &atom_packet)
{
    AtomTrace trace = AtomTrace(state.prev_location);

    for (std::size_t i = 0; i < atom_packet.en_bits_len; ++i) {
        const Location base_location = state.prev_location;

        const BranchInsn insn = processNextBranchInsn(state, base_location);

        bool is_taken = atom_packet.en_bits & (1 << i);

        // Indirect branch命令のとき、Atom packet(E)とAddress packetが生成される。
        // そのため、Atom packetを一つ消費した後に、Address packetを処理する。
        if (insn.type == INDIRECT_BRANCH) {
            // Indirect branchで生成されるAtom PacketはEである。
            assert(is_taken == true);
            // Indirect branchの次に生成されるパケットはAddress Packetである。
            assert(i == atom_packet.en_bits_len - 1);

            // Indirect branchのジャンプ先アドレスを示すAddress packetを次に処理することを期待する。
            state.has_pending_address_packet = true;
            trace.setPendingAddressPacket();
        } else {
            const addr_t next_offset = (is_taken) ? insn.taken_offset : insn.not_taken_offset;
            const addr_t next_index = insn.index;
            const Location next_location = Location(next_offset, next_index);

            // Add branch destination address by direct branch
            trace.addLocation(next_location);

            // Update state
            state.prev_location = next_location;
        }
    }

    // Create bitmap keys from the trace generated by the Direct Branch
    trace.calculateBitmapKeys(this->bitmap.size);

    return trace;
}

std::optional<AddressTrace> Process::processAddressPacket(
    ProcessState &state, const BranchPacket &address_packet)
{
    const std::optional<Location> optional_dest_location =
        getLocation(state.memory_maps, address_packet.target_address);
    // ターゲットアドレスに対応するバイナリデータが存在しない。
    if (not optional_dest_location.has_value()) {
        return std::nullopt;
    }

    const Location src_location  = state.prev_location;
    const Location dest_location = optional_dest_location.value();

    // Set branch destination address by indirect branch
    AddressTrace trace(src_location, dest_location);

    // Create bitmap keys from the trace generated by the Indirect Branch
    trace.calculateBitmapKey(this->bitmap.size);

    // Update state
    state.prev_location = dest_location;
    state.has_pending_address_packet = false;

    if (checkTraceRange(state.memory_maps, src_location) and
        checkTraceRange(state.memory_maps, dest_location)) {
        state.trace_state = TraceStateType::TRACE_ON;
    } else if (checkTraceRange(state.memory_maps, dest_location)) {
        state.trace_state = TraceStateType::TRACE_RESTART;
    } else {
        state.trace_state = TraceStateType::TRACE_OUT_OF_RANGE;
    }

    return trace;
}

BranchInsn Process::processNextBranchInsn(const ProcessState &state, const Location &base_location)
{
    // 次の分岐命令を計算する。
    BranchInsn insn; {
        #if defined(CACHE_MODE)
            // BranchInsnのキャッシュにアクセスするためのキーを作成する。
            const Location insn_key(base_location.offset, base_location.index);

            // Cacheにアクセスして、既にディスアセンブルした命令か調べる。
            // 同じバイナリファイル&オフセットに対するこの処理は、キャッシュ化することができる。
            // もし既にキャッシュに存在するなら、そのデータを使うことで高速化できる。
            if (this->cache.isCachedBranchInsn(insn_key)) {
                // 既にディスアセンブルした結果がキャッシュにあるため、そのデータを読み込む。
                insn = this->cache.getBranchInsnCache(insn_key);
            } else {
                // 命令列をディスアセンブルし、分岐命令を探す。
                insn = getNextBranchInsn(this->handle, base_location, state.memory_maps);
                // Cacheに分岐命令をディスアセンブルした結果を格納する。
                this->cache.addBranchInsnCache(std::move(insn_key), insn);
            }
        #else
            // 命令列をディスアセンブルし、分岐命令を探す。
            insn = getNextBranchInsn(this->handle, base_location, state.memory_maps);
        #endif
    }
    return insn;
}
