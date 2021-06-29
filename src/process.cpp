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


enum TraceState {
    TRACE_ON,
    TRACE_OUT_OF_RANGE,
    TRACE_RESTART,
};

struct ProcessState {
    Location prev_location;
    bool has_pending_address_packet;
    TraceState trace_state;
};


AtomTrace processAtomPacket(const ProcessParam &param, ProcessState &state, Cache &cache,
    const csh &handle, const std::vector<MemoryMap> &memory_map, const BranchPacket &atom_packet);
AddressTrace processAddressPacket(const ProcessParam &param, ProcessState &state,
    const std::vector<MemoryMap> &memory_map, const BranchPacket &address_packet);
BranchInsn processNextBranchInsn(const ProcessParam &param, ProcessState &state, Cache &cache,
    const csh &handle, const std::vector<MemoryMap> &memory_map, const Location base_location);
bool checkAddressRange(const ProcessParam &param, const Location &location);


std::vector<Trace> process(const ProcessParam &param, const std::vector<uint8_t>& trace_data,
    const std::vector<MemoryMap> &memory_map, const csh &handle)
{
    // Trace dataの中から、エッジカバレッジの復元に必要なパケットのみを取り出す。
    std::vector<BranchPacket> branch_packets; {
        std::optional<std::vector<BranchPacket>> optional_branch_packets = decodeTraceData(trace_data);

        // An error occurred during the trace data decoding process
        // Currently, the decoder only fails if it finds an overflow packet.
        if (not optional_branch_packets.has_value()) {
            return ProcessResult {
                std::vector<Trace>(),
                PROCESS_ERROR_OVERFLOW_PACKET
            };
        }

        branch_packets = optional_branch_packets.value();
    }

    // btsの先頭データは必ずAddress packetである。
    // そうでないと、トレース開始アドレスがわからない。
    assert(branch_packets.front().type == BRANCH_PKT_ADDRESS);
    const Location start_location = Location(memory_map, branch_packets.front().target_address);

    ProcessState state{start_location, false, checkAddressRange(param, start_location) ? TRACE_ON : TRACE_OUT_OF_RANGE};

    std::vector<Trace> traces;

    // Create cache
    Cache cache;

    for (size_t pkt_index = 1; pkt_index < branch_packets.size(); pkt_index++) {

        const BranchPacket branch_packet = branch_packets[pkt_index];

        if (branch_packet.type == BRANCH_PKT_ATOM) { // Atom packet
            if (state.trace_state == TRACE_OUT_OF_RANGE) {
                continue;
            }

            // Atomパケットの処理時に、未処理のIndirect Branchがある。
            // 本来であれば、Atomパケットではなく、Addressパケットがあるはずである。
            // このエラーが発生するとき、おそらくこのプログラム自体にバグがある。
            assert(state.has_pending_address_packet == false);

            // Cacheにアクセスして、既に同じトレースデータと開始アドレスから、
            // エッジカバレッジを復元したことがあるか調べる。
            // もし既にキャッシュに存在するなら、そのデータを使うことで高速化できる。
            if (param.cache_mode) {
                const TraceKey trace_key {
                    state.prev_location.offset,
                    state.prev_location.index,
                    branch_packet.en_bits,
                    branch_packet.en_bits_len,
                };
                if (isCachedTrace(cache, trace_key)) {
                    AtomTrace trace = getTraceCache(cache, trace_key);
                    // Update state
                    state.prev_location = trace.locations.back();
                    state.has_pending_address_packet = trace.has_pending_address_packet;

                    // Save trace
                    traces.emplace_back(Trace(trace));
                } else {
                    AtomTrace trace = processAtomPacket(param, state, cache, handle, memory_map, branch_packet);

                    // Save trace
                    traces.emplace_back(Trace(trace));
                    // Add trace to cache
                    addTraceCache(cache, trace_key, trace);
                }
            } else {
                AtomTrace trace = processAtomPacket(param, state, cache, handle, memory_map, branch_packet);
                traces.emplace_back(Trace(trace));
            }
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

            if (state.has_pending_address_packet or state.trace_state == TRACE_OUT_OF_RANGE) {
                const AddressTrace trace = processAddressPacket(param,state, memory_map, branch_packet);
                // Save trace
                if (state.trace_state == TRACE_ON) {
                    traces.emplace_back(trace);
                }
                if (state.trace_state == TRACE_RESTART) {
                    state.trace_state = TRACE_ON;
                }
            }
        } else {
            // Unknown branch packet.
            __builtin_unreachable();
        }
    }

    if (state.has_pending_address_packet) {
        std::cerr << "This trace data is incomplete. There is no Address packet following Atom packet." << std::endl;
        std::exit(1);
    }

    return traces;
}

AtomTrace processAtomPacket(const ProcessParam &param, ProcessState &state, Cache &cache,
    const csh &handle, const std::vector<MemoryMap> &memory_map, const BranchPacket &atom_packet)
{
    AtomTrace trace = AtomTrace(state.prev_location);

    for (std::size_t i = 0; i < atom_packet.en_bits_len; ++i) {
        const Location base_location = state.prev_location;

        const BranchInsn insn = processNextBranchInsn(param, state, cache, handle, memory_map, base_location);

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
    trace.calculateBitmapKeys(param.bitmap_size);

    return trace;
}

AddressTrace processAddressPacket(const ProcessParam &param, ProcessState &state,
    const std::vector<MemoryMap> &memory_map, const BranchPacket &address_packet)
{
    const Location src_location  = state.prev_location;
    const Location dest_location = Location(memory_map, address_packet.target_address);

    // Set branch destination address by indirect branch
    AddressTrace trace(src_location, dest_location);

    // Create bitmap keys from the trace generated by the Indirect Branch
    trace.calculateBitmapKey(param.bitmap_size);

    // Update state
    state.prev_location = dest_location;
    state.has_pending_address_packet = false;

    if (checkAddressRange(param, src_location) and checkAddressRange(param, dest_location)) {
        state.trace_state = TRACE_ON;
    } else if (checkAddressRange(param, dest_location)) {
        state.trace_state = TRACE_RESTART;
    } else {
        state.trace_state = TRACE_OUT_OF_RANGE;
    }

    return trace;
}

BranchInsn processNextBranchInsn(const ProcessParam &param, ProcessState &state, Cache &cache,
    const csh &handle, const std::vector<MemoryMap> &memory_map, const Location base_location)
{
    // 次の分岐命令を計算する。
    BranchInsn insn; {
        if (param.cache_mode) {

            // BranchInsnのキャッシュにアクセスするためのキーを作成する。
            BranchInsnKey insn_key {
                base_location.offset,
                base_location.index
            };

            // Cacheにアクセスして、既にディスアセンブルした命令か調べる。
            // 同じバイナリファイル&オフセットに対するこの処理は、キャッシュ化することができる。
            // もし既にキャッシュに存在するなら、そのデータを使うことで高速化できる。
            if (isCachedBranchInsn(cache, insn_key)) {
                // 既にディスアセンブルした結果がキャッシュにあるため、そのデータを読み込む。
                insn = getBranchInsnCache(cache, insn_key);
            } else {
                // 命令列をディスアセンブルし、分岐命令を探す。
                insn = getNextBranchInsn(param, handle, base_location, memory_map);
                // Cacheに分岐命令をディスアセンブルした結果を格納する。
                addBranchInsnCache(cache, insn_key, insn);
            }
        } else {
            // 命令列をディスアセンブルし、分岐命令を探す。
            insn = getNextBranchInsn(param, handle, base_location, memory_map);
        }
    }
    return insn;
}

bool checkAddressRange(const ProcessParam &param, const Location &location)
{
    // TODO:
    return true;
}
