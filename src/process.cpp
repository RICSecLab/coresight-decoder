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

std::vector<Trace> process(const std::vector<uint8_t>& trace_data, const std::vector<MemoryMap> &memory_map, const csh &handle,
    const uint64_t lower_address_range, const uint64_t upper_address_range, const bool cache_mode)
{
    // Trace dataの中から、エッジカバレッジの復元に必要なパケットのみを取り出す。
    std::vector<BranchPacket> branch_packets = decodeTraceData(trace_data);

    // btsの先頭データは必ずAddress packetである。
    // そうでないと、トレース開始アドレスがわからない。
    assert(branch_packets.front().type == BRANCH_PKT_ADDRESS);

    std::vector<Trace> coverage;

    // The address where the trace was started
    Trace trace = createTrace(memory_map, branch_packets.front().target_address);

    // Create cache
    Cache cache;

    for (size_t pkt_index = 1; pkt_index < branch_packets.size(); pkt_index++) {

        if (branch_packets[pkt_index].type == BRANCH_PKT_ATOM) { // Atom packet
            // TODO: 同じアドレスとBranchPacketに対する以下の処理は、キャッシュ化することができる。
            // これにより、高速化出来る
            const BranchPacket atom_packet = branch_packets[pkt_index];
            for (size_t i = 0; i < atom_packet.en_bits_len; ++i) {
                // Save trace information
                if (lower_address_range <= trace.address and trace.address < upper_address_range) {
                    coverage.emplace_back(trace);
                }

                BranchInsn insn; {
                    if (cache_mode) {
                        BranchInsnKey insn_key {
                            trace.offset, trace.index
                        };

                        // Cacheにアクセスして、既にディスアセンブルした命令か調べる。
                        // 同じバイナリファイル&オフセットに対するこの処理は、キャッシュ化することができる。
                        // もし既にキャッシュに存在するなら、そのデータを使うことで高速化できる。
                        if (isCachedBranchInsn(cache, insn_key)) {
                            // 既にディスアセンブルした結果がキャッシュにあるため、そのデータを読み込む。
                            insn = getBranchInsnCache(cache, insn_key);
                        } else {
                            // 命令列をディスアセンブルし、分岐命令を探す。
                            insn = getNextBranchInsn(handle, trace.address, memory_map);
                            // Cacheに分岐命令をディスアセンブルした結果を格納する。
                            addBranchInsnCache(cache, insn_key, insn);
                        }
                    } else {
                        // 命令列をディスアセンブルし、分岐命令を探す。
                        insn = getNextBranchInsn(handle, trace.address, memory_map);
                    }
                }

                // Calculate the next address to save as edge coverage (address -> next_address)
                Trace next_trace;

                bool is_taken = atom_packet.en_bits & (1 << i);

                // Indirect branch命令のとき、Atom packet(E)とAddress packetが生成される。
                // そのため、Atom packetを一つ消費した後に、Address packetを処理する。
                if (insn.type == INDIRECT_BRANCH) {
                    assert(is_taken == true);
                    pkt_index++;
                    if (pkt_index >= branch_packets.size()) {
                        std::cerr << "This trace data is incomplete. There is no Address packet following Atom packet." << std::endl;
                        std::exit(1);
                    }
                    assert(branch_packets[pkt_index].type == BRANCH_PKT_ADDRESS);
                    next_trace = createTrace(memory_map, branch_packets[pkt_index].target_address);
                } else {
                    if (is_taken) { // taken
                        next_trace.address = insn.taken_address;
                        next_trace.offset  = insn.taken_offset;
                    } else { // not taken
                        next_trace.address = insn.not_taken_address;
                        next_trace.offset  = insn.not_taken_offset;
                    }
                    next_trace.index = insn.index;
                }

                // Update
                trace = next_trace;
            }
        } else if (branch_packets[pkt_index].type == BRANCH_PKT_ADDRESS) { // Address packet
            // Address packetは下記の3つの場合に生成される。
            //     1. トレース開始時に、トレース開始アドレスを示すために生成される。
            //     2. Indirect branchのときに、Atom pakcet(E)に続き、生成される。
            //     3. トレースが途切れたときに、Trace On packetに続き、生成される。
            // 3.のとき、
            //     3.1 トレースが再開されたアドレスを示すAddress packetの場合と、
            //     3.2 トレースが途切れる前のAtom(E)に続く、Address packetの場合がある。
            // 3.1の場合は必要ないので無視する。
        } else {
            std::cerr << "Unknown branch packet." << std::endl;
            std::exit(1);
        }
    }
    return coverage;
}
