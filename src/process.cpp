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


void Process::reset(MemoryMaps &&memory_maps, const std::uint8_t target_trace_id)
{
    this->data.bitmap.reset();
    this->deformatter.reset(target_trace_id);
    this->decoder.reset();
    this->state.reset(std::move(memory_maps));
}

ProcessResultType Process::final()
{
    if (state.has_pending_address_packet) {
        // This trace data is incomplete. There is no Address packet following Atom packet.
        return ProcessResultType::PROCESS_ERROR_TRACE_DATA_INCOMPLETE;
    }

    return ProcessResultType::PROCESS_SUCCESS;
}

ProcessResultType Process::run(
    const std::uint8_t* trace_data_addr, const std::size_t trace_data_size)
{
    // Read trace data and deformat trace data.
    this->deformatter.deformatTraceData(trace_data_addr, trace_data_size, decoder.trace_data);

    const std::size_t size = this->decoder.trace_data.size();
    while (this->decoder.trace_data_offset < size) {
        const Packet packet = this->decoder.decodePacket();
        DEBUG("%s\n", packet.toString().c_str());

        // パケットデータの長さが不十分であり、現段階でデコードを正しく行うことができない
        // このとき、デコードを進めずに、いったん途中で終わる。
        if (packet.type == PKT_INCOMPLETE) {
            return ProcessResultType::PROCESS_SUCCESS;
        }

        this->decoder.trace_data_offset += packet.size;

        switch (this->decoder.state) {
            case DecodeState::START: {
                switch (packet.type) {
                    case ETM4_PKT_I_ATOM_F1:
                    case ETM4_PKT_I_ATOM_F2:
                    case ETM4_PKT_I_ATOM_F3:
                    case ETM4_PKT_I_ATOM_F4:
                    case ETM4_PKT_I_ATOM_F5:
                    case ETM4_PKT_I_ATOM_F6: {
                        // The first branch packet is always an address pocket.
                        // Otherwise, the trace start address is not known.
                        std::cerr << "The first branch packet is always an address pocket." << std::endl;
                        std::exit(EXIT_FAILURE);
                    }

                    case ETM4_PKT_I_ADDR_L_64IS0: {
                        // トレースの開始アドレスがメモリマップ上にあるか調べる。
                        // もしなければ、エラーを返す。
                        const std::optional<Location> optional_start_location =
                            getLocation(this->state.memory_maps, packet.addr);
                        if (not optional_start_location.has_value()) {
                            return ProcessResultType::PROCESS_ERROR_PAGE_FAULT;
                        }

                        const Location start_location = optional_start_location.value();
                        this->state.prev_location = start_location;
                        this->state.trace_state = checkTraceRange(this->state.memory_maps, start_location)
                            ? TraceStateType::TRACE_ON : TraceStateType::TRACE_OUT_OF_RANGE;

                        this->decoder.state = DecodeState::TRACE;
                        break;
                    }

                    default:
                        break;
                }
                break;
            }

            case DecodeState::TRACE: {
                switch (packet.type) {
                    case ETM4_PKT_I_ATOM_F1:
                    case ETM4_PKT_I_ATOM_F2:
                    case ETM4_PKT_I_ATOM_F3:
                    case ETM4_PKT_I_ATOM_F4:
                    case ETM4_PKT_I_ATOM_F5:
                    case ETM4_PKT_I_ATOM_F6: {
                        // ATOMパケットでは、トレースしているバイナリファイルに変化はないため、
                        // 既にトレース領域外であれば、ここでもトレース領域外である。
                        if (state.trace_state == TraceStateType::TRACE_OUT_OF_RANGE) {
                            break;
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
                                packet.en_bits,
                                packet.en_bits_len
                            );

                            if (this->data.cache.isCachedTrace(trace_key)) {
                                AtomTrace trace = this->data.cache.getTraceCache(trace_key);
                                // Update state
                                this->state.prev_location = trace.locations.back();
                                this->state.has_pending_address_packet = trace.has_pending_address_packet;

                                // Write bitmap
                                trace.writeBitmapKeys(this->data.bitmap);
                                #if defined(PRINT_EDGE_COV)
                                    trace.printTraceLocations(this->state.memory_maps);
                                #endif
                            } else {
                                AtomTrace trace = processAtomPacket(packet);

                                // Write bitmap
                                trace.writeBitmapKeys(this->data.bitmap);
                                #if defined(PRINT_EDGE_COV)
                                    trace.printTraceLocations(this->state.memory_maps);
                                #endif

                                // Add trace to cache
                                this->data.cache.addTraceCache(trace_key, trace);
                            }
                        #else
                            AtomTrace trace = processAtomPacket(packet);
                            // Write bitmap
                            trace.writeBitmapKeys(this->data.bitmap);
                            #if defined(PRINT_EDGE_COV)
                                trace.printTraceLocations(state.memory_maps);
                            #endif
                        #endif
                        break;
                    }

                    case ETM4_PKT_I_ADDR_L_64IS0: {
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
                                processAddressPacket(packet);
                            if (not optional_trace.has_value()) {
                                return ProcessResultType::PROCESS_ERROR_PAGE_FAULT;
                            }

                            const AddressTrace trace = optional_trace.value();

                            // Save trace
                            if (state.trace_state == TraceStateType::TRACE_ON) {
                                // Write bitmap
                                trace.writeBitmapKey(this->data.bitmap);
                                #if defined(PRINT_EDGE_COV)
                                    trace.printTraceLocation(state.memory_maps);
                                #endif
                            }
                            if (state.trace_state == TraceStateType::TRACE_RESTART) {
                                state.trace_state = TraceStateType::TRACE_ON;
                            }
                        }
                        break;
                    }

                    // Exception Packetは例外が発生したときに、生成される。
                    // Exceptionパケットに続き、2つのAddress Packetが生成される。
                    // 1つ目はException後に戻るアドレスを示し、
                    // 2つ目は実際にException後に実行が開始されたアドレスを示している。
                    // そのため、ユーザ空間のトレースではこの2つのAddress Packetを無視する。
                    case ETM4_PKT_I_EXCEPT: {
                        this->decoder.state = DecodeState::EXCEPTION_ADDR1;
                        break;
                    }

                    case ETM4_PKT_I_OVERFLOW: {
                        // An Overflow packet is output in the data trace stream whenever the data trace buffer
                        // in the trace unit overflows. This means that part of the data trace stream might be lost,
                        // and tracing is inactive until the overflow condition clears.
                        std::cerr << "Found an overflow packet that indicates that a trace unit buffer overflow has occurred. ";
                        std::cerr << "The trace data may be corrupted." << std::endl;
                        return ProcessResultType::PROCESS_ERROR_OVERFLOW_PACKET;
                    }

                    default:
                        break;
                }
                break;
            }

            case DecodeState::EXCEPTION_ADDR1: {
                if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                    this->decoder.state = DecodeState::EXCEPTION_ADDR2;
                }
                break;
            }

            case DecodeState::EXCEPTION_ADDR2: {
                if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                    this->decoder.state = DecodeState::TRACE;
                }
                break;
            }

            default:
                __builtin_unreachable();
        }
    }

    return ProcessResultType::PROCESS_SUCCESS;
}

AtomTrace Process::processAtomPacket(const Packet &atom_packet)
{
    AtomTrace trace = AtomTrace(state.prev_location);

    for (std::size_t i = 0; i < atom_packet.en_bits_len; ++i) {
        const Location base_location = state.prev_location;

        const BranchInsn insn = processNextBranchInsn(base_location);

        bool is_taken = atom_packet.en_bits & (1 << i);

        // Indirect branch命令のとき、Atom packet(E)とAddress packetが生成される。
        // そのため、Atom packetを一つ消費した後に、Address packetを処理する。
        if (insn.type == INDIRECT_BRANCH) {
            // Indirect branchで生成されるAtom PacketはEである。
            assert(is_taken == true);
            // Indirect branchの次に生成されるパケットはAddress Packetである。
            assert(i == atom_packet.en_bits_len - 1);

            // Indirect branchのジャンプ先アドレスを示すAddress packetを次に処理することを期待する。
            this->state.has_pending_address_packet = true;
            trace.setPendingAddressPacket();

            // TODO: この時のaddress packetは長さが1なので、トレースデータに保存する必要なし
        } else {
            const addr_t next_offset = (is_taken) ? insn.taken_offset : insn.not_taken_offset;
            const addr_t next_index = insn.index;
            const Location next_location = Location(next_offset, next_index);

            // Add branch destination address by direct branch
            trace.addLocation(next_location);

            // Update state
            this->state.prev_location = next_location;
        }
    }

    // Create bitmap keys from the trace generated by the Direct Branch
    trace.calculateBitmapKeys(this->data.bitmap.size);

    return trace;
}

std::optional<AddressTrace> Process::processAddressPacket(const Packet &address_packet)
{
    const std::optional<Location> optional_dest_location =
        getLocation(state.memory_maps, address_packet.addr);
    // ターゲットアドレスに対応するバイナリデータが存在しない。
    if (not optional_dest_location.has_value()) {
        return std::nullopt;
    }

    const Location src_location  = state.prev_location;
    const Location dest_location = optional_dest_location.value();

    // Set branch destination address by indirect branch
    AddressTrace trace(src_location, dest_location);

    // Create bitmap keys from the trace generated by the Indirect Branch
    trace.calculateBitmapKey(this->data.bitmap.size);

    // Update state
    this->state.prev_location = dest_location;
    this->state.has_pending_address_packet = false;

    if (checkTraceRange(this->state.memory_maps, src_location) and
        checkTraceRange(this->state.memory_maps, dest_location)) {
        state.trace_state = TraceStateType::TRACE_ON;
    } else if (checkTraceRange(state.memory_maps, dest_location)) {
        this->state.trace_state = TraceStateType::TRACE_RESTART;
    } else {
        this->state.trace_state = TraceStateType::TRACE_OUT_OF_RANGE;
    }

    return trace;
}

BranchInsn Process::processNextBranchInsn(const Location &base_location)
{
    // 次の分岐命令を計算する。
    BranchInsn insn; {
        #if defined(CACHE_MODE)
            // BranchInsnのキャッシュにアクセスするためのキーを作成する。
            const Location insn_key(base_location.offset, base_location.index);

            // Cacheにアクセスして、既にディスアセンブルした命令か調べる。
            // 同じバイナリファイル&オフセットに対するこの処理は、キャッシュ化することができる。
            // もし既にキャッシュに存在するなら、そのデータを使うことで高速化できる。
            if (this->data.cache.isCachedBranchInsn(insn_key)) {
                // 既にディスアセンブルした結果がキャッシュにあるため、そのデータを読み込む。
                insn = this->data.cache.getBranchInsnCache(insn_key);
            } else {
                // 命令列をディスアセンブルし、分岐命令を探す。
                insn = getNextBranchInsn(this->data.handle, base_location, this->state.memory_maps);
                // Cacheに分岐命令をディスアセンブルした結果を格納する。
                this->data.cache.addBranchInsnCache(std::move(insn_key), insn);
            }
        #else
            // 命令列をディスアセンブルし、分岐命令を探す。
            insn = getNextBranchInsn(this->data.handle, base_location, this->state.memory_maps);
        #endif
    }
    return insn;
}


ProcessResultType PTrixProcess::run(
    const std::uint8_t* trace_data_addr, const std::size_t trace_data_size)
{
    this->deformatter.deformatTraceData(trace_data_addr, trace_data_size, decoder.trace_data);

    const std::size_t size = this->decoder.trace_data.size();

    while (this->decoder.trace_data_offset < size) {
        const Packet packet = this->decoder.decodePacket();
        DEBUG(packet.toString());

        // パケットデータの長さが不十分であり、現段階でデコードを正しく行うことができない
        // このとき、デコードを進めずに、いったん途中で終わる。
        if (packet.type == PKT_INCOMPLETE) {
            return ProcessResultType::PROCESS_SUCCESS;
        }

        this->decoder.trace_data_offset += packet.size;

        switch (this->decoder.state) {
            case DecodeState::START:
            case DecodeState::TRACE: {
                switch (packet.type)
                    case ETM4_PKT_I_ATOM_F1:
                    case ETM4_PKT_I_ATOM_F2:
                    case ETM4_PKT_I_ATOM_F3:
                    case ETM4_PKT_I_ATOM_F4:
                    case ETM4_PKT_I_ATOM_F5:
                    case ETM4_PKT_I_ATOM_F6: {
                        if (ctx_en_bits_len < MAX_ATOM_LEN) {
                            ctx_en_bits |= std::bitset<MAX_ATOM_LEN>(packet.en_bits) << ctx_en_bits_len;
                            ctx_en_bits_len += packet.en_bits_len;
                        }
                        break;

                    case ETM4_PKT_I_ADDR_L_64IS0: {
                        const std::optional<Location> optional_target_location =
                            getLocation(this->memory_maps, packet.addr);
                        if (not optional_target_location.has_value()) {
                            return ProcessResultType::PROCESS_ERROR_PAGE_FAULT;
                        }

                        const Location target_location = optional_target_location.value();

                        // ATOMのEN列でhashを更新
                        if (ctx_en_bits_len != 0) {
                            ctx_hash ^= std::hash<std::bitset<MAX_ATOM_LEN>>()(ctx_en_bits);
                            ctx_en_bits = 0;
                            ctx_en_bits_len = 0;
                        }

                        // Addressでhashを更新
                        ctx_hash ^= std::hash<Location>()(target_location);
                        ctx_address_cnt++;

                        if (ctx_address_cnt >= MAX_ADDRESS_LEN) {
                            // bitmapのindexを計算する
                            std::size_t index = ctx_hash & (this->bitmap.size - 1);
                            // bitmapを更新する
                            this->bitmap.data[index]++;

                            ctx_address_cnt = 0;
                            ctx_hash = 0;
                        }
                        break;
                    }

                    // Exception Packetは例外が発生したときに、生成される。
                    // Exception Packetに続き、2つのAddress Packetが生成される。
                    // 1つ目はException後に戻るアドレスを示し、
                    // 2つ目は実際にException後に実行が開始されたアドレスを示している。
                    // そのため、ユーザ空間のトレースではこの2つのAddress Packetを無視する。
                    case ETM4_PKT_I_EXCEPT:
                        this->decoder.state = DecodeState::EXCEPTION_ADDR1;
                        break;

                    // Trace On Packetは、トレースストリームの不連続性を示す。
                    // トレースユニットはTrace On Packetを生成した後、
                    // 次のAtom、Exception Packetを発生する前に、
                    // トレースの開始位置を示すAddress Packetを生成する。
                    case ETM4_PKT_I_TRACE_ON:
                        this->decoder.state = DecodeState::WAIT_ADDR_AFTER_TRACE_ON;
                        break;

                    default:
                        break;
                }
                break;
            }

            case DecodeState::EXCEPTION_ADDR1: {
                if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                    this->decoder.state = DecodeState::EXCEPTION_ADDR2;
                }
                break;
            }

            case DecodeState::EXCEPTION_ADDR2: {
                if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                    this->decoder.state = DecodeState::TRACE;
                }
                break;
            }

            case DecodeState::WAIT_ADDR_AFTER_TRACE_ON: {
                if (packet.type == ETM4_PKT_I_ADDR_L_64IS0) {
                    this->decoder.state = DecodeState::TRACE;
                }
                break;
            }

            default:
                __builtin_unreachable();
        }

    }

    return ProcessResultType::PROCESS_SUCCESS;
}

void PTrixProcess::reset(MemoryMaps &&memory_maps, std::uint8_t target_trace_id)
{
    this->bitmap.reset();
    this->deformatter.reset(target_trace_id);
    this->decoder.reset();
    this->memory_maps = std::move(memory_maps);

    ctx_en_bits = 0;
    ctx_en_bits_len = 0;
    ctx_address_cnt = 0;
    ctx_hash = 0;
}

ProcessResultType PTrixProcess::final()
{
    return ProcessResultType::PROCESS_SUCCESS;
}
