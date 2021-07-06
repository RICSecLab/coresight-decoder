#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

#include "bitmap.hpp"
#include "trace.hpp"


// ELFファイル上のオフセットとして記録してあるエッジカバレッジから、bitmapを計算する。
// TODO: coverageデータにはELFファイルの上のオフセットが記録されており、
// 複数のELFファイルがある場合、どのファイルのオフセットなのかを区別する必要があるが、
// 現在はしていない。
void writeBitmap(const std::vector<Trace> &traces,
    std::uint8_t* const bitmap, const size_t bitmap_size)
{
    // Reset bitmap
    std::fill(bitmap, bitmap + bitmap_size, 0);

    // Write bitmap
    for (const Trace &trace: traces) {
        if (trace.type == TRACE_ATOM_TYPE) {
            // Direct branchのbitmapをコピーする
            for (const uint64_t key : trace.atom_trace.bitmap_keys) {
                // bitmapのキーの値から、対応する位置の値を増やす。
                bitmap[key]++;
            }
        } else if (trace.type == TRACE_ADDRESS_TYPE) {
            // Indirect branchのbitmapをコピーする
            bitmap[trace.address_trace.bitmap_key]++;
        } else {
            __builtin_unreachable();
        }
    }
}

uint64_t generateBitmapKey(const Location& from_location, const Location& to_location, const size_t bitmap_size)
{
    //ELF上のオフセットの値をハッシュ関数を通して、ランダムな値に変換し、
    // それを用いて、bitmapのキーを計算する。
    //
    // aflのtechnical_details.txtに書いてある通り、AFLのカバレッジの計算は以下のようである。
    //     cur_location = <COMPILE_TIME_RANDOM>;
    //     shared_mem[cur_location ^ prev_location]++;
    //     prev_location = cur_location >> 1;
    //
    const uint64_t to_h   = std::hash<Location>()(from_location);
    const uint64_t from_h = std::hash<Location>()(to_location);
    return (to_h ^ (from_h >> 1)) & (bitmap_size - 1);
}
