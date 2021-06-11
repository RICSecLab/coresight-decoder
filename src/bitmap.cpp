#include <vector>
#include <string>

#include "bitmap.hpp"


uint64_t generateBitmapKey(const uint64_t from, const uint64_t to);
uint64_t mixBits(const uint64_t value);


// ELFファイル上のオフセットとして記録してあるエッジカバレッジから、bitmapを計算する。
// TODO: coverageデータにはELFファイルの上のオフセットが記録されており、
// 複数のELFファイルがある場合、どのファイルのオフセットなのかを区別する必要があるが、
// 現在はしていない。
std::vector<uint8_t> createBitmap(const std::vector<Coverage> &coverage, size_t bitmap_size)
{
    std::vector<std::uint8_t> bitmap(bitmap_size, 0);

    // まず、ELF上のオフセットの値をハッシュ関数を通して、ランダムな値に変換し、
    // それを用いて、bitmapのキーを計算する。

    for (size_t i = 0; i < coverage.size() - 1; ++i) {
        // ハッシュ関数を通して、ELF上の位置の値をランダムな値に変換する。
        const uint64_t from = mixBits(coverage[i].binary_offset);
        const uint64_t to   = mixBits(coverage[i + 1].binary_offset);

        // bitmapのキーを計算し、対応する位置の値を増やす。
        const uint64_t bitmap_size = (uint64_t)bitmap.size();
        const uint64_t key = generateBitmapKey(from, to) & (bitmap_size - 1);
        bitmap[key]++;
    }

    return bitmap;
}

uint64_t generateBitmapKey(const uint64_t from, const uint64_t to)
{
    // aflのtechnical_details.txtに書いてある通り、AFLのカバレッジの計算は以下のようである。
    //     cur_location = <COMPILE_TIME_RANDOM>;
    //     shared_mem[cur_location ^ prev_location]++;
    //     prev_location = cur_location >> 1;
    //
    return mixBits(to) ^ (mixBits(from) >> 1);
}

uint64_t mixBits(const uint64_t value)
{
    uint64_t v = value;
    v ^= (v >> 31);
    v *= 0x7fb5d329728ea185;
    v ^= (v >> 27);
    v *= 0x81dadef4bc2dd44d;
    v ^= (v >> 33);
    return v;
}
