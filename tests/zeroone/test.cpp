#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <bitset>

struct DiffInfo {
    std::vector<int> passed;
    std::vector<int> ignored;
};


std::vector<std::uint8_t> readBitmap(const std::string &filename)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    std::vector<uint8_t> data(pos);

    ifs.seekg(0, std::ios::beg);
    ifs.read((char*)&data[0], pos);
    return data;
}

std::unordered_map<size_t, uint8_t> GetCoverage(const int bit_seq)
{
    std::string bit_seq_str = std::bitset<8>(bit_seq).to_string();
    std::reverse(bit_seq_str.begin(), bit_seq_str.end());
    const std::string bitmap_filename = "trace/bit_seq_" + bit_seq_str + "/bitmap.out";

    std::vector<uint8_t> bitmap = readBitmap(bitmap_filename);

    std::unordered_map<size_t, uint8_t> coverage; {
        for (size_t key = 0; key < bitmap.size(); ++key) {
            BOOST_CHECK(bitmap[key] <= 1);

            if (bitmap[key] > 0) {
                coverage.insert(std::make_pair(key, bitmap[key]));
            }
        }
        std::cout << std::endl;
    }
    return coverage;
}

BOOST_AUTO_TEST_CASE(TestZeroOne)
{
    // create "diffs" between 00000000 and 10000000, between 0000000 and 01000000, ...
    auto base_cov = GetCoverage(0);
    // coverages cannot be empty
    BOOST_CHECK(base_cov.size() > 0);

    DiffInfo diffs[8];
    for (int i = 0; i < 8; i++) {
        auto cov = GetCoverage(1 << i);
        // coverages cannot be empty
        BOOST_CHECK(cov.size() > 0);

        // into DiffInfo::passed, append basic blocks which the seed corresponding to (1 << i) passes, but which the seed corresponding to 0 doesn't pass
        for (const auto& itr : cov) {
            if (!base_cov.count(itr.first)) diffs[i].passed.emplace_back(itr.first);
        }
        // into DiffInfo::ignored, append basic blocks which the seed corresponding to (1 << i) doesn't pass, but which the seed corresponding to 0 passes
        for (const auto& itr : base_cov) {
            if (!cov.count(itr.first)) diffs[i].ignored.emplace_back(itr.first);
        }

        std::string name(8, '0');
        name[i] = '1';
        std::cout << "---" << name << "---\n";
        std::cout << "Hashes of edges which this input should pass:";
        for (int edge_idx : diffs[i].passed) {
            std::cout << " " << edge_idx;
        }
        std::cout << "\nHashes of edges which given input should not pass:";
        for (int edge_idx : diffs[i].ignored) {
            std::cout << " " << edge_idx;
        }
        std::cout << std::endl;

        // there must be some differences
        BOOST_CHECK(diffs[i].passed.size() > 0);
        BOOST_CHECK(diffs[i].ignored.size() > 0);

        // moreover, normally the difference should be exactly two edges(where "var = 1" or "var = 0" takes place)
        BOOST_CHECK_EQUAL(diffs[i].passed.size(), 2);
        BOOST_CHECK_EQUAL(diffs[i].ignored.size(), 2);
    }

    int lim = 1 << 8;
    for (int bit_seq = 0; bit_seq < lim; bit_seq++) {
        std::string bit_seq_str = std::bitset<8>(bit_seq).to_string();
        std::reverse(bit_seq_str.begin(), bit_seq_str.end());
        std::cout << "bit_seq: " << bit_seq_str << std::endl;
        auto cov = GetCoverage(bit_seq);
        for (int i = 0; i < 8; i++) {
            // check if the i-th bit counting from LSB is set
            bool is_ith_set = bit_seq >> i & 1;
            if (is_ith_set) {
                // the i-th bit of this seed is set
                // that means seed bit_seq should have passed edges in diffs[i].passed
                for (int edge_idx : diffs[i].passed) {
                    BOOST_CHECK(cov.count(edge_idx) > 0);
                }
                // and that seed bit_seq should not have passed edges in diffs[i].ignored
                for (int edge_idx : diffs[i].ignored) {
                    BOOST_CHECK(cov.count(edge_idx) == 0);
                }
          } else {
                // the i-th bit of this seed is not set
                // that means seed bit_seq should have passed edges in diffs[i].ignored
                for (int edge_idx : diffs[i].ignored) {
                    BOOST_CHECK(cov.count(edge_idx) > 0);
                }
                // and that seed bit_seq should not have passed edges in diffs[i].passed
                for (int edge_idx : diffs[i].passed) {
                    BOOST_CHECK(cov.count(edge_idx) == 0);
                }
            }
        }
    }
}
