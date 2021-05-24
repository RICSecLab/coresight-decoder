#include <string>
#include <fstream>
#include <vector>

#include "utils.hpp"


std::vector<uint8_t> read_binary_file(const std::string &filename)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    std::vector<uint8_t> result(pos);

    ifs.seekg(0, std::ios::beg);
    ifs.read((char*)&result[0], pos);

    return result;
}
