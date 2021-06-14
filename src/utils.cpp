#include <string>
#include <fstream>
#include <vector>

#include "utils.hpp"


std::vector<uint8_t> readBinaryFile(const std::string &filename)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    std::vector<uint8_t> result(pos);

    ifs.seekg(0, std::ios::beg);
    ifs.read((char*)&result[0], pos);

    return result;
}

void writeBinaryFile(const std::vector<uint8_t> &data, const std::string &filename)
{
    std::ofstream ofs(filename, std::ios::out | std::ios::binary);
    ofs.write((const char*)&data[0], data.size() * sizeof(uint8_t));
    ofs.close();
}
