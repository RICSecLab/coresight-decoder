/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#include <fstream>
#include <string>
#include <vector>

#include "utils.hpp"

std::vector<uint8_t> readBinaryFile(const std::string &filename) {
  std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
  std::ifstream::pos_type pos = ifs.tellg();

  std::vector<uint8_t> result(pos);

  ifs.seekg(0, std::ios::beg);
  ifs.read(reinterpret_cast<char *>(&result[0]), pos);

  return result;
}

void writeBinaryFile(const std::vector<uint8_t> &data,
                     const std::string &filename) {
  std::ofstream ofs(filename, std::ios::out | std::ios::binary);
  ofs.write(reinterpret_cast<const char *>(&data[0]),
            data.size() * sizeof(uint8_t));
  ofs.close();
}
