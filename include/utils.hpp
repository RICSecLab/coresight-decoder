#pragma once

std::vector<uint8_t> readBinaryFile(const std::string &filename);
void writeBinaryFile(const std::vector<uint8_t> &data, const std::string &filename);
