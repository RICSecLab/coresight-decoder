/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#pragma once

std::vector<uint8_t> readBinaryFile(const std::string &filename);
void writeBinaryFile(const std::vector<uint8_t> &data, const std::string &filename);
