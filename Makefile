# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Ricerca Security, Inc. All rights reserved.

TARGET := processor
LIBTARGET := libcsdec.a

SRC_DIR := src
INC_DIR := include

# capstone library name (without prefix 'lib' and suffix '.so')
LIBCAPSTONE := capstone

CXX ?= g++
CXXFLAGS := -std=c++17 -Wall
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -l$(LIBCAPSTONE)

# When the value is 1, cache mode is enabled.
# This mode speeds up the decoding process by saving the disassemble
# and trace results in the software cache."
CACHE_MODE := 1

PRINT_EDGE_COV := 0

ifeq ($(CACHE_MODE), 1)
	CXXFLAGS += -DCACHE_MODE
endif

ifeq ($(PRINT_EDGE_COV), 1)
	CXXFLAGS += -DPRINT_EDGE_COV
endif


# For ptrix mode
MAX_ATOM_LEN := 4096
ifneq ($(strip $(MAX_ATOM_LEN)),)
	CXXFLAGS += -DMAX_ATOM_LEN=$(MAX_ATOM_LEN)
endif


SRCS := $(SRC_DIR)/bitmap.cpp \
	$(SRC_DIR)/cache.cpp \
	$(SRC_DIR)/common.cpp \
	$(SRC_DIR)/decoder.cpp \
	$(SRC_DIR)/deformatter.cpp \
	$(SRC_DIR)/disassembler.cpp \
	$(SRC_DIR)/libcsdec.cpp \
	$(SRC_DIR)/process.cpp \
	$(SRC_DIR)/processor.cpp \
	$(SRC_DIR)/trace.cpp \
	$(SRC_DIR)/utils.cpp

OBJS := $(SRCS:.cpp=.o)

FIB_TEST := tests/fib
BRANCHES_TEST := tests/branches


all: CXXFLAGS += -O3
all: CXXFLAGS += -DNDEBUG # Disable calls to assert()
all: $(TARGET) $(LIBTARGET)

debug: CXXFLAGS += -DDEBUG_BUILD
debug: CXXFLAGS += -g
debug: $(TARGET) $(LIBTARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS)

$(LIBTARGET): $(subst src/processor.o,,$(OBJS))
	$(AR) -rc $@ $^

test: fib-test branches-test

fib-test:
	make -C $(FIB_TEST) test

branches-test:
	make -C $(BRANCHES_TEST) test

format:
	clang-format -i src/*.cpp include/*.hpp include/*.h tests/*.cpp

tidy:
	clang-tidy $(SRCS) \
		--checks='-*,bugprone-*,cert-*,cppcoreguidelines-*, \
				  hicpp-*,modernize-*,performance-*,portability-*, \
				  readability-*,misc-*' \
		-- -$(CXXFLAGS)

clean:
	rm -rf $(OBJS) $(TARGET) $(LIBTARGET)

dist-clean: clean
	make -C $(FIB_TEST) clean
	make -C $(BRANCHES_TEST) clean

.PHONY: all debug test fib-test branches-test format clean dist-clean
