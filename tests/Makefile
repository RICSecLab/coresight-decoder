# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Ricerca Security, Inc. All rights reserved.

INC_DIR := ../include

LIBCSDEC := ../libcsdec.a

# capstone library name (without prefix 'lib' and suffix '.so')
LIBCAPSTONE := capstone

CXX := g++
CXXFLAGS := -Wall -O3 -std=c++17 -g
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -l$(LIBCAPSTONE)

EDGE_COV_MODE := 1
PATH_COV_MODE := 0

ifeq ($(EDGE_COV_MODE), 1)
	CXXFLAGS += -DEDGE_COV
endif

ifeq ($(PATH_COV_MODE), 1)
	CXXFLAGS += -DPATH_COV
endif

OBJS := test.o
PROGRAM := test


CACHE_MODE := 1
NON_CACHE_MODE := 0

TEST_TARGET := fib
# TEST_TARGET := branches

TRACE_DATA_NUM := 1
TRACE_DATA_DIR := $(realpath $(TEST_TARGET)/trace1)

IMAGE_FILE_NUM := 3
IMAGE_FILE1 := $(realpath $(TEST_TARGET)/$(TEST_TARGET))
IMAGE_FILE2 := $(realpath $(TEST_TARGET)/ld-2.31.so)
IMAGE_FILE3 := $(realpath $(TEST_TARGET)/libc-2.31.so)

PERFORMANCE_TEST_LOOP_CNT := 256
EXECUTION_TIMES_DATA_CACHE_MODE := execution_times_cache_mode.dat
EXECUTION_TIMES_DATA_NON_CACHE_MODE := execution_times_non_cache_mode.dat


$(PROGRAM): $(OBJS) $(LIBCSDEC)
	$(CXX) -o $@ $^ $(LIBCSDEC) $(CXXFLAGS)

test-performance: $(PROGRAM)
	make run-decoder-with-cache-mode
	make run-decoder-with-non-cache-mode

	gnuplot -e "non_cache_mode='$(TEST_TARGET)/$(EXECUTION_TIMES_DATA_NON_CACHE_MODE)'; \
		cache_mode='$(TEST_TARGET)/$(EXECUTION_TIMES_DATA_CACHE_MODE)'" plot.plt

run-decoder-with-cache-mode:
	make -C ../ clean && make -C ../ CACHE_MODE=$(CACHE_MODE)
	make $(PROGRAM)

	cd $(TEST_TARGET) && ../$(PROGRAM) \
		$(TRACE_DATA_NUM) $(TRACE_DATA_DIR) \
		$(IMAGE_FILE_NUM) $(IMAGE_FILE1) $(IMAGE_FILE2) $(IMAGE_FILE3) \
		--output-filename=$(EXECUTION_TIMES_DATA_CACHE_MODE) --loop-cnt=$(PERFORMANCE_TEST_LOOP_CNT)

run-decoder-with-non-cache-mode: $(PROGRAM)
	make -C ../ clean && make -C ../ CACHE_MODE=$(NON_CACHE_MODE)
	make $(PROGRAM)

	cd $(TEST_TARGET) && ../$(PROGRAM) \
		$(TRACE_DATA_NUM) $(TRACE_DATA_DIR) \
		$(IMAGE_FILE_NUM) $(IMAGE_FILE1) $(IMAGE_FILE2) $(IMAGE_FILE3) \
		--output-filename=$(EXECUTION_TIMES_DATA_NON_CACHE_MODE) --loop-cnt=$(PERFORMANCE_TEST_LOOP_CNT)

clean:
	rm -f test.o test

.PHONY: clean
