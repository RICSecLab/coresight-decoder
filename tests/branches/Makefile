# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Ricerca Security, Inc. All rights reserved.

TEST_ROOT_DIR := ..

TRACE_DATA_NUM := 4
TRACE_DATA_DIR1 := $(realpath trace1)
TRACE_DATA_DIR2 := $(realpath trace2)
TRACE_DATA_DIR3 := $(realpath trace3)
TRACE_DATA_DIR4 := $(realpath trace4)

IMAGE_FILE_NUM := 3
IMAGE_FILE1 := $(realpath branches)
IMAGE_FILE2 := $(realpath ld-2.31.so)
IMAGE_FILE3 := $(realpath libc-2.31.so)

LOOP_CNT := 1


test:
	make test-processor
	make test-libcsdec

test-processor:
	make -C ../../ clean && make -C ../../ PRINT_EDGE_COV=1
	./test.sh

test-libcsdec:
	make -C ../../ clean && make -C ../../
	make -C $(TEST_ROOT_DIR)
	$(TEST_ROOT_DIR)/test \
		$(TRACE_DATA_NUM) $(TRACE_DATA_DIR1) $(TRACE_DATA_DIR2) $(TRACE_DATA_DIR3) $(TRACE_DATA_DIR4) \
		$(IMAGE_FILE_NUM) $(IMAGE_FILE1) $(IMAGE_FILE2) $(IMAGE_FILE3) \
		--loop-cnt=$(LOOP_CNT)

clean:
	rm -rf trace*_bitmap.out trace*_edge_coverage.out
	rm -f execution_times_cache_mode.dat execution_times_non_cache_mode.dat

.PHONY: test test-processor test-libcsdec clean
