# For performance test
CACHE_MODE := 1
NON_CACHE_MODE := 0
PERFORMANCE_TEST_DIR := ../performance
TRACEE := branches
TRACE_DATA_DIR1 := $(realpath trace1)
TRACE_DATA_DIR2 := $(realpath trace2)
TRACE_DATA_DIR3 := $(realpath trace3)
TRACE_DATA_DIR4 := $(realpath trace4)
LOOP_CNT := 256
EXECUTION_TIMES_DATA_NON_CACHE_MODE := execution_times_non_cache_mode.dat
EXECUTION_TIMES_DATA_CACHE_MODE := execution_times_cache_mode.dat


test: test-non-cache-mode test-cache-mode

test-non-cache-mode:
	make -C ../../ clean
	make -C ../../ CACHE_MODE=0 PRINT_EDGE_COV=1
	./test.sh NON_CACHE_MODE

test-cache-mode:
	make -C ../../ clean
	make -C ../../ CACHE_MODE=1 PRINT_EDGE_COV=1
	./test.sh CACHE_MODE

test-performance-cache-mode:
	make run-decoder-with-non-cache-mode
	make run-decoder-with-cache-mode
	# Plot
	gnuplot -e "non_cache_mode='$(EXECUTION_TIMES_DATA_NON_CACHE_MODE)'; \
		cache_mode='$(EXECUTION_TIMES_DATA_CACHE_MODE)'" plot.plt

run-decoder-with-non-cache-mode:
	make -C ../../ clean && make -C ../../ CACHE_MODE=$(NON_CACHE_MODE)
	make -C $(PERFORMANCE_TEST_DIR)
	# Execute decoder with non-cache mode
	$(PERFORMANCE_TEST_DIR)/test $(TRACEE) $(EXECUTION_TIMES_DATA_NON_CACHE_MODE) \
		$(LOOP_CNT) $(TRACE_DATA_DIR1)

run-decoder-with-cache-mode:
	make -C ../../ clean && make -C ../../ CACHE_MODE=$(CACHE_MODE)
	make -C $(PERFORMANCE_TEST_DIR)
	# Execute decoder with cache mode
	$(PERFORMANCE_TEST_DIR)/test $(TRACEE) $(EXECUTION_TIMES_DATA_CACHE_MODE) \
		$(LOOP_CNT) $(TRACE_DATA_DIR1)

clean:
	rm -f trace*_edge_coverage.out trace*_bitmap.out
	rm -rf execution_times_cache_mode.dat execution_times_non_cache_mode.dat

.PHONY: test test-non-cache-mode test-cache-mode \
		test-performance-cache-mode run-decoder-with-non-cache-mode run-decoder-with-cache-mode \
		clean
