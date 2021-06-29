#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <limits.h>

typedef void* libcsdec_t;

struct libcsdec_memory_map {
    unsigned long start;
    unsigned long end;
    char path[PATH_MAX];
};

typedef enum libcsdec_result {
    DECODE_SUCCESS,
    DECODE_ERROR,
} libcsdec_result_t;

libcsdec_t libcsdec_init(
    const int binary_file_num, const char *binary_file_path[],
    const void *bitmap_addr, const int bitmap_size, const bool cache_mode);

libcsdec_result_t libcsdec_write_bitmap(const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size,
    const char trace_id, const int memory_map_num,
    const struct libcsdec_memory_map memory_map[]);

#ifdef __cplusplus
} // extern "C"
#endif
