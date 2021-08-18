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
    LIBCEDEC_SUCCESS,
    LIBCSDEC_ERROR,
    LIBCSDEC_ERROR_OVERFLOW_PACKET,
    LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE,
    LIBCSDEC_ERROR_PAGE_FAULT
} libcsdec_result_t;

libcsdec_t libcsdec_init_edge(
    int binary_file_num, const char *binary_file_path[],
    void *bitmap_addr, int bitmap_size);

libcsdec_result_t libcsdec_reset_edge(
    const libcsdec_t libcsdec,
    char trace_id, int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[]);

libcsdec_result_t libcsdec_run_edge(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size);

libcsdec_result_t libcsdec_finish_edge(const libcsdec_t libcsdec);


libcsdec_t libcsdec_init_path(
    void *bitmap_addr, int bitmap_size);

libcsdec_result_t libcsdec_reset_path(
    const libcsdec_t libcsdec,
    char trace_id, int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[]);

libcsdec_result_t libcsdec_run_path(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size);

libcsdec_result_t libcsdec_finish_path(const libcsdec_t libcsdec);

#ifdef __cplusplus
} // extern "C"
#endif
