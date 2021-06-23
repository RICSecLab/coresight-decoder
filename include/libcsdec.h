#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <limits.h>

struct bin_addr_range {
    unsigned long start;
    unsigned long end;
    char path[PATH_MAX];
};  

int write_bitmap(const char *trace_data_filename, const char trace_id,
    const int binary_file_num, struct bin_addr_range *binary_files,
    void *bitmap_addr, const int bitmap_size, bool cache_mode);

#ifdef __cplusplus
} // extern "C"
#endif
