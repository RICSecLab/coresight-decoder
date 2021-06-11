#pragma once

#ifdef DEBUG_BUILD
# define DEBUG(fmt, ...) do {fprintf(stderr, fmt, ##__VA_ARGS__);} while (0)
#else
# define DEBUG(fmt, ...)
#endif


struct Coverage {
    uint64_t address;
    uint64_t binary_offset;
    size_t binary_file_index;
};
