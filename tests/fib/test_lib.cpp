#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <algorithm>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "libcsdec.h"

int load_bin(const char *path, void **buf, size_t *size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        std::exit(1);
    }

    struct stat sb;
    fstat(fd, &sb);

    char *addr = (char *)mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        std::exit(EXIT_FAILURE);
    }

    *buf = (void *)addr;
    *size = (size_t)sb.st_size;

    close(fd);
    return 0;
}

int check_bitmaps(unsigned char* global_bitmap, unsigned char* local_bitmap, int bitmap_size) {

    int diff_cnt = 0;
    for (int i = 0; i < bitmap_size; ++i) {
        if (global_bitmap[i] != local_bitmap[i]) {
            diff_cnt++;
            global_bitmap[i] = local_bitmap[i];
        }
    }
    return diff_cnt;
}


void test_edge(unsigned char *global_bitmap, const int bitmap_size) {
    const int binary_file_num = 1;
    const char* binary_file_path[] = {
        "fib",
    };

    unsigned char* local_bitmap = (unsigned char*)malloc(bitmap_size);

    libcsdec_t libcsdec = libcsdec_init_edge(binary_file_num, binary_file_path, local_bitmap, bitmap_size);
    if (libcsdec == NULL) {
        printf("Failed to initialize libcsdec\n");
        exit(1);
    }

    // trace1
    {
        const char trace_data_filename[PATH_MAX] = "trace1/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaadd370000, 0xaaaadd371000, "fib"},
            {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
            {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_edge(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_edge(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find new edge
        assert(diff_cnt > 0);
    }

    // trace2
    {
        const char trace_data_filename[PATH_MAX] = "trace2/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaaac0b0000, 0xaaaaac0b1000, "fib"},
            {0xffff83b7a000, 0xffff83b9b000, "ld-2.31.so"},
            {0xffff83a07000, 0xffff83b7a000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_edge(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_edge(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace3
    {
        const char trace_data_filename[PATH_MAX] = "trace3/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac3f60000, 0xaaaac3f61000, "fib"},
            {0xffff93020000, 0xffff93041000, "ld-2.31.so"},
            {0xffff92ead000, 0xffff93020000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_edge(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_edge(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace4
    {
        const char trace_data_filename[PATH_MAX] = "trace4/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac4e00000, 0xaaaac4e01000, "fib"},
            {0xffff80c02000, 0xffff80c23000, "ld-2.31.so"},
            {0xffff80a8f000, 0xffff80c02000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_edge(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_edge(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }
}


void test_edge_sequence(unsigned char *global_bitmap, const int bitmap_size) {
    const int binary_file_num = 1;
    const char* binary_file_path[] = {
        "fib",
    };

    unsigned char* local_bitmap = (unsigned char*)malloc(bitmap_size);

    libcsdec_t libcsdec = libcsdec_init_edge(binary_file_num, binary_file_path, local_bitmap, bitmap_size);
    if (libcsdec == NULL) {
        printf("Failed to initialize libcsdec\n");
        exit(1);
    }

    // trace1
    {
        const char trace_data_filename[PATH_MAX] = "trace1/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaadd370000, 0xaaaadd371000, "fib"},
            {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
            {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 16) {
            enum libcsdec_result result = libcsdec_run_edge(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(16, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_edge(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find new edge
        assert(diff_cnt > 0);
    }

    // trace2
    {
        const char trace_data_filename[PATH_MAX] = "trace2/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaaac0b0000, 0xaaaaac0b1000, "fib"},
            {0xffff83b7a000, 0xffff83b9b000, "ld-2.31.so"},
            {0xffff83a07000, 0xffff83b7a000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 16) {
            enum libcsdec_result result = libcsdec_run_edge(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(16, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_edge(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace3
    {
        const char trace_data_filename[PATH_MAX] = "trace3/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac3f60000, 0xaaaac3f61000, "fib"},
            {0xffff93020000, 0xffff93041000, "ld-2.31.so"},
            {0xffff92ead000, 0xffff93020000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 32) {
            enum libcsdec_result result = libcsdec_run_edge(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(32, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_edge(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace4
    {
        const char trace_data_filename[PATH_MAX] = "trace4/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac4e00000, 0xaaaac4e01000, "fib"},
            {0xffff80c02000, 0xffff80c23000, "ld-2.31.so"},
            {0xffff80a8f000, 0xffff80c02000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_edge(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 64) {
            enum libcsdec_result result = libcsdec_run_edge(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(64, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_edge(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }
}



void test_path(unsigned char *global_bitmap, const int bitmap_size) {
    unsigned char* local_bitmap = (unsigned char*)malloc(bitmap_size);

    libcsdec_t libcsdec = libcsdec_init_path(local_bitmap, bitmap_size);
    if (libcsdec == NULL) {
        printf("Failed to initialize libcsdec\n");
        exit(1);
    }

    // trace1
    {
        const char trace_data_filename[PATH_MAX] = "trace1/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaadd370000, 0xaaaadd371000, "fib"},
            {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
            {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_path(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_path(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find new edge
        assert(diff_cnt > 0);
    }

    // trace2
    {
        const char trace_data_filename[PATH_MAX] = "trace2/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaaac0b0000, 0xaaaaac0b1000, "fib"},
            {0xffff83b7a000, 0xffff83b9b000, "ld-2.31.so"},
            {0xffff83a07000, 0xffff83b7a000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_path(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_path(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace3
    {
        const char trace_data_filename[PATH_MAX] = "trace3/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac3f60000, 0xaaaac3f61000, "fib"},
            {0xffff93020000, 0xffff93041000, "ld-2.31.so"},
            {0xffff92ead000, 0xffff93020000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_path(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_path(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace4
    {
        const char trace_data_filename[PATH_MAX] = "trace4/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac4e00000, 0xaaaac4e01000, "fib"},
            {0xffff80c02000, 0xffff80c23000, "ld-2.31.so"},
            {0xffff80a8f000, 0xffff80c02000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        enum libcsdec_result result1 = libcsdec_run_path(
            libcsdec, trace_data_addr, trace_data_size);

        enum libcsdec_result result2 = libcsdec_finish_path(libcsdec);

        if (result1 != LIBCSDEC_SUCCESS or result2 != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }
}


void test_path_sequence(unsigned char *global_bitmap, const int bitmap_size) {
    unsigned char* local_bitmap = (unsigned char*)malloc(bitmap_size);

    libcsdec_t libcsdec = libcsdec_init_path(local_bitmap, bitmap_size);
    if (libcsdec == NULL) {
        printf("Failed to initialize libcsdec\n");
        exit(1);
    }

    // trace1
    {
        const char trace_data_filename[PATH_MAX] = "trace1/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaadd370000, 0xaaaadd371000, "fib"},
            {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
            {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 16) {
            enum libcsdec_result result = libcsdec_run_path(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(16, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_path(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find new edge
        assert(diff_cnt > 0);
    }

    // trace2
    {
        const char trace_data_filename[PATH_MAX] = "trace2/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaaac0b0000, 0xaaaaac0b1000, "fib"},
            {0xffff83b7a000, 0xffff83b9b000, "ld-2.31.so"},
            {0xffff83a07000, 0xffff83b7a000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 16) {
            enum libcsdec_result result = libcsdec_run_path(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(16, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_path(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace3
    {
        const char trace_data_filename[PATH_MAX] = "trace3/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac3f60000, 0xaaaac3f61000, "fib"},
            {0xffff93020000, 0xffff93041000, "ld-2.31.so"},
            {0xffff92ead000, 0xffff93020000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 32) {
            enum libcsdec_result result = libcsdec_run_path(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(32, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_path(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    // trace4
    {
        const char trace_data_filename[PATH_MAX] = "trace4/cstrace.bin";
        const char trace_id = 0x10;
        const int memory_map_num = 3;
        const struct libcsdec_memory_map memory_map[] = {
            {0xaaaac4e00000, 0xaaaac4e01000, "fib"},
            {0xffff80c02000, 0xffff80c23000, "ld-2.31.so"},
            {0xffff80a8f000, 0xffff80c02000, "libc-2.31.so"}
        };

        void *trace_data_addr = NULL;
        size_t trace_data_size = 0;
        load_bin(trace_data_filename, &trace_data_addr, &trace_data_size);

        libcsdec_reset_path(libcsdec, trace_id,
            memory_map_num, memory_map);

        for (size_t i = 0; i < trace_data_size; i += 64) {
            enum libcsdec_result result = libcsdec_run_path(
                libcsdec, (unsigned char*)trace_data_addr + i,
                std::min<size_t>(64, trace_data_size - i));
            if (result != LIBCSDEC_SUCCESS) {
                printf("Decoder error occurred.\n");
                exit(1);
            }
        }

        if (libcsdec_finish_path(libcsdec) != LIBCSDEC_SUCCESS) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps(global_bitmap, local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }
}



int main(int argc, char const *argv[])
{
    const int bitmap_size = 0x1000;

    {
        unsigned char* global_bitmap1 = (unsigned char*)malloc(bitmap_size);
        memset(global_bitmap1, 0, bitmap_size);
        test_edge(global_bitmap1, bitmap_size);

        unsigned char* global_bitmap2 = (unsigned char*)malloc(bitmap_size);
        memset(global_bitmap2, 0, bitmap_size);
        test_edge_sequence(global_bitmap2, bitmap_size);

        int diff_cnt = check_bitmaps(global_bitmap1, global_bitmap2, bitmap_size);
        assert(diff_cnt == 0);
    }

    {
        unsigned char* global_bitmap1 = (unsigned char*)malloc(bitmap_size);
        memset(global_bitmap1, 0, bitmap_size);
        test_path(global_bitmap1, bitmap_size);

        unsigned char* global_bitmap2 = (unsigned char*)malloc(bitmap_size);
        memset(global_bitmap2, 0, bitmap_size);
        test_path_sequence(global_bitmap2, bitmap_size);

        int diff_cnt = check_bitmaps(global_bitmap1, global_bitmap2, bitmap_size);
        assert(diff_cnt == 0);
    }

    return 0;
}
