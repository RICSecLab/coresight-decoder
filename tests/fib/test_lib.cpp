#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "libcsdec.h"


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


int main(int argc, char const *argv[])
{
    const int binary_file_num = 3;
    const char* binary_file_path[] = {
        "fib",
        "ld-2.31.so",
        "libc-2.31.so"
    };
    const int bitmap_size = 0x1000;
    void* local_bitmap  = malloc(bitmap_size);
    const bool cache_mode = false;

    libcsdec_t libcsdec = libcsdec_init(binary_file_num, binary_file_path, local_bitmap, bitmap_size, cache_mode);
    if (libcsdec == NULL) {
        printf("Failed to initialize libcsdec\n");
        exit(1);
    }


    void* global_bitmap = malloc(bitmap_size);

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

        enum libcsdec_result result = libcsdec_write_bitmap(libcsdec, trace_data_filename, trace_id, memory_map_num, memory_map);
        if (result == DECODE_ERROR) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps((unsigned char*)global_bitmap, (unsigned char*)local_bitmap, bitmap_size);
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

        enum libcsdec_result result = libcsdec_write_bitmap(libcsdec, trace_data_filename, trace_id, memory_map_num, memory_map);
        if (result == DECODE_ERROR) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps((unsigned char*)global_bitmap, (unsigned char*)local_bitmap, bitmap_size);
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

        enum libcsdec_result result = libcsdec_write_bitmap(libcsdec, trace_data_filename, trace_id, memory_map_num, memory_map);
        if (result == DECODE_ERROR) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps((unsigned char*)global_bitmap, (unsigned char*)local_bitmap, bitmap_size);
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

        enum libcsdec_result result = libcsdec_write_bitmap(libcsdec, trace_data_filename, trace_id, memory_map_num, memory_map);
        if (result == DECODE_ERROR) {
            printf("Decoder error occurred.\n");
            exit(1);
        }

        int diff_cnt = check_bitmaps((unsigned char*)global_bitmap, (unsigned char*)local_bitmap, bitmap_size);
        // Find no new edge
        assert(diff_cnt == 0);
    }

    printf("PASSED fib library test\n");
    return 0;
}
