#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <iostream>
#include <chrono>
#include <bitset>
#include <fstream>
#include <optional>
#include <vector>
#include <algorithm>
#include <numeric>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "libcsdec.h"


enum class Cov { Edge, Path };

#if defined EDGE_COV
    constexpr Cov cov = Cov::Edge;
#elif defined PATH_COV
    constexpr Cov cov = Cov::Path;
#else
    #error Specify the coverage recording method with edge or path.
#endif


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

libcsdec_memory_map* read_memory_map(const std::string &decoder_args_path, char *trace_data_filepath,
    int &trace_id, int &memory_map_num) {
    // Read decoderargs.txt.
    std::ifstream fin(decoder_args_path);
    if (!fin) {
        std::cerr << "Failed to read decoderargs.txt" << std::endl;
        std::cerr << "Error code: " << strerror(errno); // Get some info as to why
        std::exit(EXIT_FAILURE);
    }

    // Parse decoderargs.txt and Create libcsdec_memory_map.
    fin >> trace_data_filepath >> std::hex >> trace_id >> memory_map_num;

    libcsdec_memory_map *memory_map = (libcsdec_memory_map*)malloc(sizeof(libcsdec_memory_map) * memory_map_num);

    for (int i = 0; i < memory_map_num; i++) {
        fin >> memory_map[i].path >> memory_map[i].start >> memory_map[i].end;
    }

    return memory_map;
}

std::optional<double> run_decoder(libcsdec_t &libcsdec, const std::string &decoder_args_path, unsigned char* global_bitmap,
    unsigned char* local_bitmap, const int bitmap_size, bool has_new_cov) {
    char trace_data_filepath[PATH_MAX];
    int trace_id = 0;
    int memory_map_num;
    struct libcsdec_memory_map *memory_map =
        read_memory_map(decoder_args_path, trace_data_filepath, trace_id, memory_map_num);

    void *trace_data_addr = NULL;
    size_t trace_data_size = 0;
    load_bin(trace_data_filepath, &trace_data_addr, &trace_data_size);

    if (cov == Cov::Edge) {
        libcsdec_reset_edge(libcsdec,trace_id, memory_map_num, memory_map);
    } else if (cov == Cov::Path) {
        libcsdec_reset_path(libcsdec, trace_id, memory_map_num, memory_map);
    } else {
        __builtin_unreachable();
    }

    // Run decoder and measure its execution time.
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();

    if (cov == Cov::Edge) {
        if (libcsdec_run_edge(libcsdec, trace_data_addr, trace_data_size) != LIBCEDEC_SUCCESS) {
            std::cerr << "Failed to run decoder." << std::endl;
        }
    } else if (cov == Cov::Path) {
        if (libcsdec_run_path(libcsdec, trace_data_addr, trace_data_size) != LIBCEDEC_SUCCESS) {
            std::cerr << "Failed to run decoder." << std::endl;
        }
    } else {
        __builtin_unreachable();
    }

    std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
    double elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end-start).count();

    if (cov == Cov::Edge) {
        if (libcsdec_finish_edge(libcsdec) != LIBCEDEC_SUCCESS) {
            std::cerr << "Failed to finish decoder." << std::endl;
            return std::nullopt;
        }
    } else if (cov == Cov::Path) {
        if (libcsdec_finish_path(libcsdec) != LIBCEDEC_SUCCESS) {
            std::cerr << "Failed to finish decoder." << std::endl;
            return std::nullopt;
        }
    } else {
        __builtin_unreachable();
    }

    int diff_cnt = check_bitmaps((unsigned char*)global_bitmap, (unsigned char*)local_bitmap, bitmap_size);

    if (has_new_cov) {
        // Find new edge
        assert(diff_cnt > 0);
    } else {
        assert(diff_cnt == 0);
    }

    return elapsed;
}

void save_exeuction_times(std::vector<double> &execution_times, std::string filename) {
    std::ofstream ofs(filename);
    if (!ofs) {
        std::cerr << "Failed to open " << filename << std::endl;
        std::exit(EXIT_FAILURE);
    }

    int idx = 0;
    for (const double time : execution_times) {
        ofs << idx << " " << time << std::endl;
        idx++;
    }
}

void print_results(const std::vector<double> &data) {
    const double ans_min = *std::min_element(data.begin(), data.end());
    const double ans_max = *std::max_element(data.begin(), data.end());
    const double ans_avg = std::accumulate(begin(data), end(data), 0.0) / data.size();
    const double ans_med = (data.size() % 2 == 0
        ? static_cast<double>(data[data.size() / 2] + data[data.size() / 2 - 1]) / 2
        : data[data.size() / 2]);
    printf("MIN: %f[us], MAX: %f[us], AVG: %f[us], MED: %f[us]\n", ans_min, ans_max, ans_avg, ans_med);
}

int main(int argc, char const *argv[])
{
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << "[tracee_path] [output filename] [LOOP CNT]"
                  << "[trace out dir1] [trace out dir2] .. " << std::endl;
        std::exit(EXIT_FAILURE);
    }

    const int binary_file_num = 1;
    const char* binary_file_path[] = { argv[1] };

    const int bitmap_size = 0x10000;
    unsigned char* local_bitmap  = (unsigned char*)malloc(bitmap_size);

    libcsdec_t libcsdec; {
        if (cov == Cov::Edge) {
            libcsdec = libcsdec_init_edge(binary_file_num, binary_file_path,local_bitmap, bitmap_size);
        } else if (cov == Cov::Path) {
            libcsdec = libcsdec_init_path(local_bitmap, bitmap_size);
        } else {
            __builtin_unreachable();
        }
    }

    if (libcsdec == NULL) {
        std::cerr << "Failed to initialize libcsdec" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    unsigned char* global_bitmap = (unsigned char*)malloc(bitmap_size);
    memset(global_bitmap, 0, bitmap_size);

    std::vector<std::string> trace_out_dirs;
    for (int i = 4; i < argc; i++) {
        trace_out_dirs.emplace_back(argv[i]);
    }

    std::vector<double> execution_times;
    for (int time = 0; time < atoi(argv[3]); ++time) {
        for (std::size_t i = 0; i < trace_out_dirs.size(); i++) {
            // Here, it dependes on the PUT.
            const std::string trace_out_dir = argv[1];
            const std::string decoder_args_path = trace_out_dirs[i] + "/decoderargs.txt";

            std::optional<double> execution_time = run_decoder(libcsdec, decoder_args_path,
                global_bitmap, local_bitmap, bitmap_size, (i == 0 and time == 0));
            if (execution_time.has_value()) {
                execution_times.emplace_back(execution_time.value());
            }
        }
    }

    save_exeuction_times(execution_times, argv[3]);
    print_results(execution_times);
    return 0;
}
