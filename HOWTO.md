# How to use coresight-decoder library

## Edge coverage

This mode generates an AFL-style bitmap by reconstructing edge coverage from the executables and the trace data.

The below is an example.

```cpp
const int bitmap_size = 0x1000;
unsigned char* bitmap = (unsigned char*)malloc(bitmap_size);

// Initialize the deocder.
libcsdec_t libcsdec = libcsdec_init_edge(bitmap, bitmap_size);

const char trace_id = 0x10;
const int memory_map_num = 3;
const struct libcsdec_memory_map memory_map[] = {
    {0xaaaadd370000, 0xaaaadd371000, "fib"},
    {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
    {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
};


// Reset the decoder state.
libcsdec_reset_edge(libcsdec, trace_id, memory_map_num, memory_map);

// Start decoding.
while (trace(trace_data_addr, trace_data_size)) {
    if (libcsdec_run_edge(libcsdec, trace_data_addr, trace_data_size)
        != LIBCEDEC_SUCCESS) {
        exit(EXIT_FAILURE);
    }
}

// Finish the decoding session.
if (libcsdec_finish_edge(libcsdec) != LIBCEDEC_SUCCESS) {
    exit(EXIT_FAILURE);
}
```

## Path Coverage

In this mode, it generates a PTrix-style path coverage bitmap by using the trace data only. It does not require the executable disassembly process and is expected to be better performance.

```cpp
const int bitmap_size = 0x1000;
unsigned char* bitmap = (unsigned char*)malloc(bitmap_size);

// Initialize the deocder.
libcsdec_t libcsdec = libcsdec_init_path(
    bitmap, bitmap_size);

const char trace_id = 0x10;
const int memory_map_num = 3;
const struct libcsdec_memory_map memory_map[] = {
    {0xaaaadd370000, 0xaaaadd371000, "fib"},
    {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
    {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
};


// Reset the decoder state.
libcsdec_reset_path(libcsdec, trace_id, memory_map_num, memory_map);

// Start decoding.
while (trace(trace_data_addr, trace_data_size)) {
    if (libcsdec_run_path(libcsdec, trace_data_addr, trace_data_size)
        != LIBCEDEC_SUCCESS) {
        exit(EXIT_FAILURE);
    }
}

// Finish the decoding session.
if (libcsdec_finish_path(libcsdec) != LIBCEDEC_SUCCESS) {
    exit(EXIT_FAILURE);
}
```