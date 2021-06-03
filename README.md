# coresight-decoder
Experimental CoreSight Decoder

## Usage
```
make
./processor cstrace.bin target.elf 0xaaaaacfe0000
```

## Example
```
./processor ./tests/fib/trace/cstrace.bin 0x10 3 \
    ./tests/fib/fib 0xaaaac6640000 0xaaaac6641000 \
    ./tests/fib/libc-2.31.so 0xffffaed96000 0xffffaef09000 \
    ./tests/fib/ld-2.31.so 0xffffaef09000 0xffffaef2a000
```
