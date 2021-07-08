#!/bin/bash


# Program for calculating edge coverage
PROGRAM=../../processor
# Suffix of the file that outputs edge coverage
OUTPUT_FILE_SUFFIX="_edge_coverage.out"
# Suffix of the file that outputs bitmap of edge coverage
OUTPUT_BITMAP_FILE_SUFFIX="_bitmap.out"


# Calculate edge coverage and output to a file
run () {
    target="$1" # Trace data for calculating edge coverage
    output_file=$target$OUTPUT_FILE_SUFFIX
    bitmap_file=$target$OUTPUT_BITMAP_FILE_SUFFIX

    $PROGRAM $(cat $target/decoderargs.txt) --bitmap-size=0x1000 \
                                            --bitmap-filename=$bitmap_file \
                                            --trace-binary-filename=fib \
                                            > $output_file
}


run_full () {
    target="$1" # Trace data for calculating edge coverage
    output_file=$target$OUTPUT_FILE_SUFFIX
    bitmap_file=$target$OUTPUT_BITMAP_FILE_SUFFIX

    $PROGRAM $(cat $target/decoderargs.txt) --bitmap-size=0x1000 \
                                            --bitmap-filename=$bitmap_file \
                                            --trace-binary-filename=fib \
                                            --trace-binary-filename=ld-2.31.so \
                                            --trace-binary-filename=libc-2.31.so \
                                            > $output_file
}


# Compare edge coverage for two trace data
assert_edge_coverage() {
    target1="$1"
    target2="$2"
    output_file1=$target1$OUTPUT_FILE_SUFFIX
    output_file2=$target2$OUTPUT_FILE_SUFFIX

    diff $output_file1 $output_file2
    result="$?"
    if [ $result -ne 0 ]; then
        echo "Found differences: $target1, $target2"
        exit 1
    fi
}


# Compare bitmap
assert_bitmap() {
    target1="$1"
    target2="$2"
    output_file1=$target1$OUTPUT_BITMAP_FILE_SUFFIX
    output_file2=$target2$OUTPUT_BITMAP_FILE_SUFFIX

    echo "Compare bitmap $output_file1 and $output_file2"
    cmp $output_file1 $output_file2
    result="$?"
    if [ $result -ne 0 ]; then
        echo "Found differences: $target1, $target2"
        exit 1
    fi
}


assert() {
    # Compare edge coverage for each trace data
    assert_edge_coverage trace1 trace2
    assert_edge_coverage trace1 trace3
    assert_edge_coverage trace1 trace4
    assert_edge_coverage trace2 trace3
    assert_edge_coverage trace2 trace4
    assert_edge_coverage trace3 trace4


    # Compare each bitmap
    assert_bitmap trace1 trace2
    assert_bitmap trace1 trace3
    assert_bitmap trace1 trace4
    assert_bitmap trace2 trace3
    assert_bitmap trace2 trace4
    assert_bitmap trace3 trace4
}


# Calculate edge coverage for all trace data
run trace1
run trace2
run trace3
run trace4

assert

# Edge coverage matches for multiple trace data for the fib program
echo "PASSED fib test"


# Calculate edge coverage for all trace data with full trace
run_full trace1
run_full trace2
run_full trace3
run_full trace4

assert

# Edge coverage matches for multiple trace data for the fib program
echo "PASSED fib test with full trace"
