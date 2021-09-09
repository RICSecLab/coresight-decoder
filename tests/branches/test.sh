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
                                            > $output_file
    if [ $? -ne 0 ]; then
        echo "Failed to run decoder."
        exit 1
    fi
}

# Compare edge coverage for two trace data
assert_edge_coverage() {
    target1="$1"
    target2="$2"
    output_file1=$target1$OUTPUT_FILE_SUFFIX
    output_file2=$target2$OUTPUT_FILE_SUFFIX

    # Extract only the required edge coverage starting from 0x900-> 0x71c
    diff \
        <(grep 0x900 $output_file1 -A41 | grep 0x71c -A41) \
        <(grep 0x900 $output_file2 -A41 | grep 0x71c -A41)

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
    # Compare with expected edge coverage
    assert_edge_coverage trace1 expected
    assert_edge_coverage trace2 expected
    assert_edge_coverage trace3 expected
    assert_edge_coverage trace4 expected

    # Compare each bitmap
    assert_bitmap trace1 trace2
    assert_bitmap trace1 trace3
    assert_bitmap trace1 trace4
    assert_bitmap trace2 trace3
    assert_bitmap trace2 trace4
    assert_bitmap trace3 trace4
}


mode="$1"

# Calculate edge coverage for all trace data
run trace1
run trace2
run trace3
run trace4

assert

# Passed all test cases
echo "PASSED branches test with "$mode
