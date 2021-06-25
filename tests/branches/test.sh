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
    lower_address="$2"
    upper_address="$3"
    bitmap_file=$target$OUTPUT_BITMAP_FILE_SUFFIX

    $PROGRAM $(cat $target/decoderargs.txt) --address-range=$lower_address,$upper_address \
                                            --bitmap-mode \
                                            --bitmap-size=0x1000 \
                                            --bitmap-filename=$bitmap_file \
                                            > $output_file
}


# Compare edge coverage for two trace data
assert() {
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


# Calculate edge coverage for all trace data
run trace1 0xaaaaceaa071c 0xaaaaceaa0940
run trace2 0xaaaae560071c 0xaaaae5600940
run trace3 0xaaaae28e071c 0xaaaae28e0940
run trace4 0xaaaabeaf071c 0xaaaabeaf0940


# Compare with expected edge coverage
assert trace1 expected
assert trace2 expected
assert trace3 expected
assert trace4 expected


# Compare each bitmap
assert_bitmap trace1 trace2
assert_bitmap trace1 trace3
assert_bitmap trace1 trace4
assert_bitmap trace2 trace3
assert_bitmap trace2 trace4
assert_bitmap trace3 trace4


# Passed all test cases
echo "PASSED branches test"
