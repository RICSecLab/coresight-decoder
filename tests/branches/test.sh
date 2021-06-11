#!/bin/bash


# Program for calculating edge coverage
PROGRAM=../../processor
# Suffix of the file that outputs edge coverage
OUTPUT_FILE_SUFFIX="_edge_coverage.out"


# Calculate edge coverage and output to a file
run () {
    target="$1" # Trace data for calculating edge coverage
    output_file=$target$OUTPUT_FILE_SUFFIX
    lower_address="$2"
    upper_address="$3"
    $PROGRAM $(cat $target/decoderargs.txt) --address-range=$lower_address,$upper_address > $output_file
}


# Compare edge coverage for two trace data
assert() {
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


# Passed all test cases
echo "PASSED branches test"
