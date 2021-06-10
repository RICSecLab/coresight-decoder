#!/bin/bash


# Program for calculating edge coverage
PROGRAM=../../processor
# Suffix of the file that outputs edge coverage
OUTPUT_FILE_SUFFIX="_edge_coverage.out"


# Calculate edge coverage and output to a file
run () {
    target="$1" # Trace data for calculating edge coverage
    output_file=$target$OUTPUT_FILE_SUFFIX
    $PROGRAM $(cat $target/decoderargs.txt) > $output_file
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
run trace1
run trace2
run trace3
run trace4


# Compare edge coverage for each trace data
assert trace1 trace2
assert trace1 trace3
assert trace1 trace4
assert trace2 trace3
assert trace2 trace4
assert trace3 trace4


# Edge coverage matches for multiple trace data for the fib program
echo "PASSED"
