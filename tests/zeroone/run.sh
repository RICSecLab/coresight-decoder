#!/bin/bash


TRACE_OUT_ROOT_DIR=$(realpath trace)
TRACEE=$(realpath zeroone)
PROC_TRACE_DIR="$1"


DECODER=../../processor
EDGE_COVERAGE_FILENAME="edge_coverage.out"
BITMAP_FILENAME="bitmap.out"


run_tracer () {
    bit_seq="$1"
    trace_out_dir="$2"

    DIR=$trace_out_dir TRACEE=$TRACEE TRACEE_ARGS=$bit_seq make -C $PROC_TRACE_DIR trace > /dev/null
    if [ $? -ne 0 ]; then
        echo "Failed to run tracer"
        exit 1
    fi
}

run_decoder () {
    trace_out_dir="$1"
    edge_coverage_file=$trace_out_dir/$EDGE_COVERAGE_FILENAME
    bitmap_file=$trace_out_dir/$BITMAP_FILENAME

    $DECODER $(cat $trace_out_dir/decoderargs.txt) --bitmap-size=0x10000 \
                                                   --bitmap-filename=$bitmap_file \
                                                   --trace-binary-filename=$TRACEE \
                                                   > $edge_coverage_file

    err=$?
    if [ $err -ne 0 ]; then
        echo "Failed to run decoder due to corrupted trace data or bugs in the decoder implementation."
    fi
    return $err
}

run() {
    bit_seq="$1"
    trace_out_dir="$2"

    while :
    do
        run_tracer $bit_seq $trace_out_dir
        run_decoder $trace_out_dir

        if [ $? -ne 0 ]; then
            echo "Maybe the tracer didn't work properly. So try again."
            rm -rf $trace_out_dir
        else
            echo "Successfully run tracer and decoder."
            break
        fi
    done
}


for i in $(seq 0 255)
do
    D2B=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
    bit_seq=${D2B[i]}

    echo "RUN: "$bit_seq

    trace_out_dir=$TRACE_OUT_ROOT_DIR"/bit_seq_"$bit_seq

    run $bit_seq $trace_out_dir
done
