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
    DIR=$trace_out_dir TRACEE=$TRACEE TRACEE_ARGS=$bit_seq make -C $PROC_TRACE_DIR trace

    if [ $? -ne 0 ]; then
        echo "Failed to run tracer"
        exit 1
    fi
}

run_decoder () {
    trace_out_dir="$1"
    edge_coverage_file=$trace_out_dir/$EDGE_COVERAGE_FILENAME
    bitmap_file=$trace_out_dir/$BITMAP_FILENAME

    decoder_args=($(cat $trace_out_dir"/decoderargs.txt"))

    lower_address=${decoder_args[4]}
    upper_address=${decoder_args[5]}

    $DECODER $(cat $trace_out_dir/decoderargs.txt) --address-range=$lower_address,$upper_address \
                                                   --bitmap-mode \
                                                   --bitmap-size=0x1000 \
                                                   --bitmap-filename=$bitmap_file \
                                                   > $edge_coverage_file

    if [ $? -ne 0 ]; then
        echo "Failed to run decoder due to corrupted trace data or bugs in the decoder implementation."
        exit 1
    fi
}


for i in $(seq 0 255)
do
    D2B=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
    bit_seq=${D2B[i]}

    echo "RUN: "$bit_seq

    trace_out_dir=$TRACE_OUT_ROOT_DIR"/bit_seq_"$bit_seq

    run_tracer $bit_seq $trace_out_dir
    run_decoder $trace_out_dir
done
