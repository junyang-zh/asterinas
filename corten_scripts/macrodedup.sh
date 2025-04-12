#!/bin/bash

# usage: macrodedup.sh [linux|asterinas] [tc|pt] [aster_breakdown]

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
BENCH_SCRIPT="$SCRIPT_DIR/bench.sh"
CORTEN_OUTPUT_DIR="$SCRIPT_DIR/../corten_outputs"
mkdir -p "$CORTEN_OUTPUT_DIR"

SYS_NAME=$1
MALLOC=$2

if [ "$SYS_NAME" != "linux" ] && [ "$SYS_NAME" != "aster" ] && [ "$MALLOC" != "tc" ] && [ "$MALLOC" != "pt" ]; then
    echo "Usage: $0 <linux|aster> <tc|pt> [aster_breakdown]"
    exit 1
fi

DO_ASTER_BREAKDOWN=$3
if [ "$SYS_NAME" == "linux" ]; then
    DO_ASTER_BREAKDOWN=""
fi

if [ "$SYS_NAME" == "linux" ]; then
    EXTRA_MNT_CMDS="mount -t devtmpfs devtmpfs /dev; mount -t ext2 /dev/vdb /benchmark/bin/vm_scale_bench_data"
else
    EXTRA_MNT_CMDS="echo 0"
fi

BENCH_OUTPUT_FILE="$CORTEN_OUTPUT_DIR/macrodedup_${SYS_NAME}_$(date +%Y%m%d_%H%M%S).log"

THREAD_COUNTS=(1 2 4 8 16 32 64 128 192 256 320 384)
for THREAD_COUNT in "${THREAD_COUNTS[@]}"; do
    if [ $THREAD_COUNT -ge 320 ]; then
        export NR_CPUS=384
    else
        export NR_CPUS=$THREAD_COUNT
    fi
    export CORTEN_RUN_ARGS="FEATURES=mprotect_async_tlb"
    $BENCH_SCRIPT $SYS_NAME $BENCH_OUTPUT_FILE "$EXTRA_MNT_CMDS; /test/corten_benchdedup.sh $MALLOC $THREAD_COUNT $DO_ASTER_BREAKDOWN"
done
