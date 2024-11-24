#!/bin/bash

# args: microbench.sh [linux/asterinas]

set -ex

export QMP_PORT=3336

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PIN_CPU_SCRIPT="$SCRIPT_DIR/pin_cpu.py"
TEST_RESULTS_DIR="$SCRIPT_DIR/../test_results"
TMUX_SESSION_NAME="microbench_session"
mkdir -p "$TEST_RESULTS_DIR"

BENCH_TARGET=$1
if [ "$BENCH_TARGET" == "linux" ]; then
    START_VM_CMD="$SCRIPT_DIR/start_linux.sh"
    BENCH_OUTPUT_FILE="$TEST_RESULTS_DIR/linux_output.txt"
else
    START_VM_CMD="make run SMP=128 MEM=256G RELEASE_LTO=1"
    BENCH_OUTPUT_FILE="$TEST_RESULTS_DIR/aster_output.txt"
fi

pushd "$SCRIPT_DIR/.."

tmux new-session -d -s ${TMUX_SESSION_NAME}

ASTER_SESSION_KEYS=$START_VM_CMD
ASTER_SESSION_KEYS+=" 2>&1 | tee ${BENCH_OUTPUT_FILE}"
# Exit session when the command finishes
ASTER_SESSION_KEYS+="; exit"
tmux send-keys -t ${TMUX_SESSION_NAME}:0 "$ASTER_SESSION_KEYS" Enter

# Wait for "~ #" shell prompt to appear in $BENCH_OUTPUT_FILE
while ! tail -n 1 $BENCH_OUTPUT_FILE | grep -q "~ #"; do
    sleep 5
done

# Bind cores
python3 $PIN_CPU_SCRIPT $QMP_PORT 128

# Run the microbenchmark

tmux select-window -t ${TMUX_SESSION_NAME}:0

tmux send-keys -t ${TMUX_SESSION_NAME}:0 './test/microbench-vm-scale.sh' Enter

unset QMP_PORT

popd

tmux attach -t ${TMUX_SESSION_NAME}:0
