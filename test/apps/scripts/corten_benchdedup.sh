#!/bin/sh

# usage: corten_benchdedup.sh thread_count

THREAD_COUNT=$1

if [ -z "$THREAD_COUNT" ]; then
    echo "Usage: $0 <thread_count>"
    exit 1
fi

# Copy the text file to ramfs
cp /benchmark/bin/vm_scale_bench_data/800MB.txt /root

echo "***TEST_START***"

/benchmark/bin/dedup/dedup -c -p -v -t $THREAD_COUNT -i /root/800MB.txt -o /test/output.dat.ddp

echo "***TEST_END***"
