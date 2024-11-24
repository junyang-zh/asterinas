#!/bin/sh

set -ex

/test/scale/mmap
/test/scale/mmap_pf
/test/scale/pf
/test/scale/munmap_virt
/test/scale/munmap

poweroff -f
