// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void reject_size(size_t size)
{
	unsigned char mask[sizeof(cpu_set_t)];
	memset(mask, 0xa5, sizeof(mask));
	errno = 0;
	long result = syscall(SYS_sched_getaffinity, 0, size, mask);
	assert(result == -1 && errno == EINVAL);
	for (size_t i = 0; i < sizeof(mask); ++i)
		assert(mask[i] == 0xa5);
}

int main(void)
{
	cpu_set_t full;
	assert(sched_getaffinity(0, sizeof(full), &full) == 0);
	int highest = -1;
	for (int i = 0; i < CPU_SETSIZE; ++i)
		if (CPU_ISSET(i, &full))
			highest = i;
	assert(highest >= 0);

	// A successful short copy must never hide CPUs from a growing-buffer caller.
	for (size_t size = 0; size * 8 <= (size_t)highest; size += sizeof(long))
		reject_size(size);
	reject_size(1);
	reject_size(sizeof(long) - 1);
	reject_size(sizeof(long) + 1);

	unsigned char mask[sizeof(full) + sizeof(long)];
	memset(mask, 0xa5, sizeof(mask));
	long copied = syscall(SYS_sched_getaffinity, 0, sizeof(full), mask);
	assert(copied > 0 && copied <= sizeof(full));
	assert(copied % sizeof(long) == 0);
	assert(memcmp(mask, &full, copied) == 0);
	for (size_t i = copied; i < sizeof(mask); ++i)
		assert(mask[i] == 0xa5);
	printf("sched_getaffinity size checks passed: highest=%d copied=%ld\n",
	       highest, copied);
	return 0;
}
