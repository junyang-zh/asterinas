/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

FN_TEST(short_affinity_masks)
{
	cpu_set_t original, single, actual;
	unsigned int tested = 0;
	size_t page = sysconf(_SC_PAGESIZE);
	char *buf = CHECK_WITH(mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
			       _ret != MAP_FAILED);
	CHECK(mprotect(buf + page, page, PROT_NONE));
	CHECK(sched_getaffinity(0, sizeof(original), &original));

	/* Put each supplied mask at the end of a readable page. */
	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &original) || (cpu != 0 && cpu % 8))
			continue;
		size_t len = cpu / 8 + 1;
		CPU_ZERO(&single);
		CPU_SET(cpu, &single);
		memcpy(buf + page - len, &single, len);
		CHECK(syscall(SYS_sched_setaffinity, 0, len, buf + page - len));
		CPU_ZERO(&actual);
		CHECK(sched_getaffinity(0, sizeof(actual), &actual));
		CHECK_WITH(CPU_EQUAL(&actual, &single), _ret);
		tested++;
	}
	/* The empty mask and an unreadable buffer must leave affinity intact. */
	CPU_ZERO(&single);
	CHECK_WITH(syscall(SYS_sched_setaffinity, 0, sizeof(single), &single),
		   _ret == -1 && errno == EINVAL);
	CHECK_WITH(syscall(SYS_sched_setaffinity, 0, 1, buf + page),
		   _ret == -1 && errno == EFAULT);
	if (tested) {
		CPU_ZERO(&single);
		CHECK(sched_getaffinity(0, sizeof(single), &single));
		CHECK_WITH(CPU_EQUAL(&single, &actual), _ret);
	}
	CHECK(sched_setaffinity(0, sizeof(original), &original));
	TEST_SUCC(munmap(buf, 2 * page));
}
END_TEST()
