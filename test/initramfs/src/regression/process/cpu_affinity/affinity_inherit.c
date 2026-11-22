/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

static int placed_on(int expected)
{
	cpu_set_t mask;
	unsigned int current;

	return sched_getaffinity(0, sizeof(mask), &mask) == 0 &&
	       CPU_COUNT(&mask) == 1 && CPU_ISSET(expected, &mask) &&
	       syscall(SYS_getcpu, &current, NULL, NULL) == 0 &&
	       current == (unsigned int)expected && sched_getcpu() == expected;
}

static void *check_new_thread(void *cpu)
{
	return placed_on(*(int *)cpu) ? NULL : cpu;
}

FN_TEST(affinity_placement_and_inheritance)
{
	cpu_set_t allowed, single;
	int current = CHECK(sched_getcpu());
	int target = current;
	CHECK(sched_getaffinity(0, sizeof(allowed), &allowed));
	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (cpu != current && CPU_ISSET(cpu, &allowed)) {
			target = cpu;
			break;
		}
	}

	CPU_ZERO(&single);
	CPU_SET(target, &single);
	CHECK(sched_setaffinity(0, sizeof(single), &single));
	TEST_RES(placed_on(target), _ret);

	pid_t pid = CHECK(fork());
	if (pid == 0)
		_exit(placed_on(target) ? 0 : 1);
	int status;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret);

	pthread_t thread;
	void *result;
	CHECK_WITH(pthread_create(&thread, NULL, check_new_thread, &target), _ret == 0);
	CHECK_WITH(pthread_join(thread, &result), _ret == 0);
	TEST_RES(result == NULL, _ret);
	CHECK(sched_setaffinity(0, sizeof(allowed), &allowed));
}
END_TEST()
