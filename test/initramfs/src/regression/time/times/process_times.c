// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <stdatomic.h>
#include <sys/auxv.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

static clock_t clock_ticks(struct timeval value, long hz)
{
	return value.tv_sec * hz + value.tv_usec * hz / 1000000;
}

FN_TEST(process_clock_ticks)
{
	struct rusage before, after;
	struct tms t;
	long hz = sysconf(_SC_CLK_TCK);

	TEST_RES(getauxval(AT_CLKTCK), _ret == (unsigned long)hz && hz == 100);
	TEST_SUCC(syscall(SYS_times, NULL));
	CHECK(getrusage(RUSAGE_SELF, &before));
	TEST_SUCC(times(&t));
	CHECK(getrusage(RUSAGE_SELF, &after));
	TEST_RES(t.tms_utime, _ret >= clock_ticks(before.ru_utime, hz) &&
				 _ret <= clock_ticks(after.ru_utime, hz));
	TEST_RES(t.tms_stime, _ret >= clock_ticks(before.ru_stime, hz) &&
				 _ret <= clock_ticks(after.ru_stime, hz));
}
END_TEST()

FN_TEST(waited_child_clock_ticks)
{
	struct tms before, after;
	CHECK(times(&before));
	pid_t pid = CHECK(fork());
	if (!pid) {
		struct timespec start, now;
		CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start));
		do {
			for (int i = 0; i < 32768; i++)
				atomic_signal_fence(memory_order_seq_cst);
			CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now));
		} while ((now.tv_sec - start.tv_sec) * 1000000000LL +
				 now.tv_nsec - start.tv_nsec < 100000000);
		_exit(0);
	}
	int status;
	CHECK(waitpid(pid, &status, 0));
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);
	CHECK(times(&after));
	// Two truncated clocks can lose up to two ticks in the sum.
	TEST_RES(after.tms_cutime + after.tms_cstime - before.tms_cutime -
			 before.tms_cstime, _ret >= 8);
}
END_TEST()
