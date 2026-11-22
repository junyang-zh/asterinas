// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

FN_TEST(thread_virtual_timer_expires_on_user_ticks)
{
	// Linux CPU clock encoding: the complemented TID, thread scope (4),
	// and the virtual clock (1), which advances in userspace.
	clockid_t clock = (clockid_t)((~(uint32_t)syscall(SYS_gettid) << 3) | 5);
	struct sigevent event = { .sigev_notify = SIGEV_SIGNAL,
				  .sigev_signo = SIGUSR1 };
	struct itimerspec timer_spec = { .it_value.tv_nsec = 24000000 };
	struct timespec start, now, timeout = { .tv_sec = 1 };
	sigset_t mask, previous;
	timer_t timer;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	CHECK(sigprocmask(SIG_BLOCK, &mask, &previous));
	CHECK(timer_create(clock, &event, &timer));
	CHECK(clock_gettime(clock, &start));
	CHECK(timer_settime(timer, 0, &timer_spec, NULL));
	alarm(10);
	do {
		for (unsigned int i = 0; i < 65536; i++)
			atomic_signal_fence(memory_order_seq_cst);
		CHECK(clock_gettime(clock, &now));
	} while ((now.tv_sec - start.tv_sec) * 1000000000LL +
			 now.tv_nsec - start.tv_nsec < 80000000);
	TEST_RES(sigtimedwait(&mask, NULL, &timeout), _ret == SIGUSR1);
	alarm(0);
	CHECK(timer_delete(timer));
	CHECK(sigprocmask(SIG_SETMASK, &previous, NULL));
}
END_TEST()
