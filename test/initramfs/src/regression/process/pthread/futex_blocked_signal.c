// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <linux/futex.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

static pthread_t waiter;
static atomic_bool finished;

static void *send_blocked_signals(void *arg)
{
	bool thread_directed = *(bool *)arg;

	do {
		if (thread_directed)
			CHECK_WITH(pthread_kill(waiter, SIGUSR1), _ret == 0);
		else
			CHECK(kill(getpid(), SIGUSR1));
		usleep(1000);
	} while (!atomic_load(&finished));
	return NULL;
}

FN_TEST(blocked_signals_leave_futex_wait_asleep)
{
	struct timespec timeout = { .tv_nsec = 150000000 }, zero = { 0 };
	sigset_t mask, previous;
	int word = 0;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	CHECK_WITH(pthread_sigmask(SIG_BLOCK, &mask, &previous), _ret == 0);
	waiter = pthread_self();
	for (int i = 0; i < 4; i++) {
		bool thread_directed = i & 1;
		int op = FUTEX_WAIT | ((i & 2) ? FUTEX_PRIVATE_FLAG : 0);
		pthread_t sender;

		atomic_store(&finished, false);
		CHECK_WITH(pthread_create(&sender, NULL, send_blocked_signals,
					  &thread_directed), _ret == 0);
		TEST_ERRNO(syscall(SYS_futex, &word, op, 0, &timeout, NULL, 0),
			   ETIMEDOUT);
		atomic_store(&finished, true);
		CHECK_WITH(pthread_join(sender, NULL), _ret == 0);
		TEST_RES(sigtimedwait(&mask, NULL, &zero), _ret == SIGUSR1);
	}
	CHECK_WITH(pthread_sigmask(SIG_SETMASK, &previous, NULL), _ret == 0);
}
END_TEST()
