/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

struct wait_args {
	int *word;
	int flags;
	int result;
	struct timespec deadline;
};

static void *wait_on_bit_two(void *arg)
{
	struct wait_args *wait = arg;
	long ret = syscall(SYS_futex, wait->word,
			   FUTEX_WAIT_BITSET | wait->flags, 0, &wait->deadline,
			   NULL, 2);
	wait->result = ret == 0 ? 0 : errno;
	return NULL;
}

static pthread_t start_and_move(struct wait_args *wait, bool expire)
{
	int *words = wait->word;
	pthread_t thread;
	int op = FUTEX_REQUEUE | wait->flags;
	long moved = 0;

	CHECK(clock_gettime(CLOCK_MONOTONIC, &wait->deadline));
	wait->deadline.tv_sec += expire ? 2 : 8;
	CHECK_WITH(pthread_create(&thread, NULL, wait_on_bit_two, wait),
		   _ret == 0);
	/* Requeue itself establishes that the waiter has entered the kernel. */
	for (int i = 0; i < 1500 && !moved; i++) {
		moved = CHECK_WITH(syscall(SYS_futex, &words[0], op, 0, 1,
					   &words[1], 0),
				   _ret == 0 || _ret == 1);
		if (!moved)
			usleep(1000);
	}
	CHECK_WITH(moved, _ret == 1);
	return thread;
}

FN_TEST(bitset_and_timeout_follow_requeue)
{
	size_t length = getpagesize();
	int *words = mmap(NULL, length, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK_WITH(words, _ret != MAP_FAILED);
	for (int i = 0; i < 2; i++) {
		int flags = i == 0 ? 0 : FUTEX_PRIVATE_FLAG;
		TEST_ERRNO(syscall(SYS_futex, &words[0], FUTEX_REQUEUE | flags,
				   -1, 0, &words[1], 0),
			   EINVAL);
		TEST_ERRNO(syscall(SYS_futex, &words[0], FUTEX_REQUEUE | flags,
				   0, -1, &words[1], 0),
			   EINVAL);
		for (int expire = 0; expire < 2; expire++) {
			struct wait_args wait = { .word = words,
						  .flags = flags };
			pthread_t thread = start_and_move(&wait, expire);

			TEST_RES(syscall(SYS_futex, &words[1],
					 FUTEX_REQUEUE | flags, 0, 0, &words[2],
					 0),
				 _ret == 0);
			TEST_RES(syscall(SYS_futex, &words[1],
					 FUTEX_REQUEUE | flags, 0, 1, &words[2],
					 0),
				 _ret == 1);
			TEST_RES(syscall(SYS_futex, &words[2],
					 FUTEX_WAKE_BITSET | flags, 1, NULL,
					 NULL, 1),
				 _ret == 0);
			if (!expire)
				TEST_RES(syscall(SYS_futex, &words[2],
						 FUTEX_WAKE_BITSET | flags, 1,
						 NULL, NULL, 2),
					 _ret == 1);
			CHECK_WITH(pthread_join(thread, NULL), _ret == 0);
			TEST_RES(wait.result, _ret == (expire ? ETIMEDOUT : 0));
			TEST_RES(syscall(SYS_futex, &words[2],
					 FUTEX_WAKE | flags, 1, NULL, NULL, 0),
				 _ret == 0);
		}
	}
	CHECK(munmap(words, length));
}
END_TEST()
