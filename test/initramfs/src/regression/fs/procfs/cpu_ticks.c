// SPDX-License-Identifier: MPL-2.0

#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

static void read_task_ticks(const char *path, clock_t *user, clock_t *system)
{
	FILE *file = CHECK_WITH(fopen(path, "r"), _ret != NULL);
	char buf[4096], *save;
	CHECK_WITH(fgets(buf, sizeof(buf), file), _ret != NULL);
	CHECK(fclose(file));

	// The command in field 2 may contain spaces and parentheses.
	char *end = CHECK_WITH(strrchr(buf, ')'), _ret != NULL);
	char *word = strtok_r(end + 1, " ", &save);
	for (int field = 3; field <= 15; ++field) {
		CHECK_WITH(word, _ret != NULL);
		if (field == 14 || field == 15) {
			char *tail;
			long value = strtol(word, &tail, 10);
			CHECK_WITH(value, _ret >= 0 && *tail == '\0');
			if (field == 14)
				*user = value;
			else
				*system = value;
		}
		word = strtok_r(NULL, " ", &save);
	}
}

FN_TEST(process_and_thread_stat_ticks)
{
	struct tms before, after;
	char thread_path[96];
	clock_t start = CHECK(clock());
	// Accumulate enough CPU time to distinguish clock units on a fresh boot.
	while (CHECK(clock()) - start < CLOCKS_PER_SEC / 8) {
		for (int i = 0; i < 1000; ++i)
			syscall(SYS_getpid);
	}
	snprintf(thread_path, sizeof(thread_path), "/proc/self/task/%ld/stat",
		 syscall(SYS_gettid));
	const char *paths[] = { "/proc/self/stat", thread_path };
	for (int i = 0; i < 2; ++i) {
		clock_t user = 0, system = 0;
		CHECK(times(&before));
		read_task_ticks(paths[i], &user, &system);
		CHECK(times(&after));
		TEST_RES(user, _ret >= before.tms_utime - 1 &&
			       _ret <= after.tms_utime + 1);
		TEST_RES(system, _ret >= before.tms_stime - 1 &&
				 _ret <= after.tms_stime + 1);
	}
}
END_TEST()

static double idle_seconds(void)
{
	FILE *file = CHECK_WITH(fopen("/proc/uptime", "r"), _ret != NULL);
	double uptime, idle;
	CHECK_WITH(fscanf(file, "%lf %lf", &uptime, &idle), _ret == 2);
	CHECK(fclose(file));
	return idle;
}

FN_TEST(system_stat_idle_ticks)
{
	long hz = CHECK(sysconf(_SC_CLK_TCK));
	double before = idle_seconds();
	FILE *file = CHECK_WITH(fopen("/proc/stat", "r"), _ret != NULL);
	unsigned long long user, nice, system, idle;
	CHECK_WITH(fscanf(file, "cpu %llu %llu %llu %llu", &user, &nice, &system,
			  &idle), _ret == 4);
	CHECK(fclose(file));
	double after = idle_seconds();

	// /proc/uptime truncates its idle duration to centiseconds.
	TEST_RES((double)idle, _ret >= before * hz - 1 &&
				_ret <= (after + 0.01) * hz + 1);
}
END_TEST()
