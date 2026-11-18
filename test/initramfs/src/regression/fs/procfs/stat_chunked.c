// SPDX-License-Identifier: MPL-2.0

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

// Growing decimal counters must not move CPU records between read offsets.
static int check_cpu_records(char *text)
{
	char *save, *line = strtok_r(text, "\n", &save);
	int cpu = -1;
	while (line && strncmp(line, "cpu", 3) == 0) {
		char *next = line + 3;
		if (cpu >= 0) {
			assert(isdigit(*next));
			assert(strtol(next, &next, 10) == cpu);
		}
		for (int field = 0; field < 10; ++field) {
			assert(*next == ' ');
			while (*next == ' ')
				++next;
			assert(isdigit(*next));
			strtoull(next, &next, 10);
		}
		assert(*next == '\0');
		++cpu;
		line = strtok_r(NULL, "\n", &save);
	}
	assert(line && strncmp(line, "intr ", 5) == 0);
	return cpu;
}

int main(void)
{
	long expected = sysconf(_SC_NPROCESSORS_CONF);
	assert(expected > 0);
	pid_t children[8];
	size_t workers = expected < 8 ? expected : 8;
	for (size_t i = 0; i < workers; ++i) {
		children[i] = fork();
		assert(children[i] >= 0);
		if (children[i] == 0) {
			volatile unsigned long counter = 0;
			for (;;)
				++counter;
		}
	}

	int passed = 1;
	// Run assertions in a child so the parent always reaps the load workers.
	pid_t reader = fork();
	assert(reader >= 0);
	if (reader == 0) {
		char text[1024 * 1024];
		for (int trial = 0; trial < 32; ++trial) {
			int fd = open("/proc/stat", O_RDONLY);
			assert(fd >= 0);
			size_t used = 0;
			for (;;) {
				assert(used + 20 < sizeof(text));
				ssize_t n = read(fd, text + used, 19);
				assert(n > 0);
				used += n;
				text[used] = '\0';
				char *intr = strstr(text, "\nintr ");
				if (intr) {
					intr[6] = '\0';
					break;
				}
				usleep(3000);
			}
			assert(close(fd) == 0);
			assert(check_cpu_records(text) == expected);
		}
		_exit(0);
	}
	int status;
	assert(waitpid(reader, &status, 0) == reader);
	passed = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	for (size_t i = 0; i < workers; ++i) {
		assert(kill(children[i], SIGTERM) == 0);
		assert(waitpid(children[i], &status, 0) == children[i]);
	}
	assert(passed);
	puts("Chunked /proc/stat CPU records passed under concurrent load");
	return 0;
}
