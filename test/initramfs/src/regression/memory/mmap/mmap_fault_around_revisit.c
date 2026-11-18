// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define NR_PAGES 16
#define REPEATS 64

int main(void)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	assert(page_size > 0);
	const size_t page = (size_t)page_size;
	const size_t span = NR_PAGES * page;

	char name[] = "/tmp/fault-around-XXXXXX";
	int fd = mkstemp(name);
	assert(fd >= 0);
	assert(unlink(name) == 0);
	assert(ftruncate(fd, (off_t)span) == 0);
	for (size_t i = 0; i < NR_PAGES; ++i) {
		unsigned char value = i + 1;
		assert(pwrite(fd, &value, 1, (off_t)(i * page)) == 1);
	}

	// Keep every file page inside one naturally aligned fault-around window.
	void *reservation = mmap(NULL, 2 * span, PROT_NONE,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(reservation != MAP_FAILED);
	const uintptr_t aligned = (uintptr_t)reservation +
				  (span - (uintptr_t)reservation % span) % span;
	void *mapping = mmap((void *)aligned, span, PROT_READ,
			     MAP_PRIVATE | MAP_FIXED, fd, 0);
	assert(mapping == (void *)aligned);
	assert(close(fd) == 0);

	const volatile unsigned char *bytes = mapping;
	for (size_t i = 0; i < NR_PAGES; ++i)
		assert(bytes[i * page] == i + 1);

	for (size_t round = 0; round < REPEATS; ++round) {
		const size_t target = 1 + round % (NR_PAGES - 2);
		// Refault the discarded target alongside already-present neighbors.
		assert(madvise((unsigned char *)mapping + target * page, page,
			       MADV_DONTNEED) == 0);
		assert(bytes[target * page] == target + 1);
		assert(bytes[(target - 1) * page] == target);
		assert(bytes[(target + 1) * page] == target + 2);
	}

	assert(munmap(reservation, 2 * span) == 0);
	puts("MM CHECK PASSED");
	return 0;
}
