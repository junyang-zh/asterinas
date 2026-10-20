// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096UL
#define SIZE (8UL * 1024 * 1024)

int main(void)
{
	int fd = memfd_create("truncate-refault", 0);
	assert(fd >= 0);
	assert(ftruncate(fd, SIZE) == 0);
	unsigned char *a = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
			       MAP_SHARED, fd, 0);
	unsigned char *b = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
			       MAP_SHARED, fd, 0);
	assert(a != MAP_FAILED && b != MAP_FAILED);
	for (unsigned round = 0; round < 3; ++round) {
		for (size_t off = 0; off < SIZE; off += PAGE) {
			a[off] = 0x79;
			assert(b[off] == 0x79);
		}
		// Reverse-map invalidation must remove resident PTEs while keeping
		// the complete mapping metadata, even across detached-PT boundaries.
		assert(ftruncate(fd, 0) == 0);
		assert(ftruncate(fd, SIZE) == 0);
		for (size_t off = 0; off < SIZE; off += PAGE)
			assert(a[off] == 0 && b[off] == 0);
	}
	assert(munmap(a, SIZE) == 0);
	assert(munmap(b, SIZE) == 0);
	assert(close(fd) == 0);
	puts("TRUNCATE_REFAULT_PASS");
	return 0;
}
