// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096UL
#define PART (2UL * 1024 * 1024)
#define SIZE (3 * PART)

int main(void)
{
	int fd = memfd_create("rmap-replace", 0);
	assert(fd >= 0);
	assert(ftruncate(fd, SIZE) == 0);
	unsigned char *a = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
			       MAP_SHARED, fd, 0);
	unsigned char *alias = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
				   MAP_SHARED, fd, 0);
	assert(a != MAP_FAILED && alias != MAP_FAILED);
	for (unsigned round = 0; round < 3; ++round) {
		for (size_t off = 0; off < SIZE; off += PAGE) {
			a[off] = 0x79;
			assert(alias[off] == 0x79);
		}
		// Replacement removes old reverse-map registrations even though
		// the new anonymous mapping contributes none of its own.
		assert(mmap(a + PART, PART, PROT_READ | PROT_WRITE,
			    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
		       == a + PART);
		for (size_t off = PART; off < 2 * PART; off += PAGE) {
			assert(a[off] == 0);
			a[off] = 0x5a;
		}
		assert(ftruncate(fd, 0) == 0);
		assert(ftruncate(fd, SIZE) == 0);
		for (size_t off = 0; off < SIZE; off += PAGE) {
			assert(alias[off] == 0);
			assert(a[off] == (off >= PART && off < 2 * PART ? 0x5a : 0));
		}
		// The old anonymous range has no reverse-map entries. A new shared
		// mapping must still register before later file invalidation.
		assert(mmap(a + PART, PART, PROT_READ | PROT_WRITE,
			    MAP_FIXED | MAP_SHARED, fd, PART) == a + PART);
		for (size_t off = PART; off < 2 * PART; off += PAGE) {
			assert(a[off] == 0);
			a[off] = 0x36;
			assert(alias[off] == 0x36);
		}
		assert(ftruncate(fd, 0) == 0);
		assert(ftruncate(fd, SIZE) == 0);
		for (size_t off = 0; off < SIZE; off += PAGE)
			assert(a[off] == 0 && alias[off] == 0);
	}
	assert(munmap(a, SIZE) == 0);
	assert(munmap(alias, SIZE) == 0);
	assert(close(fd) == 0);
	puts("RMAP_REPLACE_PASS");
	return 0;
}
