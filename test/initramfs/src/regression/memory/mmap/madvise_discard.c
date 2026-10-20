// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#define PAGE 4096UL
#define SPAN (12UL * 1024 * 1024)
#define ROUNDS 512

static volatile unsigned char *remote_page;
static atomic_uint phase;
static cpu_set_t allowed;

static void pin_cpu(unsigned index)
{
	unsigned seen = 0;
	for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
		if (!CPU_ISSET(cpu, &allowed))
			continue;
		if (seen++ != index)
			continue;
		cpu_set_t one;
		CPU_ZERO(&one);
		CPU_SET(cpu, &one);
		assert(sched_setaffinity(0, sizeof(one), &one) == 0);
		return;
	}
}

static void wait_phase(unsigned expected)
{
	while (atomic_load_explicit(&phase, memory_order_acquire) != expected)
		__asm__ volatile("" ::: "memory");
}

static void *reader(void *unused)
{
	(void)unused;
	pin_cpu(1);
	for (unsigned i = 0; i < ROUNDS; ++i) {
		wait_phase(4 * i + 1);
		assert(*remote_page == 0xa7);
		atomic_store_explicit(&phase, 4 * i + 2, memory_order_release);
		wait_phase(4 * i + 3);
		assert(*remote_page == 0);
		atomic_store_explicit(&phase, 4 * i + 4, memory_order_release);
	}
	return NULL;
}

int main(void)
{
	unsigned char *p = mmap(NULL, SPAN, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(p != MAP_FAILED);
	// Multiple page-table nodes, partial end points, and repeated RSS updates.
	for (unsigned round = 0; round < 3; ++round) {
		// mprotect must put each auxiliary fragment back into its owning
		// node after walking PTEs across a page-table boundary.
		assert(mprotect(p, SPAN, PROT_READ) == 0);
		assert(mprotect(p, SPAN, PROT_READ | PROT_WRITE) == 0);
		for (size_t off = 0; off < SPAN; off += PAGE)
			p[off] = 0x5c;
		assert(madvise(p + PAGE, SPAN - 2 * PAGE, MADV_DONTNEED) == 0);
		assert(p[0] == 0x5c && p[SPAN - PAGE] == 0x5c);
		for (size_t off = PAGE; off < SPAN - PAGE; off += PAGE)
			assert(p[off] == 0);
	}
	// ENOMEM must still discard both mapped portions around a hole.
	assert(munmap(p + SPAN / 2, PAGE) == 0);
	p[PAGE] = p[SPAN - PAGE] = 0x39;
	errno = 0;
	assert(madvise(p, SPAN, MADV_DONTNEED) == -1 && errno == ENOMEM);
	assert(p[PAGE] == 0 && p[SPAN - PAGE] == 0);
	assert(munmap(p, SPAN) == 0);

	// A mostly absent mapping forces auxiliary metadata propagation during discard.
	const size_t sparse_size = 1UL << 30;
	p = mmap(NULL, sparse_size, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(p != MAP_FAILED);
	p[PAGE] = p[sparse_size - 2 * PAGE] = 0x71;
	assert(madvise(p + PAGE, sparse_size - 2 * PAGE, MADV_DONTNEED) == 0);
	assert(p[PAGE] == 0 && p[sparse_size - 2 * PAGE] == 0);
	assert(munmap(p, sparse_size) == 0);

	assert(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
	if (CPU_COUNT(&allowed) > 1) {
		remote_page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		assert(remote_page != MAP_FAILED);
		pthread_t thread;
		assert(pthread_create(&thread, NULL, reader, NULL) == 0);
		pin_cpu(0);
		for (unsigned i = 0; i < ROUNDS; ++i) {
			wait_phase(4 * i);
			*remote_page = 0xa7;
			atomic_store_explicit(&phase, 4 * i + 1, memory_order_release);
			wait_phase(4 * i + 2);
			assert(madvise((void *)remote_page, PAGE, MADV_DONTNEED) == 0);
			atomic_store_explicit(&phase, 4 * i + 3, memory_order_release);
		}
		assert(pthread_join(thread, NULL) == 0);
		assert(munmap((void *)remote_page, PAGE) == 0);
	}
	puts("MADVISE_DISCARD_PASS");
	return 0;
}
