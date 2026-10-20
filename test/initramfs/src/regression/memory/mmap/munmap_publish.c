// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/mman.h>

#define PAGE 4096UL
#define ROUNDS 512

struct pair {
	atomic_uint phase;
	unsigned char *base;
	unsigned char *source;
	unsigned cpu;
};
static cpu_set_t allowed;

static void pin_cpu(unsigned index)
{
	unsigned seen = 0;
	for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
		if (!CPU_ISSET(cpu, &allowed) || seen++ != index)
			continue;
		cpu_set_t one;
		CPU_ZERO(&one);
		CPU_SET(cpu, &one);
		assert(sched_setaffinity(0, sizeof(one), &one) == 0);
		return;
	}
	assert(0 && "missing test CPU");
}

static void wait_phase(struct pair *p, unsigned phase)
{
	while (atomic_load_explicit(&p->phase, memory_order_acquire) != phase)
		__asm__ volatile("" ::: "memory");
}

static void *reader(void *arg)
{
	struct pair *p = arg;
	volatile unsigned char *page = p->base + PAGE;
	pin_cpu(p->cpu + 1);
	for (unsigned i = 0; i < ROUNDS; ++i) {
		wait_phase(p, 4 * i + 1);
		assert(*page == 0xb9);
		atomic_store_explicit(&p->phase, 4 * i + 2, memory_order_release);
		wait_phase(p, 4 * i + 3);
		// The replacement is untouched, so a stale remote TLB can bypass
		// its first fault unless metadata publication waited for retirement.
		assert(*page == 0);
		atomic_store_explicit(&p->phase, 4 * i + 4, memory_order_release);
	}
	return NULL;
}

static void *writer(void *arg)
{
	struct pair *p = arg;
	unsigned char *page = p->base + PAGE;
	pin_cpu(p->cpu);
	for (unsigned i = 0; i < ROUNDS; ++i) {
		wait_phase(p, 4 * i);
		// Prepare every new mapping before warming the remote translation.
		// Otherwise mmap's own barrier could hide a missing remap barrier.
		if (i & 1) {
			assert(mmap(p->source, PAGE, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				    -1, 0) == p->source);
		}
		*(volatile unsigned char *)page = 0xb9;
		atomic_store_explicit(&p->phase, 4 * i + 1, memory_order_release);
		wait_phase(p, 4 * i + 2);
		assert(munmap(page, PAGE) == 0);
		if (i & 1) {
			assert(mremap(p->source, PAGE, PAGE,
				      MREMAP_MAYMOVE | MREMAP_FIXED, page) == page);
		} else {
			assert(mremap(p->base, PAGE, 2 * PAGE, 0) == p->base);
		}
		atomic_store_explicit(&p->phase, 4 * i + 3, memory_order_release);
	}
	wait_phase(p, 4 * ROUNDS);
	return NULL;
}

int main(void)
{
	assert(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
	unsigned cpus = CPU_COUNT(&allowed);
	if (cpus < 2) {
		puts("MUNMAP_PUBLISH_SKIP_REQUIRES_SMP");
		return 0;
	}
	unsigned n = cpus >= 4 ? 2 : 1;
	struct pair pairs[2] = { 0 };
	pthread_t threads[4];
	for (unsigned i = 0; i < n; ++i) {
		unsigned char *reservation = mmap(NULL, 7 * PAGE, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		assert(reservation != MAP_FAILED);
		pairs[i].base = reservation + PAGE;
		pairs[i].source = reservation + 5 * PAGE;
		pairs[i].cpu = 2 * i;
		assert(mmap(pairs[i].base, 2 * PAGE, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
		       == pairs[i].base);
	}
	for (unsigned i = 0; i < n; ++i) {
		assert(pthread_create(&threads[2 * i], NULL, writer, &pairs[i]) == 0);
		assert(pthread_create(&threads[2 * i + 1], NULL, reader, &pairs[i]) == 0);
	}
	for (unsigned i = 0; i < 2 * n; ++i)
		assert(pthread_join(threads[i], NULL) == 0);
	for (unsigned i = 0; i < n; ++i)
		assert(munmap(pairs[i].base - PAGE, 7 * PAGE) == 0);
	puts("MUNMAP_PUBLISH_PASS");
	return 0;
}
