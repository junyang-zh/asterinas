// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/mman.h>

#define PAGE 4096UL
#define ROUNDS 256

struct pair {
	atomic_uint phase;
	volatile unsigned char *page;
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
}
static void wait_phase(struct pair *p, unsigned n)
{
	while (atomic_load_explicit(&p->phase, memory_order_acquire) != n)
		__asm__ volatile("" ::: "memory");
}
static void *reader(void *arg)
{
	struct pair *p = arg;
	pin_cpu(p->cpu + 1);
	for (unsigned i = 0; i < ROUNDS; ++i) {
		wait_phase(p, 4 * i + 1);
		assert(*p->page == 0xa7);
		atomic_store_explicit(&p->phase, 4 * i + 2, memory_order_release);
		wait_phase(p, 4 * i + 3);
		// Writer has returned the replacement mapping but has never touched
		// its contents. A stale TLB bypassing the first fault must not win.
		assert(*p->page == 0);
		atomic_store_explicit(&p->phase, 4 * i + 4, memory_order_release);
	}
	return NULL;
}
static void *writer(void *arg)
{
	struct pair *p = arg;
	pin_cpu(p->cpu);
	for (unsigned i = 0; i < ROUNDS; ++i) {
		wait_phase(p, 4 * i);
		assert(mprotect((void *)p->page, PAGE, PROT_READ | PROT_WRITE) == 0);
		*p->page = 0xa7;
		errno = 0;
		assert(mmap((void *)p->page, PAGE, PROT_READ,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			    -1, 0) == MAP_FAILED && errno == EEXIST);
		atomic_store_explicit(&p->phase, 4 * i + 1, memory_order_release);
		wait_phase(p, 4 * i + 2);
		int flag = MAP_FIXED;
		if ((i & 1) == 0) {
			assert(munmap((void *)p->page, PAGE) == 0);
			flag = MAP_FIXED_NOREPLACE;
		}
		assert(mmap((void *)p->page, PAGE, PROT_READ,
			    MAP_PRIVATE | MAP_ANONYMOUS | flag, -1, 0) == p->page);
		atomic_store_explicit(&p->phase, 4 * i + 3, memory_order_release);
	}
	wait_phase(p, 4 * ROUNDS);
	assert(munmap((void *)p->page, PAGE) == 0);
	return NULL;
}
int main(void)
{
	assert(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
	unsigned cpus = CPU_COUNT(&allowed);
	if (cpus < 2) {
		puts("MUNMAP_REUSE_SKIP_REQUIRES_SMP");
		return 0;
	}
	unsigned n = cpus >= 4 ? 2 : 1;
	struct pair pairs[2] = { 0 };
	pthread_t threads[4];
	// Reserve guards before creating any threads: another NULL mmap must not
	// choose a temporarily unmapped test address during worker startup.
	for (unsigned i = 0; i < n; ++i) {
		unsigned char *base = mmap(NULL, 3 * PAGE, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		assert(base != MAP_FAILED);
		pairs[i].page = base + PAGE;
	}
	for (unsigned i = 0; i < n; ++i) {
		pairs[i].cpu = 2 * i;
		assert(pthread_create(&threads[2 * i], NULL, writer, &pairs[i]) == 0);
		assert(pthread_create(&threads[2 * i + 1], NULL, reader, &pairs[i]) == 0);
	}
	for (unsigned i = 0; i < 2 * n; ++i)
		assert(pthread_join(threads[i], NULL) == 0);
	for (unsigned i = 0; i < n; ++i)
		assert(munmap((void *)(pairs[i].page - PAGE), 3 * PAGE) == 0);
	puts("MUNMAP_REUSE_PASS");
	return 0;
}
