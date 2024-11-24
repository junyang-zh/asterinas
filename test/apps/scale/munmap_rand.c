#include "common.h"

#define NUM_PAGES 32 // Number of pages to unmap per thread

void *worker_thread(void *arg)
{
	thread_data_t *data = (thread_data_t *)arg;

	long tsc_start, tsc_end;

	// Wait for the main thread to signal that all threads are ready
	while (__atomic_load_n(&DISPATCH_LIGHT, __ATOMIC_ACQUIRE) == 0) {
		sched_yield();
	}

	tsc_start = rdtsc();

	// unmap them one by one randomly
	unsigned int rand = 0xdeadbeef - data->thread_id;
	for (size_t i = 0; i < NUM_PAGES; i++) {
		rand = simple_get_rand(rand);
		size_t idx = (rand / PAGE_SIZE) %
			     (data->region_size / PAGE_SIZE) * PAGE_SIZE;
		munmap(data->region + idx, PAGE_SIZE);
	}

	tsc_end = rdtsc();
	long tot_time = get_time_in_nanos(tsc_start, tsc_end);

	data->lat = tot_time / NUM_PAGES;

	return NULL;
}

int main(int argc, char *argv[])
{
	return entry_point(argc, argv, worker_thread,
			   (test_config_t){ .num_prealloc_pages_per_thread =
						    NUM_PAGES,
					    .trigger_fault_before_spawn = 1 });
}
