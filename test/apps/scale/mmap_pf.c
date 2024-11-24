#include "common.h"

#define NUM_MMAPS 10 // Number mmaps per thread
#define PAGES_PER_MMAP 1

void *worker_thread(void *arg)
{
	thread_start();

	if (data->is_unfixed_mmap_test) {
		// map them one by one
		for (size_t i = 0; i < NUM_MMAPS; i++) {
			char *region = mmap(NULL, PAGE_SIZE * PAGES_PER_MMAP,
					    PROT_READ | PROT_WRITE,
					    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			// trigger page fault
			region[0] = 1;
		}
	} else {
		// map them one by one
		for (size_t i = 0; i < NUM_MMAPS; i++) {
			char *region = mmap(
				data->base + data->offset[i],
				PAGE_SIZE * PAGES_PER_MMAP,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
			// trigger page fault
			region[0] = 1;
		}
	}

	thread_end(NUM_MMAPS);
}

int main(int argc, char *argv[])
{
	int ret;

	printf("***MMAP_PF UNFIXED***\n");
	ret = entry_point(argc, argv, worker_thread,
			  (test_config_t){ .num_requests_per_thread = NUM_MMAPS,
					   .num_pages_per_request =
						   PAGES_PER_MMAP,
					   .mmap_before_spawn = 0,
					   .trigger_fault_before_spawn = 0,
					   .multi_vma_assign_requests = 0,
					   .contention_level = 0,
					   .is_unfixed_mmap_test = 1 });
	if (ret != 0) {
		perror("entry_point failed");
		exit(EXIT_FAILURE);
	}
	printf("\n");

	for (int contention_level = 0; contention_level <= 2;
	     contention_level++) {
		printf("***MMAP_PF FIXED %s***\n",
		       contention_level_name[contention_level]);
		ret = entry_point(
			argc, argv, worker_thread,
			(test_config_t){ .num_requests_per_thread = NUM_MMAPS,
					 .num_pages_per_request =
						 PAGES_PER_MMAP,
					 .mmap_before_spawn = 0,
					 .trigger_fault_before_spawn = 0,
					 .multi_vma_assign_requests = 0,
					 .contention_level = contention_level,
					 .is_unfixed_mmap_test = 0 });
		if (ret != 0) {
			perror("entry_point failed");
			exit(EXIT_FAILURE);
		}
		printf("\n");
	}
}