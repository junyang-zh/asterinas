#include "common.h"

#define NUM_PAGES 1024 // Number of pages to unmap per thread

void *worker_thread(void *arg)
{
	thread_start();

	// unmap them one by one
	for (size_t i = 0; i < NUM_PAGES; i++) {
		munmap(data->base + data->offset[i], PAGE_SIZE);
	}

	thread_end(NUM_PAGES);
}

int main(int argc, char *argv[])
{
	if (argc > 4 || argc < 3) {
		fprintf(stderr,
			"Usage: %s one_vma|multi_vma contention_level [num_threads]\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	int one_multi = 0;
	int contention_level = 0;
	int num_threads = -1;
	if (strcmp(argv[1], "one_vma") == 0) {
		one_multi = 0;
	} else if (strcmp(argv[1], "multi_vma") == 0) {
		one_multi = 1;
	} else {
		fprintf(stderr, "Invalid argument: %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	contention_level = atoi(argv[2]);
	if (contention_level < 0 || contention_level > 2) {
		fprintf(stderr, "Invalid contention level: %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}
	if (argc == 4) {
		num_threads = read_num_threads(argv[3]);
	} else {
		num_threads = -1;
	}
	printf("***MUNMAP_VIRT %s %s***\n",
	       one_multi ? "MULTI_VMAS" : "ONE_VMA",
	       contention_level_name[contention_level]);
	run_test_specify_threads(
		num_threads, worker_thread,
		(test_config_t){ .num_requests_per_thread = NUM_PAGES,
				 .num_pages_per_request = 1,
				 .mmap_before_spawn = 1,
				 .trigger_fault_before_spawn = 0,
				 .multi_vma_assign_requests = one_multi,
				 .contention_level = contention_level,
				 .is_unfixed_mmap_test = 0 });
	printf("\n");
}
