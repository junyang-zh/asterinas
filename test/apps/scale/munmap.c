#include "common.h"

#define NUM_PAGES 32 // Number of pages to unmap per thread

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
	int ret;

	for (int one_multi = 0; one_multi <= 1; one_multi++) {
		for (int contention_level = 0; contention_level <= 2;
		     contention_level++) {
			printf("***MUNMAP %s %s***\n",
			       one_multi ? "MULTI_VMAS" : "ONE_VMA",
			       contention_level_name[contention_level]);
			ret = entry_point(
				argc, argv, worker_thread,
				(test_config_t){
					.num_requests_per_thread = NUM_PAGES,
					.num_pages_per_request = 1,
					.mmap_before_spawn = 1,
					.trigger_fault_before_spawn = 1,
					.multi_vma_assign_requests = one_multi,
					.contention_level = contention_level,
					.is_unfixed_mmap_test = 0 });
			if (ret != 0) {
				perror("entry_point failed");
				exit(EXIT_FAILURE);
			}
			printf("\n");
		}
	}
}
