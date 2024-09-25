#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define PAGE_SIZE 4096 // Typical page size in bytes
#define NUM_PAGES 65536 // Number of pages to allocate for mmap
#define WARMUP_ITERATIONS 10
#define TEST_ITERATIONS 50
#define MAX_THREADS 128

typedef struct {
	char *region;
	size_t pages;
	int thread_id;
	int num_threads;
	int nr_workers;
} thread_data_t;

int DISPATCH_LIGHT;
int FINISHED_WORKERS;
struct timespec time_end;

void *worker_thread(void *arg)
{
	thread_data_t *data = (thread_data_t *)arg;
	size_t pages_per_thread = data->pages / data->num_threads;
	size_t start_page = data->thread_id * pages_per_thread;
	size_t end_page = start_page + pages_per_thread;
	int nr_workers = data->nr_workers;

	while (__atomic_load_n(&DISPATCH_LIGHT, __ATOMIC_ACQUIRE) == 0) {
		// Wait for the main thread to signal that all threads are ready
	}

	for (size_t i = start_page; i < end_page; i++) {
		data->region[i * PAGE_SIZE] = 1; // Trigger page fault
	}

	if (__atomic_add_fetch(&FINISHED_WORKERS, 1, __ATOMIC_RELEASE) == nr_workers) {
		clock_gettime(CLOCK_MONOTONIC, &time_end);
	}

	return NULL;
}

double get_time_in_seconds(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) +
	       (end->tv_nsec - start->tv_nsec) / 1e9;
}

double run_test(int num_threads)
{
	pthread_t threads[num_threads];
	thread_data_t thread_data[num_threads];

	char *region = mmap(NULL, NUM_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (region == MAP_FAILED) {
		perror("mmap failed");
		exit(EXIT_FAILURE);
	}

	// Initialize global variables
	__atomic_clear(&DISPATCH_LIGHT, __ATOMIC_RELEASE);
	__atomic_clear(&FINISHED_WORKERS, __ATOMIC_RELEASE);

	struct timespec start;

	// Create threads and trigger page faults in parallel
	for (int i = 0; i < num_threads; i++) {
		thread_data[i].region = region;
		thread_data[i].pages = NUM_PAGES;
		thread_data[i].thread_id = i;
		thread_data[i].num_threads = num_threads;
		thread_data[i].nr_workers = num_threads;

		if (pthread_create(&threads[i], NULL, worker_thread,
				   &thread_data[i]) != 0) {
			perror("pthread_create failed");
			exit(EXIT_FAILURE);
		}

		// Set the thread affinity to a specific core
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);
		pthread_setaffinity_np(threads[i], sizeof(cpu_set_t), &cpuset);
	}

	// Signal all threads to start
	clock_gettime(CLOCK_MONOTONIC, &start);
	__atomic_store_n(&DISPATCH_LIGHT, 1, __ATOMIC_RELEASE);

	// Join threads
	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}

	munmap(region, NUM_PAGES * PAGE_SIZE);

	return get_time_in_seconds(&start, &time_end);
}

int main()
{
	printf("Threads, Average Time (s)\n");

	for (int num_threads = 1; num_threads <= MAX_THREADS; num_threads++) {
		for (int i = 0; i < WARMUP_ITERATIONS; i++) {
			run_test(num_threads);
		}

		double total_time = 0.0;

		for (int i = 0; i < TEST_ITERATIONS; i++) {
			total_time += run_test(num_threads);
		}

		double avg_time = total_time / TEST_ITERATIONS;
		printf("%d, %.6f\n", num_threads, avg_time);
	}

	return 0;
}
