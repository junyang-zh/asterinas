#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define PAGE_SIZE 4096 // Typical page size in bytes
#define NUM_PAGES 65536 // Number of pages to allocate for mmap
#define WARMUP_ITERATIONS 10
#define TEST_ITERATIONS 50
#define MAX_THREADS 96

long get_time_in_nanos(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000000000 +
	       (end->tv_nsec - start->tv_nsec);
}

typedef struct {
	char *region;
	size_t pages;
	int thread_id;
	int num_threads;
	int nr_workers;
} thread_data_t;

int DISPATCH_LIGHT;
int FINISHED_WORKERS;
long THREAD_TOTAL_TIME;
struct timespec time_end;

void *worker_thread(void *arg)
{
	thread_data_t *data = (thread_data_t *)arg;
	size_t pages_per_thread = data->pages / data->num_threads;
	size_t start_page = data->thread_id * pages_per_thread;
	size_t end_page = start_page + pages_per_thread;
	int nr_workers = data->nr_workers;

	struct timespec thread_time_start, thread_time_end;

	// Wait for the main thread to signal that all threads are ready
	while (__atomic_load_n(&DISPATCH_LIGHT, __ATOMIC_ACQUIRE) == 0) {
		sched_yield();
	}

	clock_gettime(CLOCK_MONOTONIC, &thread_time_start);

	for (size_t i = start_page; i < end_page; i++) {
		data->region[i * PAGE_SIZE] = 1; // Trigger page fault
	}

	clock_gettime(CLOCK_MONOTONIC, &thread_time_end);
	long time = get_time_in_nanos(&thread_time_start, &thread_time_end);

	if (__atomic_add_fetch(&FINISHED_WORKERS, 1, __ATOMIC_RELEASE) ==
	    nr_workers) {
		time_end = thread_time_end;
	}

	__atomic_add_fetch(&THREAD_TOTAL_TIME, time, __ATOMIC_RELEASE);

	return NULL;
}

typedef struct {
	long completion_time;
	long per_thread_time;
} test_result_t;

void run_test(test_result_t *result, int num_threads)
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
	__atomic_store_n(&FINISHED_WORKERS, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&THREAD_TOTAL_TIME, 0, __ATOMIC_RELEASE);

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
		if (pthread_setaffinity_np(threads[i], sizeof(cpu_set_t),
					   &cpuset) != 0) {
			perror("pthread_setaffinity_np failed");
			exit(EXIT_FAILURE);
		}
	}

	// Signal all threads to start
	clock_gettime(CLOCK_MONOTONIC, &start);
	__atomic_store_n(&DISPATCH_LIGHT, 1, __ATOMIC_RELEASE);

	// Join threads
	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}

	result->completion_time = get_time_in_nanos(&start, &time_end);
	long thread_total_time =
		__atomic_load_n(&THREAD_TOTAL_TIME, __ATOMIC_ACQUIRE);
	result->per_thread_time = thread_total_time / num_threads;

	munmap(region, NUM_PAGES * PAGE_SIZE);
}

void run_multiple_avg_test(int num_threads)
{
	for (int i = 0; i < WARMUP_ITERATIONS; i++) {
		test_result_t result;
		run_test(&result, num_threads);
	}

	// Calculate average time excluding the best and worst results
	long min = 0x7FFFFFFFFFFFFFFF;
	int min_index = 0;
	long max = 0;
	int max_index = 0;
	test_result_t test_result[TEST_ITERATIONS];

	for (int i = 0; i < TEST_ITERATIONS; i++) {
		run_test(&test_result[i], num_threads);

		if (test_result[i].completion_time < min) {
			min = test_result[i].completion_time;
			min_index = i;
		}
		if (test_result[i].completion_time > max) {
			max = test_result[i].completion_time;
			max_index = i;
		}
	}

	test_result_t avg;
	avg.completion_time = 0;
	avg.per_thread_time = 0;

	for (int i = 0; i < TEST_ITERATIONS; i++) {
		if (i != min_index && i != max_index) {
			avg.completion_time += test_result[i].completion_time /
					       (TEST_ITERATIONS - 2);
			avg.per_thread_time += test_result[i].per_thread_time /
					       (TEST_ITERATIONS - 2);
		}
	}

	printf("%d, %.6f, %.6f\n", num_threads,
	       (double)avg.completion_time / 1e9,
	       (double)avg.per_thread_time / 1e9);
}

int main(int argc, char *argv[])
{
	printf("Threads, Completion Time (s), Per-Thread Time (s)\n");

	// Usage: ./pf_scale [num_threads_from] [num_threads_to]

	int num_threads_from, num_threads_to;
	if (argc == 1) {
		num_threads_from = 1;
		num_threads_to = MAX_THREADS;
	} else if (argc == 2) {
		num_threads_from = atoi(argv[1]);
		num_threads_to = num_threads_from;
	} else if (argc == 3) {
		num_threads_from = atoi(argv[1]);
		num_threads_to = atoi(argv[2]);
	} else {
		fprintf(stderr,
			"Usage: %s [num_threads_from] [num_threads_to]\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	for (int num_threads = num_threads_from; num_threads <= num_threads_to;
	     num_threads++) {
		// Spawn a process for a test in order to avoid interference between tests
		int pid = fork();
		if (pid == -1) {
			perror("fork failed");
			exit(EXIT_FAILURE);
		} else if (pid == 0) {
			// Child process
			run_multiple_avg_test(num_threads);
			exit(EXIT_SUCCESS);
		} else {
			// Parent process
			wait(NULL);
		}
	}

	return 0;
}
