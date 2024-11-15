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
#define NUM_PAGES 2048 // Number of pages to allocate for mmap
#define WARMUP_ITERATIONS 10
#define TEST_ITERATIONS 50
#define MAX_THREADS 32

double timecost[TEST_ITERATIONS];

long get_time_in_nanos(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000000000 +
	       (end->tv_nsec - start->tv_nsec);
}

typedef struct {
	char **regions;
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

	for (size_t i = start_page; i < end_page - 7; i += 8) {
		data->regions[i] = mmap(NULL, 8 * PAGE_SIZE, PROT_READ,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (data->regions[i] == MAP_FAILED) {
			perror("mmap failed");
			exit(EXIT_FAILURE);
		}
		for (size_t j = 0; j < 8; j+=2) {
			if (mprotect(data->regions[i] + j * PAGE_SIZE,
				     PAGE_SIZE*2, PROT_READ | PROT_WRITE) == -1) {
				perror("mprotect failed");
				exit(EXIT_FAILURE);
			}
		}
		// RELEASE下咋都跑不起来
		// DEBUG下且粒度为1页 能跑1线程的，2线程panic
		// DEBUG下且粒度为2页 能跑1线程的，2线程疑似死锁
		// DEBUG下且粒度为4页 能跑1,2线程，3线程panic
		// Uncaught panic:
        // assertion failed: range.start >= last_end
        // at /root/asterinas/kernel/src/vm/vmar/mod.rs:205
		// DEBUG下且粒度为8页 能跑起来
	}
	for (size_t i = start_page; i < end_page - 7; i += 8) {
		if(munmap(data->regions[i], 8 * PAGE_SIZE) == -1){
			perror("munmap failed");
			exit(EXIT_FAILURE);
		}
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

	char **regions = mmap(NULL, NUM_PAGES * sizeof(char *),
			      PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (regions == MAP_FAILED) {
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
		thread_data[i].regions = regions;
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

	munmap(regions, NUM_PAGES * sizeof(char *));
}

void run_multiple_avg_test(int num_threads)
{
	for (int i = 0; i < WARMUP_ITERATIONS; i++) {
		test_result_t result;
		run_test(&result, num_threads);
		printf("WARMUP %d\n", i);
	}

	// Calculate average time excluding the best and worst results
	long min = 0x7FFFFFFFFFFFFFFF;
	int min_index = 0;
	long max = 0;
	int max_index = 0;
	test_result_t test_result[TEST_ITERATIONS];

	for (int i = 0; i < TEST_ITERATIONS; i++) {
		run_test(&test_result[i], num_threads);
		printf("TEST %d\n", i);

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

	long second_min = 0x7FFFFFFFFFFFFFFF, second_max = 0;

	for (int i = 0; i < TEST_ITERATIONS; i++) {
		if (i != min_index && i != max_index) {
			avg.completion_time += test_result[i].completion_time /
					       (TEST_ITERATIONS - 2);
			avg.per_thread_time += test_result[i].per_thread_time /
					       (TEST_ITERATIONS - 2);
			if (test_result[i].completion_time < second_min) {
				second_min = test_result[i].completion_time;
			}
			if (test_result[i].completion_time > second_max) {
				second_max = test_result[i].completion_time;
			}
		}
	}
	double variance = 0;
	for (int i = 0; i < TEST_ITERATIONS; i++) {
		if (i != min_index && i != max_index) {
			double tmp =
				((double)test_result[i].completion_time / 1e9 -
				 (double)avg.completion_time / 1e9);
			variance += tmp * tmp / (TEST_ITERATIONS - 2);
		}
	}

	printf("%d, %.6f, %.6f, %.6f, %.6f, %.6f\n", num_threads,
	       (double)avg.completion_time / 1e9,
	       (double)avg.per_thread_time / 1e9, variance,
	       (double)second_max / 1e9, (double)second_min / 1e9);
}

int main(int argc, char *argv[])
{
	printf("Threads, Completion Time (s), Per-Thread Time (s), Variance, Second Max Time (s), Second Min Time (s)\n");

	// Usage: ./mmap_scale_addr_fixed [num_threads_from] [num_threads_to]

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
