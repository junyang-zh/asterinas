#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_DESCRIPTORS 1024
#define SHM_NAME "/benchshm"
#define SHM_SIZE 1024 * 1024 * 1024 // 1GB

// Descriptor types
#define DESC_UNUSED 0
#define DESC_SERVER_SOCKET 1
#define DESC_CLIENT_SOCKET 2
#define DESC_ACCEPTED_SOCKET 3

// Descriptor table entry
typedef struct {
	int type;
	int state;
	void *buffer; // Pointer for shared memory (optional)
} DescriptorEntry;

// Global descriptor table and lock
static DescriptorEntry descriptor_table[MAX_DESCRIPTORS];
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

// Shared memory pointer
static void *shm_ptr = NULL;

// Function pointers for original system calls
static int (*original_socket)(int, int, int) = NULL;
static int (*original_close)(int) = NULL;

// Helper to initialize shared memory
static void setup_shared_memory()
{
	shm_unlink(
		SHM_NAME); // Ensure the shared memory object is unlinked before creating it
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	if (fd == -1) {
		perror("shm_open");
		exit(EXIT_FAILURE);
	}
	if (ftruncate(fd, SHM_SIZE) == -1) {
		perror("ftruncate");
		exit(EXIT_FAILURE);
	}
	shm_ptr =
		mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (shm_ptr == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	close(fd);
}

// Helper to allocate a fake descriptor
static int allocate_descriptor(int type)
{
	pthread_mutex_lock(&table_lock);
	for (int i = 0; i < MAX_DESCRIPTORS; i++) {
		if (descriptor_table[i].type == DESC_UNUSED) {
			descriptor_table[i].type = type;
			descriptor_table[i].state = 0; // Initial state
			descriptor_table[i].buffer = shm_ptr; // Example usage
			pthread_mutex_unlock(&table_lock);
			return i + 100; // Fake descriptor (start from 100)
		}
	}
	pthread_mutex_unlock(&table_lock);
	errno = EMFILE; // Too many open files
	return -1;
}

// Helper to free a fake descriptor
static void free_descriptor(int fd)
{
	int idx = fd - 100;
	if (idx < 0 || idx >= MAX_DESCRIPTORS)
		return;
	pthread_mutex_lock(&table_lock);
	descriptor_table[idx].type = DESC_UNUSED;
	descriptor_table[idx].state = 0;
	descriptor_table[idx].buffer = NULL;
	pthread_mutex_unlock(&table_lock);
}

// Initialization
__attribute__((constructor)) void init_library()
{
	memset(descriptor_table, 0, sizeof(descriptor_table));
	setup_shared_memory();
}

// Cleanup
__attribute__((destructor)) void cleanup_library()
{
	munmap(shm_ptr, SHM_SIZE);
	shm_unlink(SHM_NAME);
}

/* Socket options */

// Intercepted socket()
int socket(int domain, int type, int protocol)
{
	if (!original_socket) {
		original_socket = dlsym(RTLD_NEXT, "socket");
	}

	if (domain == AF_INET || domain == AF_INET6) {
		return allocate_descriptor(DESC_CLIENT_SOCKET);
	}

	return original_socket(domain, type, protocol);
}

// Intercepted bind()
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type == DESC_CLIENT_SOCKET) {
		descriptor_table[idx].type = DESC_SERVER_SOCKET;
		return 0; // Success
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted listen()
int listen(int sockfd, int backlog)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type == DESC_SERVER_SOCKET) {
		descriptor_table[idx].state = 1; // Listening state
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted accept()
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type == DESC_SERVER_SOCKET) {
		return allocate_descriptor(DESC_ACCEPTED_SOCKET);
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted connect()
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type == DESC_CLIENT_SOCKET) {
		descriptor_table[idx].state = 1; // Connected state
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted close()
int close(int fd)
{
	if (!original_close) {
		original_close = dlsym(RTLD_NEXT, "close");
	}

	int idx = fd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS) {
		free_descriptor(fd);
		return 0; // Success
	}
	return original_close(fd);
}

/* More socket states */

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

// Intercepted setsockopt()
int setsockopt(int sockfd, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Silently succeed for any option
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted getsockopt()
int getsockopt(int sockfd, int level, int optname, void *optval,
	       socklen_t *optlen)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Silently succeed and return default values (e.g., 0)
		if (optval && optlen) {
			memset(optval, 0, *optlen); // Fill with zeroes
		}
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted getsockname()
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Provide a default dummy sockaddr structure
		if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
			struct sockaddr_in *dummy_addr =
				(struct sockaddr_in *)addr;
			memset(dummy_addr, 0, sizeof(struct sockaddr_in));
			dummy_addr->sin_family = AF_INET;
			dummy_addr->sin_port = htons(12345); // Arbitrary port
			dummy_addr->sin_addr.s_addr =
				htonl(INADDR_LOOPBACK); // Loopback address
			*addrlen = sizeof(struct sockaddr_in);
		}
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted getpeername()
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Provide a default dummy sockaddr structure
		if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
			struct sockaddr_in *dummy_addr =
				(struct sockaddr_in *)addr;
			memset(dummy_addr, 0, sizeof(struct sockaddr_in));
			dummy_addr->sin_family = AF_INET;
			dummy_addr->sin_port = htons(12345); // Arbitrary port
			dummy_addr->sin_addr.s_addr =
				htonl(INADDR_LOOPBACK); // Loopback address
			*addrlen = sizeof(struct sockaddr_in);
		}
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted shutdown()
int shutdown(int sockfd, int how)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Silently succeed
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted ioctl() (optional, often used in socket operations)
int ioctl(int sockfd, unsigned long request, void *arg)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Silently succeed for any ioctl call
		return 0;
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

/* Messaging */

#include <sys/uio.h> // For struct iovec
#include <string.h> // For memcpy

// Simulated buffer size for each descriptor
#define BUFFER_SIZE 4096

// Intercepted send()
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Write to shared memory buffer
		if (len > BUFFER_SIZE)
			len = BUFFER_SIZE; // Clamp to buffer size
		memcpy(descriptor_table[idx].buffer, buf, len);
		return len; // Simulate successful send
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted sendto()
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return send(sockfd, buf, len, flags); // Same behavior as send()
}

// Intercepted sendmsg()
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		size_t total_len = 0;
		for (size_t i = 0; i < msg->msg_iovlen; i++) {
			size_t len = msg->msg_iov[i].iov_len;
			if (total_len + len > BUFFER_SIZE)
				len = BUFFER_SIZE -
				      total_len; // Clamp to buffer size
			memcpy(descriptor_table[idx].buffer + total_len,
			       msg->msg_iov[i].iov_base, len);
			total_len += len;
			if (total_len == BUFFER_SIZE)
				break;
		}
		return total_len; // Simulate successful sendmsg
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted recv()
ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		// Read from shared memory buffer
		if (len > BUFFER_SIZE)
			len = BUFFER_SIZE; // Clamp to buffer size
		memcpy(buf, descriptor_table[idx].buffer, len);
		return len; // Simulate successful recv
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

// Intercepted recvfrom()
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen)
{
	return recv(sockfd, buf, len, flags); // Same behavior as recv()
}

// Intercepted recvmsg()
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	int idx = sockfd - 100;
	if (idx >= 0 && idx < MAX_DESCRIPTORS &&
	    descriptor_table[idx].type != DESC_UNUSED) {
		size_t total_len = 0;
		for (size_t i = 0; i < msg->msg_iovlen; i++) {
			size_t len = msg->msg_iov[i].iov_len;
			if (total_len + len > BUFFER_SIZE)
				len = BUFFER_SIZE -
				      total_len; // Clamp to buffer size
			memcpy(msg->msg_iov[i].iov_base,
			       descriptor_table[idx].buffer + total_len, len);
			total_len += len;
			if (total_len == BUFFER_SIZE)
				break;
		}
		return total_len; // Simulate successful recvmsg
	}
	errno = EBADF; // Invalid file descriptor
	return -1;
}

/* Polling */

#include <sys/epoll.h>
#include <errno.h>

// Intercepted epoll_create()
int epoll_create(int size)
{
	errno = ENOSYS; // Function not supported
	return -1;
}

// Intercepted epoll_create1()
int epoll_create1(int flags)
{
	errno = ENOSYS; // Function not supported
	return -1;
}

// Intercepted epoll_ctl()
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	errno = ENOSYS; // Function not supported
	return -1;
}

// Intercepted epoll_wait()
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	errno = ENOSYS; // Function not supported
	return -1;
}

// Intercepted epoll_pwait()
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
		int timeout, const sigset_t *sigmask)
{
	errno = ENOSYS; // Function not supported
	return -1;
}

#include <sys/select.h>
#include <errno.h>

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	   struct timeval *timeout)
{
	if (nfds >
	    MAX_DESCRIPTORS + 100) { // nfds should only check fake descriptors
		errno = EBADF;
		return -1;
	}

	int ready_count = 0;

	// Check read-ready descriptors
	if (readfds) {
		for (int i = 0; i < nfds; i++) {
			if (FD_ISSET(i, readfds)) {
				int idx = i - 100;
				if (idx >= 0 && idx < MAX_DESCRIPTORS &&
				    descriptor_table[idx].type != DESC_UNUSED) {
					// Simulate readiness for reading if in connected or accepted state
					if (descriptor_table[idx].state > 0) {
						FD_SET(i, readfds);
						ready_count++;
					} else {
						FD_CLR(i, readfds);
					}
				} else {
					FD_CLR(i,
					       readfds); // Clear invalid descriptors
				}
			}
		}
	}

	// Check write-ready descriptors
	if (writefds) {
		for (int i = 0; i < nfds; i++) {
			if (FD_ISSET(i, writefds)) {
				int idx = i - 100;
				if (idx >= 0 && idx < MAX_DESCRIPTORS &&
				    descriptor_table[idx].type != DESC_UNUSED) {
					// Simulate readiness for writing
					FD_SET(i, writefds);
					ready_count++;
				} else {
					FD_CLR(i,
					       writefds); // Clear invalid descriptors
				}
			}
		}
	}

	// For simplicity, exceptfds is ignored in this example
	if (exceptfds) {
		FD_ZERO(exceptfds); // No exceptions are simulated
	}

	// Simulate a timeout
	if (ready_count == 0 && timeout) {
		usleep((timeout->tv_sec * 1000000) + (timeout->tv_usec));
	}

	return ready_count;
}

#include <poll.h>
#include <errno.h>

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	if (!fds || nfds == 0) {
		errno = EINVAL;
		return -1;
	}

	int ready_count = 0;

	for (nfds_t i = 0; i < nfds; i++) {
		int fd = fds[i].fd - 100;
		if (fd >= 0 && fd < MAX_DESCRIPTORS &&
		    descriptor_table[fd].type != DESC_UNUSED) {
			fds[i].revents = 0; // Reset events

			// Simulate readiness for reading
			if (fds[i].events & POLLIN) {
				if (descriptor_table[fd].state > 0) {
					fds[i].revents |= POLLIN;
					ready_count++;
				}
			}

			// Simulate readiness for writing
			if (fds[i].events & POLLOUT) {
				fds[i].revents |= POLLOUT;
				ready_count++;
			}

			// No other events are simulated
		} else {
			fds[i].revents = POLLNVAL; // Invalid descriptor
		}
	}

	// Simulate a timeout
	if (ready_count == 0 && timeout > 0) {
		usleep(timeout * 1000); // Convert milliseconds to microseconds
	}

	return ready_count;
}
