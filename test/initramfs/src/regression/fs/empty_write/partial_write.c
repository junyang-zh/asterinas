/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../common/test.h"

static void check_partial_write(int fd, char *src, size_t page)
{
	struct stat st;
	char tail[65];
	char expected[65] = { 0 };

	CHECK_WITH(write(fd, "abc", 3), _ret == 3);
	CHECK_WITH(pwrite(fd, src + page, 16, 3 * page),
		   _ret == -1 && errno == EFAULT);
	CHECK(fstat(fd, &st));
	CHECK_WITH(st.st_size, _ret == 3);

	/* Only the first 32 bytes are readable and reach the destination. */
	CHECK_WITH(pwrite(fd, src + page - 32, 64, page - 32), _ret == 32);
	CHECK(fstat(fd, &st));
	CHECK_WITH(st.st_size, _ret == (off_t)page);
	CHECK_WITH(pread(fd, tail, 3, 0), _ret == 3 && !memcmp(tail, "abc", 3));
	memset(expected + 1, 'k', 32);
	CHECK_WITH(pread(fd, tail, 33, page - 33),
		   _ret == 33 && !memcmp(tail, expected, 33));

	CHECK_WITH(pwrite(fd, "x", 1, page + 64), _ret == 1);
	memset(expected, 0, sizeof(expected));
	expected[64] = 'x';
	CHECK_WITH(pread(fd, tail, sizeof(tail), page),
		   _ret == sizeof(tail) && !memcmp(tail, expected, sizeof(tail)));
}

FN_TEST(partial_write_publishes_copied_size)
{
	size_t page = sysconf(_SC_PAGESIZE);
	char path[] = "/tmp/partial-write-XXXXXX";
	char *src = CHECK_WITH(mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
			       _ret != MAP_FAILED);
	memset(src, 'k', page);
	CHECK(mprotect(src + page, page, PROT_NONE));

	int file = CHECK(mkstemp(path));
	CHECK(unlink(path));
	check_partial_write(file, src, page);
	CHECK(close(file));

	int memfd = CHECK(memfd_create("partial-write", 0));
	check_partial_write(memfd, src, page);
	CHECK(close(memfd));
	TEST_SUCC(munmap(src, 2 * page));
}
END_TEST()
