/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../../common/test.h"

static void check_partial_read(int fd, char *dst, size_t page)
{
	char data[96];
	memset(data, 'x', sizeof(data));
	CHECK_WITH(pwrite(fd, data, sizeof(data), page), _ret == sizeof(data));
	CHECK(lseek(fd, page - 8, SEEK_SET));

	/* The first eight bytes are a hole and the next 24 are resident. */
	memset(dst + page - 32, 0xaa, 32);
	CHECK_WITH(read(fd, dst + page - 32, 64), _ret == 32);
	CHECK_WITH(lseek(fd, 0, SEEK_CUR), _ret == (off_t)page + 24);
	CHECK_WITH(memcmp(dst + page - 32, (char[8]){ 0 }, 8), _ret == 0);
	CHECK_WITH(memcmp(dst + page - 24, data, 24), _ret == 0);

	CHECK_WITH(read(fd, dst + page, 8), _ret == -1 && errno == EFAULT);
	CHECK_WITH(lseek(fd, 0, SEEK_CUR), _ret == (off_t)page + 24);
	CHECK_WITH(pread(fd, dst + page - 16, 32, 0), _ret == 16);
	CHECK_WITH(memcmp(dst + page - 16, (char[16]){ 0 }, 16), _ret == 0);
	CHECK_WITH(lseek(fd, 0, SEEK_CUR), _ret == (off_t)page + 24);

	struct iovec vec[] = { { dst, 5 }, { dst + page - 9, 18 }, { dst + 5, 5 } };
	CHECK_WITH(readv(fd, vec, 3), _ret == 14);
	CHECK_WITH(lseek(fd, 0, SEEK_CUR), _ret == (off_t)page + 38);
	CHECK_WITH(pread(fd, dst + page, 1, page + sizeof(data)), _ret == 0);
}

FN_TEST(partial_read_returns_copied_bytes)
{
	size_t page = sysconf(_SC_PAGESIZE);
	char path[] = "/tmp/partial-read-XXXXXX";
	char *dst = CHECK_WITH(mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
			       _ret != MAP_FAILED);
	CHECK(mprotect(dst + page, page, PROT_NONE));

	int fd = CHECK(mkstemp(path));
	CHECK(unlink(path));
	check_partial_read(fd, dst, page);
	CHECK(close(fd));
	fd = CHECK(memfd_create("partial-read", 0));
	check_partial_read(fd, dst, page);
	CHECK(close(fd));
	TEST_SUCC(munmap(dst, 2 * page));
}
END_TEST()
