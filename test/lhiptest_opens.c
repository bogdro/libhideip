/*
 * A library for hiding local IP address.
 *	-- unit test for file opening functions.
 *
 * Copyright (C) 2015-2019 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 */

#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE 600
#define _LARGEFILE64_SOURCE 1
#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _ATFILE_SOURCE 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "libhideip.h"
#include <check.h>
#include "lhiptest_common.h"

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif
#ifndef ENODEV
# define ENODEV 19
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_OPENAT
extern int openat LHIP_PARAMS ((const int dirfd, const char * const pathname, const int flags, ...));
#endif
#ifndef HAVE_OPENAT64
extern int openat64 LHIP_PARAMS ((const int dirfd, const char * const pathname, const int flags, ...));
#endif
/*
#ifndef HAVE_FOPEN64
extern FILE* fopen64 LHIP_PARAMS ((const char * const name, const char * const mode));
#endif

#ifndef HAVE_FREOPEN64
extern FILE* freopen64 LHIP_PARAMS ((const char * const path, const char * const mode, FILE * stream));
#endif

#ifndef HAVE_OPEN64
extern int open64 LHIP_PARAMS ((const char * const path, const int flags, ... ));
#endif
*/

#ifdef __cplusplus
}
#endif

/* ====================== File functions */

#ifdef HAVE_OPENAT
START_TEST(test_openat)
{
	int fd;

	printf("test_openat\n");
	fd = openat(AT_FDCWD, LHIP_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_openat_banned)
{
	int fd;
	int dirfd;
	int r;

	printf("test_openat_banned\n");
	fd = openat(AT_FDCWD, LHIP_TEST_BANNED_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		fail("test_openat_banned: file opened, but shouldn't have been (1)\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
	dirfd = open("/etc", O_RDONLY);
	if (dirfd >= 0)
	{
		fd = openat(dirfd, LHIP_TEST_BANNED_FILENAME_SHORT, O_RDONLY);
		r = errno;
		if (fd >= 0)
		{
			close(fd);
			close(dirfd);
			fail("test_openat_banned: file opened, but shouldn't have been (2)\n");
		}
		close(dirfd);
# ifdef HAVE_ERRNO_H
		if (r != EPERM)
		{
			fail("test_openat_banned: file not opened, but errno invalid: errno=%d\n", r);
		}
# endif
	}
	else
	{
		fail("test_openat_banned: dir not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

# ifdef HAVE_SYMLINK
START_TEST(test_openat_link)
{
	int fd;
	int r;

	printf("test_openat_link\n");
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_openat_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LHIP_LINK_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		r = unlink (LHIP_LINK_FILENAME);
		if (r != 0)
		{
			fail("test_openat_link: link could not have been deleted: errno=%d, r=%d\n", errno, r);
		}
	}
	else
	{
		unlink (LHIP_LINK_FILENAME);
		fail("test_openat_link: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_openat_link_banned)
{
	int fd;
	int r;

	printf("test_openat_link_banned\n");
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_openat_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LHIP_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fail("test_openat_link_banned: file opened, but shouldn't have been\n");
	}
	r = errno;
	unlink (LHIP_TEST_BANNED_LINKNAME);
#  ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
#  endif
}
END_TEST
# endif /* HAVE_SYMLINK */
#endif /* HAVE_OPENAT */

START_TEST(test_fopen)
{
	FILE * f;

	printf("test_fopen\n");
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_fopen_banned)
{
	FILE * f;

	printf("test_fopen_banned\n");
	f = fopen(LHIP_TEST_BANNED_FILENAME, "r");
	if (f != NULL)
	{
		fclose(f);
		fail("test_fopen_banned: file opened, but shouldn't have been\n");
	}
#ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
#endif
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_fopen_link)
{
	FILE * f;
	int r;

	printf("test_fopen_link\n");
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_fopen_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_LINK_FILENAME, "r");
	if (f != NULL)
	{
		unlink (LHIP_LINK_FILENAME);
		fclose(f);
	}
	else
	{
		r = errno;
		unlink (LHIP_LINK_FILENAME);
		fail("test_fopen_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_fopen_link_banned)
{
	FILE * f;
	int r;

	printf("test_fopen_link_banned\n");
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_fopen_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_TEST_BANNED_LINKNAME, "r");
	if (f != NULL)
	{
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fclose(f);
		fail("test_fopen_link_banned: file opened, but shouldn't have been\n");
	}
	r = errno;
	unlink (LHIP_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
# endif
}
END_TEST
#endif /* HAVE_SYMLINK */

START_TEST(test_freopen)
{
	FILE * f;

	printf("test_freopen\n");
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LHIP_TEST_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_stdout)
{
	FILE * f;

	printf("test_freopen_stdout\n");
	f = freopen(LHIP_TEST_FILENAME, "r", stdout);
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_freopen_stdout: file not re-opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_banned)
{
	FILE * f;

	printf("test_freopen_banned\n");
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LHIP_TEST_BANNED_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			fail("test_freopen_banned: file opened, but shouldn't have been\n");
		}
#ifdef HAVE_ERRNO_H
		ck_assert_int_eq(errno, EPERM);
#endif
	}
	else
	{
		fail("test_freopen_banned: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_stdout_banned)
{
	FILE * f;

	printf("test_freopen_stdout_banned\n");
	f = freopen(LHIP_TEST_BANNED_FILENAME, "r", stdout);
	if (f != NULL)
	{
		fclose(f);
		fail("test_freopen_stdout_banned: file opened, but shouldn't have been\n");
	}
#ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
#endif
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_freopen_link)
{
	FILE * f;
	int r;

	printf("test_freopen_link\n");
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_freopen_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_LINK_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LHIP_LINK_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			unlink (LHIP_LINK_FILENAME);
		}
		else
		{
			r = errno;
			unlink (LHIP_LINK_FILENAME);
			fail("test_freopen_link: file not re-opened: errno=%d\n", r);
		}
	}
	else
	{
		r = errno;
		unlink (LHIP_LINK_FILENAME);
		fail("test_freopen_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_freopen_link_banned)
{
	FILE * f;
	int r;

	printf("test_freopen_link_banned\n");
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_freopen_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LHIP_TEST_BANNED_LINKNAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			unlink (LHIP_TEST_BANNED_LINKNAME);
			fail("test_freopen_link_banned: file opened, but shouldn't have been\n");
		}
		r = errno;
		unlink (LHIP_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
		ck_assert_int_eq(r, EPERM);
# endif
	}
	else
	{
		r = errno;
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fail("test_freopen_link_banned: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_freopen_link_banned_stdout)
{
	FILE * f;
	int r;

	printf("test_freopen_link_banned_stdout\n");
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_freopen_link_banned_stdout: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = freopen(LHIP_TEST_BANNED_LINKNAME, "r", stdout);
	if (f != NULL)
	{
		fclose(f);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fail("test_freopen_link_banned_stdout: file opened, but shouldn't have been\n");
	}
	r = errno;
	unlink (LHIP_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
# endif
}
END_TEST
#endif /* HAVE_SYMLINK */

START_TEST(test_open)
{
	int fd;

	printf("test_open\n");
	fd = open(LHIP_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_open_banned)
{
	int fd;

	printf("test_open_banned\n");
	fd = open(LHIP_TEST_BANNED_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		fail("test_open_banned: file opened, but shouldn't have been\n");
	}
#ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
#endif
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_open_link)
{
	int fd;
	int r;

	printf("test_open_link\n");
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_open_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = open(LHIP_LINK_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LHIP_LINK_FILENAME);
	}
	else
	{
		r = errno;
		unlink (LHIP_LINK_FILENAME);
		fail("test_open_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_open_link_banned)
{
	int fd;
	int r;

	printf("test_open_link_banned\n");
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_open_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = open(LHIP_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fail("test_open_link_banned: file opened, but shouldn't have been\n");
	}
	r = errno;
	unlink (LHIP_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
# endif
}
END_TEST
#endif /* HAVE_SYMLINK */

/* ======================================================= */

/*
__attribute__ ((constructor))
static void setup_global(void) / * unchecked * /
{
}
*/

/*
static void teardown_global(void)
{
}
*/

static void setup_file_test(void) /* checked */
{
	FILE *f;

	f = fopen(LHIP_TEST_FILENAME, "w");
	if (f != NULL)
	{
		fwrite("aaa", 1, LHIP_TEST_FILE_LENGTH, f);
		fclose(f);
	}
}

static void teardown_file_test(void)
{
	unlink(LHIP_TEST_FILENAME);
}

static Suite * lhip_create_suite(void)
{
	Suite * s = suite_create("libhideip");

	TCase * tests_open = tcase_create("open");

#ifdef HAVE_OPENAT
	tcase_add_test(tests_open, test_openat);
	tcase_add_test(tests_open, test_openat_banned);
# ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_openat_link);
	tcase_add_test(tests_open, test_openat_link_banned);
# endif
#endif

	tcase_add_test(tests_open, test_open);
	tcase_add_test(tests_open, test_open_banned);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_open_link);
	tcase_add_test(tests_open, test_open_link_banned);
#endif

	tcase_add_test(tests_open, test_fopen);
	tcase_add_test(tests_open, test_fopen_banned);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_fopen_link);
	tcase_add_test(tests_open, test_fopen_link_banned);
#endif
	tcase_add_test(tests_open, test_freopen);
	tcase_add_test(tests_open, test_freopen_stdout);
	tcase_add_test(tests_open, test_freopen_banned);
	tcase_add_test(tests_open, test_freopen_stdout_banned);

#ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_freopen_link);
	tcase_add_test(tests_open, test_freopen_link_banned);
	tcase_add_test(tests_open, test_freopen_link_banned_stdout);
#endif

	tcase_add_checked_fixture(tests_open, &setup_file_test, &teardown_file_test);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_open, 30);

	suite_add_tcase(s, tests_open);

	return s;
}

int main(void)
{
	int failed;

	Suite * s = lhip_create_suite();
	SRunner * sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
