/*
 * LibHideIP - A library for hiding local IP address.
 *	-- unit test for file opening functions.
 *
 * Copyright (C) 2015-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "lhiptest_common.h"
#include "libhideip.h"

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

	LHIP_PROLOG_FOR_TEST();
	fd = openat(AT_FDCWD, LHIP_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		ck_abort_msg("test_openat: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_openat_banned)
{
	int fd;
	int dirfd;
	int r;

	LHIP_PROLOG_FOR_TEST();
	fd = openat(AT_FDCWD, LHIP_TEST_BANNED_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		ck_abort_msg("test_openat_banned: file opened, but shouldn't have been (1)\n");
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
			ck_abort_msg("test_openat_banned: file opened, but shouldn't have been (2)\n");
		}
		close(dirfd);
# ifdef HAVE_ERRNO_H
		if (r != EPERM)
		{
			ck_abort_msg("test_openat_banned: file not opened, but errno invalid: errno=%d\n", r);
		}
# endif
	}
	else
	{
		ck_abort_msg("test_openat_banned: dir not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

# ifdef HAVE_SYMLINK
START_TEST(test_openat_link)
{
	int fd;
	int r;

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_openat_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LHIP_LINK_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		r = unlink (LHIP_LINK_FILENAME);
		if (r != 0)
		{
			ck_abort_msg("test_openat_link: link could not have been deleted: errno=%d, r=%d\n", errno, r);
		}
	}
	else
	{
		unlink (LHIP_LINK_FILENAME);
		ck_abort_msg("test_openat_link: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_openat_link_banned)
{
	int fd;
	int r;

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		ck_abort_msg("test_openat_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LHIP_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		ck_abort_msg("test_openat_link_banned: file opened, but shouldn't have been\n");
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

	LHIP_PROLOG_FOR_TEST();
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_fopen_dev)
{
	FILE * f;

	LHIP_PROLOG_FOR_TEST();
	f = fopen("/dev/null", "r");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_dev: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_fopen_proc)
{
	FILE * f;
	/* strlen(/proc/) + strlen(maxuint or "self") + strlen(/exe) + '\0' */
	char procpath[6 + 11 + 4 + 1];

	LHIP_PROLOG_FOR_TEST();

#ifdef HAVE_SNPRINTF
# ifdef HAVE_GETPID
	snprintf (procpath, sizeof(procpath) - 1, "/proc/%d/exe", getpid());
# else
	strncpy (procpath, "/proc/self/exe", sizeof(procpath) - 1);
# endif
#else
# ifdef HAVE_GETPID
	sprintf (procpath, "/proc/%d/exe", getpid());
# else
	strncpy (procpath, "/proc/self/exe", sizeof(procpath) - 1);
# endif
#endif

	f = fopen(procpath, "r");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_proc: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_fopen_banned)
{
	FILE * f;

	LHIP_PROLOG_FOR_TEST();
	f = fopen(LHIP_TEST_BANNED_FILENAME, "r");
	if (f != NULL)
	{
		fclose(f);
		ck_abort_msg("test_fopen_banned: file opened, but shouldn't have been\n");
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

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_fopen_link: link could not have been created: errno=%d, r=%d\n", errno, r);
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
		ck_abort_msg("test_fopen_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_fopen_link_banned)
{
	FILE * f;
	int r;

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		ck_abort_msg("test_fopen_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_TEST_BANNED_LINKNAME, "r");
	if (f != NULL)
	{
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fclose(f);
		ck_abort_msg("test_fopen_link_banned: file opened, but shouldn't have been\n");
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

	LHIP_PROLOG_FOR_TEST();
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
			ck_abort_msg("test_freopen: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_stdout)
{
	FILE * f;

	LHIP_PROLOG_FOR_TEST();
	f = freopen(LHIP_TEST_FILENAME, "r", stdout);
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_freopen_stdout: file not re-opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_banned)
{
	FILE * f;

	LHIP_PROLOG_FOR_TEST();
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LHIP_TEST_BANNED_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			ck_abort_msg("test_freopen_banned: file opened, but shouldn't have been\n");
		}
#ifdef HAVE_ERRNO_H
		ck_assert_int_eq(errno, EPERM);
#endif
	}
	else
	{
		ck_abort_msg("test_freopen_banned: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_stdout_banned)
{
	FILE * f;

	LHIP_PROLOG_FOR_TEST();
	f = freopen(LHIP_TEST_BANNED_FILENAME, "r", stdout);
	if (f != NULL)
	{
		fclose(f);
		ck_abort_msg("test_freopen_stdout_banned: file opened, but shouldn't have been\n");
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

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_freopen_link: link could not have been created: errno=%d, r=%d\n", errno, r);
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
			ck_abort_msg("test_freopen_link: file not re-opened: errno=%d\n", r);
		}
	}
	else
	{
		r = errno;
		unlink (LHIP_LINK_FILENAME);
		ck_abort_msg("test_freopen_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_freopen_link_banned)
{
	FILE * f;
	int r;

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		ck_abort_msg("test_freopen_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LHIP_TEST_BANNED_LINKNAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			unlink (LHIP_TEST_BANNED_LINKNAME);
			ck_abort_msg("test_freopen_link_banned: file opened, but shouldn't have been\n");
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
		ck_abort_msg("test_freopen_link_banned: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_freopen_link_banned_stdout)
{
	FILE * f;
	int r;

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		ck_abort_msg("test_freopen_link_banned_stdout: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = freopen(LHIP_TEST_BANNED_LINKNAME, "r", stdout);
	if (f != NULL)
	{
		fclose(f);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		ck_abort_msg("test_freopen_link_banned_stdout: file opened, but shouldn't have been\n");
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

	LHIP_PROLOG_FOR_TEST();
	fd = open(LHIP_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		ck_abort_msg("test_open: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_open_banned)
{
	int fd;

	LHIP_PROLOG_FOR_TEST();
	fd = open(LHIP_TEST_BANNED_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		ck_abort_msg("test_open_banned: file opened, but shouldn't have been\n");
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

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_FILENAME, LHIP_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_open_link: link could not have been created: errno=%d, r=%d\n", errno, r);
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
		ck_abort_msg("test_open_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_open_link_banned)
{
	int fd;
	int r;

	LHIP_PROLOG_FOR_TEST();
	r = symlink (LHIP_TEST_BANNED_FILENAME, LHIP_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		ck_abort_msg("test_open_link_banned: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = open(LHIP_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		ck_abort_msg("test_open_link_banned: file opened, but shouldn't have been\n");
	}
	r = errno;
	unlink (LHIP_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
# endif
}
END_TEST
#endif /* HAVE_SYMLINK */

START_TEST(test_open_proc)
{
	int fd;
	/* strlen(/proc/) + strlen(maxuint or "self") + strlen(/exe) + '\0' */
	char procpath[6 + 11 + 4 + 1];

	LHIP_PROLOG_FOR_TEST();

#ifdef HAVE_SNPRINTF
# ifdef HAVE_GETPID
	snprintf (procpath, sizeof(procpath) - 1, "/proc/%d/exe", getpid());
# else
	strncpy (procpath, "/proc/self/exe", sizeof(procpath) - 1);
# endif
#else
# ifdef HAVE_GETPID
	sprintf (procpath, "/proc/%d/exe", getpid());
# else
	strncpy (procpath, "/proc/self/exe", sizeof(procpath) - 1);
# endif
#endif

	fd = open(procpath, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		ck_abort_msg("test_open_proc: file not opened: errno=%d\n", errno);
	}
}
END_TEST

/* ======================================================= */

static Suite * lhip_create_suite(void)
{
	Suite * s = suite_create("libhideip_open");

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
	tcase_add_test(tests_open, test_open_proc);

	tcase_add_test(tests_open, test_fopen);
	tcase_add_test(tests_open, test_fopen_dev);
	tcase_add_test(tests_open, test_fopen_proc);
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

	lhiptest_add_fixtures (tests_open);

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
