/*
 * A library for hiding local IP address.
 *	-- unit test for program execution functions.
 *
 * Copyright (C) 2015-2021 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 600
#define _LARGEFILE64_SOURCE 1
#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#define _DEFAULT_SOURCE 1

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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#else
# define S_IRUSR 0600
# define S_IWUSR 0400
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_EXECVEAT
extern int execveat LHIP_PARAMS ((int dirfd, const char *pathname,
	char *const argv[], char *const envp[], int flags));
#endif
#ifndef HAVE_FEXECVE
extern int fexecve LHIP_PARAMS ((int fd, char *const argv[], char *const envp[]));
#endif

#ifdef __cplusplus
}
#endif

/* ====================== Execution functions */

#ifdef HAVE_UNISTD_H
START_TEST(test_execve)
{
	char progname[] = "/bin/cat";
	char fname[] = LHIP_TEST_FILENAME;
	char * args[] = { NULL, NULL, NULL };
	char * envp[] = { NULL };

	LHIP_PROLOG_FOR_TEST();
	args[0] = progname;
	args[1] = fname;
	execve (progname, args, envp);
	fail("test_execve: the program didn't run, but it should have: errno=%d\n", errno); /* should never be reached */
}
END_TEST

START_TEST(test_execve_banned)
{
	int a;
	char * args[] = { NULL };
	char * envp[] = { NULL };

	LHIP_PROLOG_FOR_TEST();
	a = execve ("/sbin/ifconfig", args, envp);
	ck_assert_int_ne(a, 0);
	exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
}
END_TEST

# ifdef HAVE_EXECVEAT
START_TEST(test_execveat)
{
	char progname[] = "cat";
	char fname[] = LHIP_TEST_FILENAME;
	char * args[] = { NULL, NULL, NULL };
	char * envp[] = { NULL };
	int dirfd;
	int err;

	LHIP_PROLOG_FOR_TEST();
	dirfd = open ("/bin", O_DIRECTORY | O_PATH);
	if ( dirfd >= 0 )
	{
		args[0] = progname;
		args[1] = fname;
		execveat (dirfd, progname, args, envp, 0);
		err = errno;
		close (dirfd);
		fail("test_execveat: the program didn't run, but it should have: errno=%d\n", err); /* should never be reached */
	}
	else
	{
		fail("test_execveat: directory not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_execveat_banned)
{
	int a;
	char progname[] = "ifconfig";
	char * args[] = { NULL };
	char * envp[] = { NULL };
	int dirfd;

	LHIP_PROLOG_FOR_TEST();
	dirfd = open ("/sbin", O_DIRECTORY | O_PATH);
	if ( dirfd >= 0 )
	{
		a = execveat (dirfd, progname, args, envp, 0);
		close (dirfd);
		ck_assert_int_ne(a, 0);
		exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
	}
	else
	{
		fail("test_execveat_banned: directory not opened: errno=%d\n", errno);
	}
}
END_TEST
# endif

# ifdef HAVE_FEXECVE
START_TEST(test_fexecve)
{
	char progname[] = "/bin/cat";
	char fname[] = LHIP_TEST_FILENAME;
	char * args[] = { NULL, NULL, NULL };
	char * envp[] = { NULL };
	int prog_fd;
	int err;

	LHIP_PROLOG_FOR_TEST();
	prog_fd = open (progname, O_RDONLY);
	if ( prog_fd >= 0 )
	{
		args[0] = progname;
		args[1] = fname;
		fexecve (prog_fd, args, envp);
		err = errno;
		close (prog_fd);
		fail("test_fexecve: the program didn't run, but it should have: errno=%d\n", err); /* should never be reached */
	}
	else
	{
		fail("test_fexecve: program not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_fexecve_banned)
{
	int a;
	char progname[] = "/sbin/ifconfig";
	char * args[] = { NULL, NULL };
	char * envp[] = { NULL };
	int prog_fd;

	LHIP_PROLOG_FOR_TEST();
	prog_fd = open (progname, O_RDONLY);
	if ( prog_fd >= 0 )
	{
		args[0] = progname; /* must be set */
		a = fexecve (prog_fd, args, envp);
		close (prog_fd);
		ck_assert_int_ne(a, 0);
		exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
	}
	else
	{
		fail("test_fexecve_banned: program not opened: errno=%d\n", errno);
	}
}
END_TEST
# endif
#endif /* HAVE_UNISTD_H */

START_TEST(test_system)
{
	int a;

	LHIP_PROLOG_FOR_TEST();
	a = system ("/bin/cat " LHIP_TEST_FILENAME);
	ck_assert_int_eq(a, 0);
}
END_TEST

START_TEST(test_system_banned)
{
	int a;

	LHIP_PROLOG_FOR_TEST();
	a = system ("/sbin/ifconfig");
	ck_assert_int_ne(a, 0);
}
END_TEST

START_TEST(test_system_banned2)
{
	int a;

	LHIP_PROLOG_FOR_TEST();
	a = system ("/sbin/ifconfig -a");
	ck_assert_int_ne(a, 0);
}
END_TEST

/* ======================================================= */

static Suite * lhip_create_suite(void)
{
	Suite * s = suite_create("libhideip_exec");

	TCase * tests_exec = tcase_create("exec");

#ifdef HAVE_UNISTD_H
	/*tcase_add_test(tests_exec, test_execve);*/
	tcase_add_exit_test(tests_exec, test_execve, 0);
	/*tcase_add_test(tests_exec, test_execve_banned);*/
	tcase_add_exit_test(tests_exec, test_execve_banned, LHIP_EXIT_VALUE);
# ifdef HAVE_EXECVEAT
	tcase_add_exit_test(tests_exec, test_execveat, 0);
	/*tcase_add_test(tests_exec, test_execveat_banned);*/
	tcase_add_exit_test(tests_exec, test_execveat_banned, LHIP_EXIT_VALUE);
# endif
# ifdef HAVE_FEXECVE
	tcase_add_exit_test(tests_exec, test_fexecve, 0);
	/*tcase_add_test(tests_exec, test_fexecve_banned);*/
	tcase_add_exit_test(tests_exec, test_fexecve_banned, LHIP_EXIT_VALUE);
# endif
#endif
	tcase_add_test(tests_exec, test_system);
	tcase_add_test(tests_exec, test_system_banned);
	tcase_add_test(tests_exec, test_system_banned2);

	lhiptest_add_fixtures (tests_exec);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_exec, 30);

	suite_add_tcase(s, tests_exec);

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
