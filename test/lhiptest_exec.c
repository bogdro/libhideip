/*
 * LibHideIP - A library for hiding local IP address.
 *	-- unit test for program execution functions.
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

#ifndef IFCONFIG_DIR
# define IFCONFIG_DIR "/usr/bin"
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
	ck_abort_msg("test_execve: the program didn't run, but it should have: errno=%d\n", errno); /* should never be reached */
}
END_TEST

START_TEST(test_execve_banned)
{
	int a;
	char * args[] = { NULL };
	char * envp[] = { NULL };

	LHIP_PROLOG_FOR_TEST();
	a = execve (IFCONFIG_DIR "/ifconfig", args, envp);
	ck_assert_int_ne(a, 0);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
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
		ck_abort_msg("test_execveat: the program didn't run, but it should have: errno=%d\n", err); /* should never be reached */
	}
	else
	{
		ck_abort_msg("test_execveat: directory not opened: errno=%d\n", errno);
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
	int err;

	LHIP_PROLOG_FOR_TEST();
	dirfd = open (IFCONFIG_DIR, O_DIRECTORY | O_PATH);
	if ( dirfd >= 0 )
	{
		a = execveat (dirfd, progname, args, envp, 0);
		err = errno;
		close (dirfd);
		ck_assert_int_ne(a, 0);
#  ifdef HAVE_ERRNO_H
		ck_assert_int_eq(err, EPERM);
#  endif
		exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
	}
	else
	{
		ck_abort_msg("test_execveat_banned: directory not opened: errno=%d\n", errno);
	}
}
END_TEST

#  ifdef HAVE_SYMLINK
START_TEST(test_execveat_banned_link)
{
	int a;
	char * args[] = { NULL };
	char * envp[] = { NULL };
	int dirfd;
	int err;

	LHIP_PROLOG_FOR_TEST();
	a = symlink (IFCONFIG_DIR "/ifconfig", LHIP_LINK_FILENAME);
	if (a != 0)
	{
		ck_abort_msg("test_execveat_banned_link: link could not have been created: errno=%d, res=%d\n", errno, a);
	}
	dirfd = open (".", O_DIRECTORY | O_PATH);
	if ( dirfd >= 0 )
	{
		a = execveat (dirfd, LHIP_LINK_FILENAME, args, envp, 0);
		err = errno;
		close (dirfd);
		unlink (LHIP_LINK_FILENAME);
 		ck_assert_int_ne(a, 0);
#  ifdef HAVE_ERRNO_H
		ck_assert_int_eq(err, EPERM);
#   endif
		exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
	}
	else
	{
		ck_abort_msg("test_execveat_banned_link: directory not opened: errno=%d\n", errno);
	}
}
END_TEST
#  endif /* HAVE_SYMLINK */

#  ifdef AT_EMPTY_PATH
START_TEST(test_execveat_banned_empty_path)
{
	int a;
	char * args[] = { NULL };
	char * envp[] = { NULL };
	int fd;
	int err;

	LHIP_PROLOG_FOR_TEST();
	fd = open (IFCONFIG_DIR "/ifconfig", O_RDONLY);
	if ( fd >= 0 )
	{
		a = execveat (fd, "", args, envp, AT_EMPTY_PATH);
		err = errno;
		close (fd);
		ck_assert_int_ne(a, 0);
#   ifdef HAVE_ERRNO_H
		ck_assert_int_eq(err, EPERM);
#   endif
		exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
	}
	else
	{
		ck_abort_msg("test_execveat_banned_empty_path: " IFCONFIG_DIR "/ifconfig not opened: errno=%d\n", errno);
	}
}
END_TEST

#   ifdef HAVE_SYMLINK
START_TEST(test_execveat_banned_empty_path_link)
{
	int a;
	char * args[] = { NULL };
	char * envp[] = { NULL };
	int fd;
	int err;

	LHIP_PROLOG_FOR_TEST();
	a = symlink (IFCONFIG_DIR "/ifconfig", LHIP_LINK_FILENAME);
	if (a != 0)
	{
		ck_abort_msg("test_execveat_banned_empty_path_link: link could not have been created: errno=%d, res=%d\n", errno, a);
	}
	fd = open (LHIP_LINK_FILENAME, O_RDONLY);
	if ( fd >= 0 )
	{
		a = execveat (fd, "", args, envp, AT_EMPTY_PATH);
		err = errno;
		close (fd);
		unlink (LHIP_LINK_FILENAME);
		ck_assert_int_ne(a, 0);
#   ifdef HAVE_ERRNO_H
		ck_assert_int_eq(err, EPERM);
#   endif
		exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
	}
	else
	{
		ck_abort_msg("test_execveat_banned_empty_path_link: " IFCONFIG_DIR "/ifconfig not opened: errno=%d\n", errno);
	}
}
END_TEST
#   endif /* HAVE_SYMLINK */
#  endif /* AT_EMPTY_PATH */
# endif /* HAVE_EXECVEAT */

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
		ck_abort_msg("test_fexecve: the program didn't run, but it should have: errno=%d\n", err); /* should never be reached */
	}
	else
	{
		ck_abort_msg("test_fexecve: program not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_fexecve_banned)
{
	int a;
	char progname[] = "/usr/bin/wget";
	char * args[] = { NULL, "https://libhideip.sourceforge.io", NULL };
	char * envp[] = { NULL };
	int prog_fd;
	int err;

	LHIP_PROLOG_FOR_TEST();
	prog_fd = open (progname, O_RDONLY);
	if ( prog_fd >= 0 )
	{
		args[0] = progname; /* must be set */
		a = fexecve (prog_fd, args, envp);
		err = errno;
		close (prog_fd);
		ck_assert_int_ne(a, 0);
#  ifdef HAVE_ERRNO_H
		ck_assert_int_eq(err, EPERM);
#  endif
		exit (LHIP_EXIT_VALUE); /* expected exit value if the banned program didn't indeed run */
	}
	else
	{
		ck_abort_msg("test_fexecve_banned: program not opened: errno=%d\n", errno);
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
	a = system (IFCONFIG_DIR "/ifconfig");
	ck_assert_int_ne(a, 0);
#ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
#endif
}
END_TEST

START_TEST(test_system_banned2)
{
	int a;

	LHIP_PROLOG_FOR_TEST();
	a = system (IFCONFIG_DIR "/ifconfig -a");
	ck_assert_int_ne(a, 0);
#ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
#endif
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
#  ifdef HAVE_SYMLINK
	tcase_add_exit_test(tests_exec, test_execveat_banned_link, LHIP_EXIT_VALUE);
#  endif
#  ifdef AT_EMPTY_PATH
	tcase_add_exit_test(tests_exec, test_execveat_banned_empty_path, LHIP_EXIT_VALUE);
#   ifdef HAVE_SYMLINK
	tcase_add_exit_test(tests_exec, test_execveat_banned_empty_path_link, LHIP_EXIT_VALUE);
#   endif
#  endif
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
