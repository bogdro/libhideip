/*
 * LibHideIP - A library for hiding local IP address.
 *	-- unit test for banning functions.
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

#define _POSIX_C_SOURCE 200112L
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

#ifdef HAVE_UNISTD_H
# include <unistd.h> /* unlink */
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
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

/* ======================================================= */

#ifdef LHIP_CAN_USE_BANS
START_TEST(test_banned_in_userfile_prog)
{
	int fd;
	FILE * user_ban_file;
	char * user_ban_file_name;
	char * home_env;
	int err;
	long file_len;

	LHIP_PROLOG_FOR_TEST();

	home_env = getenv("HOME");
	if ( home_env == NULL )
	{
		return;
	}
	user_ban_file_name = (char *) malloc (strlen (home_env) + 1
		+ strlen (LHIP_BANNING_USERFILE) + 1);
	if ( user_ban_file_name == NULL )
	{
		ck_abort_msg("test_banned_in_userfile_prog: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (user_ban_file_name, home_env);
	strcat (user_ban_file_name, "/");
	strcat (user_ban_file_name, LHIP_BANNING_USERFILE);

	user_ban_file = fopen (user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (user_ban_file_name);
		ck_abort_msg("test_banned_in_userfile_prog: cannot open user file: errno=%d\n", err);
	}

	fseek (user_ban_file, 0, SEEK_END);
	file_len = ftell (user_ban_file);
	fwrite ("\nlhiptest\n", 1, strlen("\nlhiptest\n"), user_ban_file);
	fclose (user_ban_file);

	fd = open(LHIP_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (user_ban_file_name);
	}
	else
	{
		truncate (user_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		free (user_ban_file_name);
		ck_abort_msg("test_banned_in_userfile_prog: file not opened: errno=%d\n", err);
	}
	free (user_ban_file_name);
}
END_TEST
#endif

#ifdef LHIP_CAN_USE_ENV
START_TEST(test_banned_in_env_prog)
{
	int fd;
	FILE * env_ban_file;
	char env_ban_file_name[] = "libhideip.env";
	int err;
	long file_len;
	int res;

	LHIP_PROLOG_FOR_TEST();

	res = setenv(LHIP_BANNING_ENV, env_ban_file_name, 1);
	if ( res != 0 )
	{
		ck_abort_msg("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (env_ban_file_name, "a+");
	if ( env_ban_file == NULL )
	{
		unsetenv(LHIP_BANNING_ENV);
		ck_abort_msg("test_banned_in_env_prog: cannot open user file: errno=%d\n", errno);
	}

	fseek (env_ban_file, 0, SEEK_END);
	file_len = ftell (env_ban_file);
	fwrite ("\nlhiptest\n", 1, strlen("\nlhiptest\n"), env_ban_file);
	fclose (env_ban_file);

	fd = open(LHIP_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (env_ban_file_name);
	}
	else
	{
		truncate (env_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		unsetenv(LHIP_BANNING_ENV);
		ck_abort_msg("test_banned_in_env_prog: file not opened: errno=%d\n", err);
	}
}
END_TEST
#endif

/* ======================================================= */

static Suite * lhip_create_suite(void)
{
	Suite * s = suite_create("libhideip_banning");

	TCase * tests_banned = tcase_create("banning");

#ifdef LHIP_CAN_USE_BANS
	tcase_add_test(tests_banned, test_banned_in_userfile_prog);
#endif
#ifdef LHIP_CAN_USE_ENV
	tcase_add_test(tests_banned, test_banned_in_env_prog);
#endif
	lhiptest_add_fixtures (tests_banned);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_banned, 30);

	suite_add_tcase(s, tests_banned);

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
