/*
 * A library for hiding local IP address.
 *	-- unit test for system name functions.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "libhideip.h"
#include <check.h>
#include "lhiptest_common.h"

#include <stdio.h>

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

/* ====================== System name functions */

#ifdef HAVE_SYS_UTSNAME_H
START_TEST(test_uname)
{
	int a;
	struct utsname u;

	printf("test_uname\n");
	a = uname (&u);
	ck_assert_int_eq(a, 0);
	if (u.nodename != NULL)
	{
		if (strncmp (u.nodename, "localhost", strlen (u.nodename)) != 0)
		{
			fail("u.nodename contains something else than 'localhost': '%s'\n", u.nodename);
		}
	}
}
END_TEST
#endif

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

static Suite * lhip_create_suite(void)
{
	Suite * s = suite_create("libhideip");

#ifdef HAVE_SYS_UTSNAME_H
	TCase * tests_uname = tcase_create("uname");

	tcase_add_test(tests_uname, test_uname);

	tcase_set_timeout(tests_uname, 30);

	suite_add_tcase(s, tests_uname);
#endif
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
