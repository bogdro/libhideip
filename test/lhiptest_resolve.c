/*
 * A library for hiding local IP address.
 *	-- unit test for name resolution (DNS) functions.
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif

#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif

static char buf[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);

/* ====================== Name resolver functions */

#ifdef HAVE_RESOLV_H
START_TEST(test_res_query)
{
	int a;

	printf("test_res_query\n");
	res_init();
	a = res_query("www.google.com", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_query: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_query_banned)
{
	int a;

	printf("test_res_query_banned\n");
	res_init();
	a = res_query("localhost", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_query_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_search)
{
	int a;

	printf("test_res_search\n");
	res_init();
	a = res_search("www.google.com", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_search: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_search_banned)
{
	int a;

	printf("test_res_search_banned\n");
	res_init();
	a = res_search("localhost", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_search_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_querydomain)
{
	int a;

	printf("test_res_querydomain\n");
	res_init();
	a = res_querydomain("www", "google.com", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_querydomain: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_querydomain_banned)
{
	int a;

	printf("test_res_querydomain_banned\n");
	res_init();
	a = res_querydomain("localhost", "localdomain", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_querydomain_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_mkquery)
{
	int a;

	printf("test_res_mkquery\n");
	res_init();
	a = res_mkquery(QUERY, "www.google.com", C_ANY, T_A, NULL, 0, NULL, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_mkquery: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_mkquery_banned)
{
	int a;

	printf("test_res_mkquery_banned\n");
	res_init();
	a = res_mkquery(QUERY, "localhost", C_ANY, T_A, NULL, 0, NULL, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_mkquery_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST

# if (defined HAVE_RES_NQUERY) || (defined res_nquery)
START_TEST(test_res_nquery)
{
	int a;
	struct __res_state state;

	printf("test_res_nquery\n");
	res_ninit(&state);
	a = res_nquery(&state, "www.google.com", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_nquery: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_nquery_banned)
{
	int a;
	struct __res_state state;

	printf("test_res_nquery_banned\n");
	res_ninit(&state);
	a = res_nquery(&state, "localhost", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_nquery_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_nsearch)
{
	int a;
	struct __res_state state;

	printf("test_res_nsearch\n");
	res_ninit(&state);
	a = res_nsearch(&state, "www.google.com", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_nsearch: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_nsearch_banned)
{
	int a;
	struct __res_state state;

	printf("test_res_nsearch_banned\n");
	res_ninit(&state);
	a = res_nsearch(&state, "localhost", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_nsearch_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_nquerydomain)
{
	int a;
	struct __res_state state;

	printf("test_res_nquerydomain\n");
	res_ninit(&state);
	a = res_nquerydomain(&state, "www", "google.com", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_nquerydomain: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_nquerydomain_banned)
{
	int a;
	struct __res_state state;

	printf("test_res_nquerydomain_banned\n");
	res_ninit(&state);
	a = res_nquerydomain(&state, "localhost", "localdomain", C_ANY, T_A, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_nquerydomain_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_nmkquery)
{
	int a;
	struct __res_state state;

	printf("test_res_nmkquery\n");
	res_ninit(&state);
	a = res_nmkquery(&state, QUERY, "www.google.com", C_ANY, T_A, NULL, 0, NULL, (u_char *)buf, sizeof (buf));
	if ( a < 0 )
	{
		fail("test_res_nmkquery: query failed, but shouldn't have\n");
	}
}
END_TEST

START_TEST(test_res_nmkquery_banned)
{
	int a;
	struct __res_state state;

	printf("test_res_nmkquery_banned\n");
	res_ninit(&state);
	a = res_nmkquery(&state, QUERY, "localhost", C_ANY, T_A, NULL, 0, NULL, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_nmkquery_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST
# endif /* (defined HAVE_RES_NQUERY) || (defined res_nquery) */

#endif /* HAVE_RESOLV_H */

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

	TCase * tests_resolve = tcase_create("resolve");

#ifdef HAVE_RESOLV_H
	tcase_add_test(tests_resolve, test_res_query);
	tcase_add_test(tests_resolve, test_res_query_banned);
	tcase_add_test(tests_resolve, test_res_search);
	tcase_add_test(tests_resolve, test_res_search_banned);
	tcase_add_test(tests_resolve, test_res_querydomain);
	tcase_add_test(tests_resolve, test_res_querydomain_banned);
	tcase_add_test(tests_resolve, test_res_mkquery);
	tcase_add_test(tests_resolve, test_res_mkquery_banned);
# if (defined HAVE_RES_NQUERY) || (defined res_nquery)
	tcase_add_test(tests_resolve, test_res_nquery);
	tcase_add_test(tests_resolve, test_res_nquery_banned);
	tcase_add_test(tests_resolve, test_res_nsearch);
	tcase_add_test(tests_resolve, test_res_nsearch_banned);
	tcase_add_test(tests_resolve, test_res_nquerydomain);
	tcase_add_test(tests_resolve, test_res_nquerydomain_banned);
	tcase_add_test(tests_resolve, test_res_nmkquery);
	tcase_add_test(tests_resolve, test_res_nmkquery_banned);
# endif

	tcase_set_timeout(tests_resolve, 30);

	suite_add_tcase(s, tests_resolve);
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
