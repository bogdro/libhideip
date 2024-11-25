/*
 * LibHideIP - A library for hiding local IP address.
 *	-- unit test for packet capture functions.
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

#include <stdio.h>

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h> /* unlink */
#endif

#ifdef HAVE_PCAP_H
# include <pcap.h>
#else
# ifdef HAVE_PCAP_PCAP_H
#  include <pcap/pcap.h>
# endif
#endif

static char buf[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);

/* ====================== Packet capture functions */

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
START_TEST(test_pcap_lookupdev)
{
	char * pcap_dev;

	LHIP_PROLOG_FOR_TEST();
	buf[0] = '\0';
	pcap_dev = pcap_lookupdev (buf);
	fail_if(pcap_dev != NULL);
}
END_TEST

START_TEST(test_pcap_lookupnet)
{
	int a;
	bpf_u_int32 ip;
	bpf_u_int32 mask;

	LHIP_PROLOG_FOR_TEST();
	a = pcap_lookupnet ("eth0", &ip, &mask, buf);
	ck_assert_int_eq(a, -1);
}
END_TEST

START_TEST(test_pcap_create)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_create ("eth0", buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_create: capture created, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_open_dead)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_open_dead (100, 100);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_dead: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_open_dead_with_ts)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_open_dead_with_tstamp_precision (100, 100, 100);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_dead_with_ts: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_open_live)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_open_live ("eth0", 100, 0, 1000, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_live: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_open_offline)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_open_offline (LHIP_TEST_FILENAME, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_offline: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_open_offline_with_ts)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_open_offline_with_tstamp_precision (LHIP_TEST_FILENAME, 100, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_offline_with_ts: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_fopen_offline)
{
	pcap_t * ret;
	FILE *f;

	LHIP_PROLOG_FOR_TEST();
	f = fopen(LHIP_TEST_FILENAME, "w+");
	if (f != NULL)
	{
		ret = pcap_fopen_offline (f, buf);
		if (ret != NULL)
		{
			pcap_close(ret);
			fclose(f);
			unlink (LHIP_TEST_FILENAME);
			fail("test_pcap_fopen_offline: capture opened, but shouldn't have been\n");
		}
		fclose(f);
		unlink (LHIP_TEST_FILENAME);
	}
	else
	{
		fail("test_pcap_fopen_offline: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_pcap_fopen_offline_with_ts)
{
	pcap_t * ret;
	FILE *f;

	LHIP_PROLOG_FOR_TEST();
	f = fopen(LHIP_TEST_FILENAME, "w+");
	if (f != NULL)
	{
		ret = pcap_fopen_offline_with_tstamp_precision (f, 100, buf);
		if (ret != NULL)
		{
			pcap_close(ret);
			fclose(f);
			unlink (LHIP_TEST_FILENAME);
			fail("test_pcap_fopen_offline_with_ts: capture opened, but shouldn't have been\n");
		}
		fclose(f);
		unlink (LHIP_TEST_FILENAME);
	}
	else
	{
		fail("test_pcap_fopen_offline_with_ts: file not opened: errno=%d\n", errno);
	}
}
END_TEST

#if (defined WIN32) || (defined _WIN32)
START_TEST(test_pcap_hopen_offline)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_hopen_offline (0, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_hopen_offline: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_hopen_offline_with_ts)
{
	pcap_t * ret;

	LHIP_PROLOG_FOR_TEST();
	ret = pcap_hopen_offline_with_tstamp_precision (0, 100, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_hopen_offline_with_ts: capture opened, but shouldn't have been\n");
	}
}
#endif /* WIN32 */

START_TEST(test_pcap_findalldevs)
{
	pcap_if_t * devs = NULL;
	int a;

	LHIP_PROLOG_FOR_TEST();
	a = pcap_findalldevs (&devs, buf);
	if ( (a == 0) && (devs != NULL) )
	{
		pcap_freealldevs (devs);
		fail("test_pcap_findalldevs: device list read, but shouldn't have been\n");
	}
}
END_TEST
#endif /* (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H) */


/* ======================================================= */

static Suite * lhip_create_suite(void)
{
	Suite * s = suite_create("libhideip_pcap");

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	TCase * tests_pcap = tcase_create("pcap");

	tcase_add_test(tests_pcap, test_pcap_lookupdev);
	tcase_add_test(tests_pcap, test_pcap_lookupnet);
	tcase_add_test(tests_pcap, test_pcap_create);
	tcase_add_test(tests_pcap, test_pcap_open_dead);
	tcase_add_test(tests_pcap, test_pcap_open_dead_with_ts);
	tcase_add_test(tests_pcap, test_pcap_open_live);
	tcase_add_test(tests_pcap, test_pcap_open_offline);
	tcase_add_test(tests_pcap, test_pcap_open_offline_with_ts);
	tcase_add_test(tests_pcap, test_pcap_fopen_offline);
	tcase_add_test(tests_pcap, test_pcap_fopen_offline_with_ts);
#if (defined WIN32) || (defined _WIN32)
	tcase_add_test(tests_pcap, test_pcap_hopen_offline);
	tcase_add_test(tests_pcap, test_pcap_hopen_offline_with_ts);
# endif
	tcase_add_test(tests_pcap, test_pcap_findalldevs);

	tcase_set_timeout(tests_pcap, 30);

	suite_add_tcase(s, tests_pcap);
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
