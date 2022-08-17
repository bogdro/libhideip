/*
 * A library for hiding local IP address.
 *	-- unit test for network-related functions.
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif
#ifndef ENODEV
# define ENODEV 19
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
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

#ifdef HAVE_NETDB_H
# include <netdb.h>
#else
struct hostent
{
	char  *h_name;            /* official name of host */
	char **h_aliases;         /* alias list */
	int    h_addrtype;        /* host address type */
	int    h_length;          /* length of address */
	char **h_addr_list;       /* list of addresses */
};
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#else
# define	PF_NETLINK	16
# define	PF_ROUTE	PF_NETLINK /* Alias to emulate 4.4BSD.  */
# define	AF_NETLINK	PF_NETLINK
# define	AF_ROUTE	PF_ROUTE
struct iovec
{
	void *iov_base;	/* Pointer to data.  */
	size_t iov_len;	/* Length of data.  */
};

struct msghdr
{
	void         *msg_name;       /* optional address */
	socklen_t     msg_namelen;    /* size of address */
	struct iovec *msg_iov;        /* scatter/gather array */
	size_t        msg_iovlen;     /* # elements in msg_iov */
	void         *msg_control;    /* ancillary data, see below */
	socklen_t     msg_controllen; /* ancillary data buffer len */
	int           msg_flags;      /* flags on received message */
};
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
static in_addr_t addr;
static struct in6_addr addr6;
static struct sockaddr_in sa_in;
static struct sockaddr_in6 sa_in6;
#endif

static const unsigned char __lhip_localhost_ipv4[4] = {127, 0, 0, 1};
static const unsigned char __lhip_localhost_ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static char buf[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);

/* ====================== Network functions */

/**
 * Checks if the given IPv4 address is anonymized (contains 127.0.0.1)
 * @return 1 if OK
 */
static void verify_ipv4(void * addr4)
{
	if ( addr4 == NULL )
	{
		return;
	}
	if ( memcmp (addr4, __lhip_localhost_ipv4, sizeof (__lhip_localhost_ipv4)) == 0 )
	{
		return;
	}
	fail("IPv4 address contains something else than '127.0.0.1': '0x%x'\n", *((int *)addr4));
}

/**
 * Checks if the given IPv6 address is anonymized (contains ::1)
 * @return 1 if OK
 */
static void verify_ipv6(void * addr_ip6)
{
	if ( addr_ip6 == NULL )
	{
		return;
	}
	if ( memcmp (addr_ip6, __lhip_localhost_ipv6, sizeof (__lhip_localhost_ipv6)) == 0 )
	{
		return;
	}
	fail("IPv6 address contains something else than '::1': '0x%x'\n", *((int *)addr_ip6));
}

static void verify_addrinfo (struct addrinfo * ai)
{
	struct addrinfo * tmpa;
	size_t canonname_len;

	if (ai == NULL)
	{
		return;
	}

	tmpa = ai;
	while ( tmpa != NULL )
	{
		if (tmpa->ai_canonname != NULL)
		{
			canonname_len = strlen (tmpa->ai_canonname);
			if ((strncmp (tmpa->ai_canonname, "localhost",
					canonname_len) != 0)
				&& (strncmp (tmpa->ai_canonname, "127.0.0.1",
					     canonname_len) != 0)
				&& (strncmp (tmpa->ai_canonname, "::1",
					     canonname_len) != 0)
			)
			{
				fail("tmpa->ai_canonname contains something else than 'localhost', '127.0.0.1' and '::1': '%s'\n",
					tmpa->ai_canonname);
			}
		}
		if ( (tmpa->ai_family == AF_INET) && (tmpa->ai_addr != NULL) )
		{
			verify_ipv4 (&(((struct sockaddr_in *)(tmpa->ai_addr))->sin_addr));
		}
		else if ( (tmpa->ai_family == AF_INET6) && (tmpa->ai_addr != NULL) )
		{
			verify_ipv6 (&(((struct sockaddr_in6 *)(tmpa->ai_addr))->sin6_addr));
		}
		tmpa = tmpa->ai_next;
	}
}

#ifdef HAVE_NETDB_H

/**
 * Verify if the given hostent structure contains only neutral data (like 127.0.0.1)
 */
static void verify_hostent(struct hostent * h)
{
	int i;

	if (h == NULL)
	{
		return;
	}
	if (h->h_name != NULL)
	{
		if ( (strncmp (h->h_name, "localhost", strlen (h->h_name)) != 0)
			&& (strncmp (h->h_name, "localhost6", strlen (h->h_name)) != 0)
			&& (strncmp (h->h_name, "127.0.0.1", strlen (h->h_name)) != 0)
			&& (strncmp (h->h_name, "::1", strlen (h->h_name)) != 0)
		)
		{
			fail("h->h_name contains something else than a local hostname or IP: '%s'\n", h->h_name);
		}
	}
	if (h->h_aliases != NULL)
	{
		i = 0;
		while ( h->h_aliases[i] != NULL )
		{
			if ( (strncmp (h->h_aliases[i], "localhost", strlen (h->h_aliases[i])) != 0)
				&& (strncmp (h->h_aliases[i], "localhost6", strlen (h->h_aliases[i])) != 0)
				&& (strncmp (h->h_aliases[i], "127.0.0.1", strlen (h->h_aliases[i])) != 0)
				&& (strncmp (h->h_aliases[i], "::1", strlen (h->h_aliases[i])) != 0)
			)
			{
				fail("h->h_aliases[%d] contains something else than a local hostname or IP: '%s'\n",
				     i, h->h_aliases[i]);
			}
			i++;
		}
	}
	if ( (h->h_addrtype == AF_INET) && (h->h_addr_list != NULL) )
	{
		i = 0;
		while ( h->h_addr_list[i] != NULL )
		{
			verify_ipv4 (h->h_addr_list[i]);
			i++;
		}
	}
	else if ( (h->h_addrtype == AF_INET6) && (h->h_addr_list != NULL) )
	{
		i = 0;
		while ( h->h_addr_list[i] != NULL )
		{
			verify_ipv6 (h->h_addr_list[i]);
			i++;
		}
	}
}


START_TEST(test_gethostbyaddr)
{
	struct hostent * h;

	printf("test_gethostbyaddr\n");
	h = gethostbyaddr (&addr, 4, AF_INET);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST

START_TEST(test_gethostbyaddr6)
{
	struct hostent * h;

	printf("test_gethostbyaddr6\n");
	h = gethostbyaddr (&addr6, 16, AF_INET6);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST

# ifdef HAVE_GETHOSTBYADDR_R
START_TEST(test_gethostbyaddr_r)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostbyaddr_r\n");
	buf[0] = '\0';
	a = gethostbyaddr_r (&addr, 4, AF_INET,
		&res, buf, sizeof (buf), &tmp, &err);
	ck_assert_int_eq(a, 0);
	verify_hostent(&res);
}
END_TEST

START_TEST(test_gethostbyaddr_r6)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostbyaddr_r6\n");
	buf[0] = '\0';
	a = gethostbyaddr_r (&addr6, 16, AF_INET6,
		&res, buf, sizeof (buf), &tmp, &err);
	ck_assert_int_eq(a, 0);
	verify_hostent(&res);
}
END_TEST
# endif /* HAVE_GETHOSTBYADDR_R */

START_TEST(test_gethostbyname)
{
	struct hostent * h;

	printf("test_gethostbyname\n");
	h = gethostbyname ("www.google.com");
	fail_if(h == NULL);
}
END_TEST

START_TEST(test_gethostbyname_banned)
{
	struct hostent * h;

	printf("test_gethostbyname_banned\n");
	h = gethostbyname ("127.0.0.1");
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST

# ifdef HAVE_GETHOSTBYNAME_R
START_TEST(test_gethostbyname_r)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostbyname_r\n");
	buf[0] = '\0';
	a = gethostbyname_r ("www.google.com",
		&res, buf, sizeof (buf), &tmp, &err);
	ck_assert_int_eq(a, 0);
}
END_TEST

START_TEST(test_gethostbyname_r_banned)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostbyname_r_banned\n");
	buf[0] = '\0';
	a = gethostbyname_r ("127.0.0.1",
		&res, buf, sizeof (buf), &tmp, &err);
	ck_assert_int_eq(a, 0);
	verify_hostent(&res);
}
END_TEST
# endif /* HAVE_GETHOSTBYNAME_R */

START_TEST(test_gethostbyname2)
{
	struct hostent * h;

	printf("test_gethostbyname2\n");
	h = gethostbyname2 ("www.google.com", AF_INET);
	fail_if(h == NULL);
}
END_TEST

START_TEST(test_gethostbyname2_banned)
{
	struct hostent * h;

	printf("test_gethostbyname2_banned\n");
	h = gethostbyname2 ("127.0.0.1", AF_INET);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST

START_TEST(test_gethostbyname2_banned6)
{
	struct hostent * h;

	printf("test_gethostbyname2_banned6\n");
	h = gethostbyname2 ("::1", AF_INET6);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST

# ifdef HAVE_GETHOSTBYNAME2_R
START_TEST(test_gethostbyname2_r)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostbyname2_r\n");
	buf[0] = '\0';
	a = gethostbyname2_r ("www.google.com", AF_INET,
		&res, buf, sizeof (buf), &tmp, &err);
	ck_assert_int_eq(a, 0);
}
END_TEST

START_TEST(test_gethostbyname2_r_banned)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostbyname2_r_banned\n");
	buf[0] = '\0';
	a = gethostbyname2_r ("127.0.0.1", AF_INET,
		&res, buf, sizeof (buf), &tmp, &err);
	ck_assert_int_eq(a, 0);
	verify_hostent(&res);
}
END_TEST

START_TEST(test_gethostbyname2_r_banned6)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostbyname2_r_banned6\n");
	buf[0] = '\0';
	a = gethostbyname2_r ("::1", AF_INET6,
		&res, buf, sizeof (buf), &tmp, &err);
	ck_assert_int_eq(a, 0);
	verify_hostent(&res);
}
END_TEST
# endif /* HAVE_GETHOSTBYNAME2_R */

START_TEST(test_gethostent)
{
	struct hostent * h;

	printf("test_gethostent\n");
	h = gethostent ();
	if (h != NULL)
	{
		verify_hostent(h);
	}
}
END_TEST

# ifdef HAVE_GETHOSTENT_R
START_TEST(test_gethostent_r)
{
	int err;
	int a;
	struct hostent * tmp;
	struct hostent res;

	printf("test_gethostent_r\n");
	buf[0] = '\0';
	a = gethostent_r (&res, buf, sizeof (buf), &tmp, &err);
	if ((a == 0) && (tmp != NULL))
	{
		verify_hostent(&res);
	}
}
END_TEST
# endif /* HAVE_test_gethostent_rGETHOSTENT_R */

# ifdef HAVE_GETIPNODEBYADDR
START_TEST(test_getipnodebyaddr)
{
	struct hostent * h;
	int err;

	printf("test_getipnodebyaddr\n");
	h = getipnodebyaddr (&addr, 4, AF_INET, &err);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST

START_TEST(test_getipnodebyaddr6)
{
	struct hostent * h;
	int err;

	printf("test_getipnodebyaddr6\n");
	h = getipnodebyaddr (&addr6, 16, AF_INET6, &err);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST
# endif /* HAVE_GETIPNODEBYADDR */

# ifdef HAVE_GETIPNODEBYNAME
START_TEST(test_getipnodebyname)
{
	struct hostent * h;
	int err;

	printf("test_getipnodebyname\n");
	h = getipnodebyname ("127.0.0.1", AF_INET, 0, &err);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST

START_TEST(test_getipnodebyname6)
{
	struct hostent * h;
	int err;

	printf("test_getipnodebyname6\n");
	h = getipnodebyname ("::1", AF_INET6, 0, &err);
	fail_if(h == NULL);
	verify_hostent(h);
}
END_TEST
# endif /* HAVE_GETIPNODEBYNAME */

#ifdef HAVE_SYS_SOCKET_H
START_TEST(test_getnameinfo)
{
	int a;

	printf("test_getnameinfo\n");
	buf[0] = '\0';
	a = getnameinfo ((struct sockaddr*)&sa_in, sizeof (struct sockaddr_in),
		buf, sizeof (buf), NULL, 0, 0);
	ck_assert_int_eq(a, 0);
	if (strncmp (buf, "localhost", strlen (buf)) != 0)
	{
		fail("buf contains something else than 'localhost': '%s'\n", buf);
	}
}
END_TEST

START_TEST(test_getaddrinfo)
{
	int a;
	struct addrinfo * addrinfo_all = NULL;
	struct addrinfo ai_hints;

	printf("test_getaddrinfo\n");
	memset (&ai_hints, 0, sizeof (struct addrinfo));
	ai_hints.ai_flags = /*AI_NUMERICHOST |*/ AI_CANONNAME;
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = 0;
	ai_hints.ai_protocol = 0;
	ai_hints.ai_addr = NULL;
	ai_hints.ai_canonname = NULL;
	ai_hints.ai_next = NULL;
	a = getaddrinfo ("www.google.com", NULL /* service */,
		&ai_hints, &addrinfo_all);
	ck_assert_int_eq(a, 0);
	fail_if(addrinfo_all == NULL);
}
END_TEST

START_TEST(test_getaddrinfo_banned)
{
	int a;
	struct addrinfo * addrinfo_all = NULL;
	struct addrinfo ai_hints;

	printf("test_getaddrinfo_banned\n");
	memset (&ai_hints, 0, sizeof (struct addrinfo));
	ai_hints.ai_flags = /*AI_NUMERICHOST |*/ AI_CANONNAME;
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = 0;
	ai_hints.ai_protocol = 0;
	ai_hints.ai_addr = NULL;
	ai_hints.ai_canonname = NULL;
	ai_hints.ai_next = NULL;
	a = getaddrinfo ("127.0.0.1", NULL /* service */,
		&ai_hints, &addrinfo_all);
	ck_assert_int_eq(a, 0);
	if ( addrinfo_all != NULL )
	{
		verify_addrinfo (addrinfo_all);
	}
}
END_TEST

START_TEST(test_getaddrinfo_banned6)
{
	int a;
	struct addrinfo * addrinfo_all = NULL;
	struct addrinfo ai_hints;

	printf("test_getaddrinfo_banned6\n");
	memset (&ai_hints, 0, sizeof (struct addrinfo));
	ai_hints.ai_flags = /*AI_NUMERICHOST |*/ AI_CANONNAME;
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = 0;
	ai_hints.ai_protocol = 0;
	ai_hints.ai_addr = NULL;
	ai_hints.ai_canonname = NULL;
	ai_hints.ai_next = NULL;
	a = getaddrinfo ("::1", NULL /* service */,
		&ai_hints, &addrinfo_all);
	ck_assert_int_eq(a, 0);
	if ( addrinfo_all != NULL )
	{
		verify_addrinfo (addrinfo_all);
	}
}
END_TEST
#endif /* HAVE_SYS_SOCKET_H */

#endif /* HAVE_NETDB_H */

#ifdef HAVE_IFADDRS_H
START_TEST(test_getifaddrs)
{
	int a;
	struct ifaddrs * ifa;
	struct ifaddrs * c;

	printf("test_getifaddrs\n");
	a = getifaddrs (&ifa);
	ck_assert_int_eq(a, 0);
	c = ifa;
	while (c != NULL)
	{
		if ( c->ifa_addr == NULL )
		{
			c = c->ifa_next;
			continue;
		}
		if ( c->ifa_addr->sa_family == AF_INET )
		{
			verify_ipv4 (&(((struct sockaddr_in *)(c->ifa_addr))->sin_addr));
		}
		else if ( c->ifa_addr->sa_family == AF_INET6 )
		{
			verify_ipv6 (&(((struct sockaddr_in6 *)(c->ifa_addr))->sin6_addr));
		}
		c = c->ifa_next;
	}
}
END_TEST
#endif /* HAVE_IFADDRS_H */

#ifdef HAVE_SYS_SOCKET_H
START_TEST(test_socket_inet)
{
	int a;

	printf("test_socket_inet\n");
	a = socket (AF_INET, SOCK_STREAM, 0);
	if ( a >= 0 )
	{
		close (a);
	}
	else
	{
		fail("test_socket_inet: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socket_unix)
{
	int a;

	printf("test_socket_unix\n");
	a = socket (AF_UNIX, SOCK_STREAM, 0);
	if ( a >= 0 )
	{
		close (a);
	}
	else
	{
		fail("test_socket_unix: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socket_inet6)
{
	int a;

	printf("test_socket_inet6\n");
	a = socket (AF_INET6, SOCK_STREAM, 0);
	if ( a >= 0 )
	{
		close (a);
	}
	else
	{
		fail("test_socket_inet6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socket_banned_netlink)
{
	int a;

	printf("test_socket_banned_netlink\n");
	a = socket (AF_NETLINK, SOCK_STREAM, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_netlink: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_raw)
{
	int a;

	printf("test_socket_banned_raw\n");
	a = socket (AF_INET, SOCK_RAW, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_raw: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_raw6)
{
	int a;

	printf("test_socket_banned_raw6\n");
	a = socket (AF_INET6, SOCK_RAW, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_raw6: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_recvmsg)
{
	ssize_t a;

	printf("test_recvmsg\n");
	a = recvmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_recvmsg: data received, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_sendmsg)
{
	ssize_t a;

	printf("test_sendmsg\n");
	a = sendmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_sendmsg: data sent, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_getsockname)
{
	int a;
	int sock;
	socklen_t sa;

	printf("test_getsockname\n");
	sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( sock >= 0 )
	{
		sa = sizeof (sa_in);
		a = getsockname (sock, (struct sockaddr*)&sa_in, &sa);
		close (sock);
		if ( a >= 0 )
		{
			if ( sa_in.sin_family == AF_INET )
			{
				verify_ipv4 (&(((struct sockaddr_in *)(&sa_in))->sin_addr));
			}
			else if ( sa_in.sin_family == AF_INET6 )
			{
				verify_ipv6 (&(((struct sockaddr_in6 *)(&sa_in))->sin6_addr));
			}
		}
		else
		{
			fail("test_getsockname: socket name not read\n");
		}
	}
	else
	{
		fail("test_getsockname: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_getsockname6)
{
	int a;
	int sock;
	socklen_t sa;

	printf("test_getsockname6\n");
	sock = socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if ( sock >= 0 )
	{
		sa = sizeof (sa_in);
		a = getsockname (sock, (struct sockaddr*)&sa_in, &sa);
		close (sock);
		if ( a >= 0 )
		{
			if ( sa_in.sin_family == AF_INET )
			{
				verify_ipv4 (&(((struct sockaddr_in *)(&sa_in))->sin_addr));
			}
			else if ( sa_in.sin_family == AF_INET6 )
			{
				verify_ipv6 (&(((struct sockaddr_in6 *)(&sa_in))->sin6_addr));
			}
		}
		else
		{
			fail("test_getsockname6: socket name not read\n");
		}
	}
	else
	{
		fail("test_getsockname6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_bind)
{
	int a;
	int sock;
	int err;

	printf("test_bind\n");
	sock = socket (AF_INET, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa_in.sin_family = AF_INET;
		sa_in.sin_addr.s_addr = inet_addr ("0.0.0.0");
		sa_in.sin_port = 5553;
		a = bind (sock, (struct sockaddr*)&sa_in, sizeof (struct sockaddr_in));
		err = errno;
		close (sock);
		if ( a < 0 )
		{
			fail("test_bind: socket not bound, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_bind: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_bind6)
{
	int a;
	int sock;
	int err;
	const unsigned char zero_ipv6[16]
		= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	printf("test_bind6\n");
	sock = socket (AF_INET6, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa_in6.sin6_family = AF_INET6;
		memcpy (&(sa_in6.sin6_addr.s6_addr), zero_ipv6,
			sizeof (zero_ipv6));
		sa_in6.sin6_port = 5553;
		a = bind (sock, (struct sockaddr*)&sa_in6,
			sizeof (struct sockaddr_in6));
		err = errno;
		close (sock);
		if ( a < 0 )
		{
			fail("test_bind6: socket not bound, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_bind6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_bind_banned)
{
	int a;
	int sock;

	printf("test_bind_banned\n");
	sock = socket (AF_INET, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa_in.sin_family = AF_INET;
		sa_in.sin_addr.s_addr = inet_addr ("192.168.1.250");
		sa_in.sin_port = 5553;
		a = bind (sock, (struct sockaddr*)&sa_in, sizeof (struct sockaddr_in));
		close (sock);
		if ( a >= 0 )
		{
			fail("test_bind_banned: socket bound, but shouldn't have been\n");
		}
	}
	else
	{
		fail("test_bind_banned: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_bind_banned6)
{
	int a;
	int sock;
	const unsigned char addr_ipv6[16]
		= {0x20, 0x02, 0xc0, 0xa8, 0xc0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	printf("test_bind_banned6\n");
	sock = socket (AF_INET6, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa_in6.sin6_family = AF_INET6;
		memcpy (&(sa_in6.sin6_addr.s6_addr), addr_ipv6,
			sizeof (addr_ipv6));
		sa_in6.sin6_port = 5553;
		a = bind (sock, (struct sockaddr*)&sa_in6,
			sizeof (struct sockaddr_in6));

		close (sock);
		if ( a >= 0 )
		{
			fail("test_bind_banned6: socket bound, but shouldn't have been\n");
		}
	}
	else
	{
		fail("test_bind_banned6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socketpair)
{
	int twosocks[2];
	int a;

	printf("test_socketpair\n");
	a = socketpair (AF_UNIX, SOCK_STREAM, 0, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
	}
	else
	{
		fail("test_socket_banned: socketpair not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socketpair_banned_netlink)
{
	int twosocks[2];
	int a;

	printf("test_socketpair_banned_netlink\n");
	a = socketpair (AF_NETLINK, SOCK_STREAM, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned_netlink: socketpair opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	if (errno != EPERM)
	{
		fail("test_socketpair_banned_netlink: socketpair not opened, but errno not EPERM: errno=%d\n", errno);
	}
# endif
}
END_TEST

START_TEST(test_socketpair_banned_raw)
{
	int twosocks[2];
	int a;

	printf("test_socketpair_banned_raw\n");
	a = socketpair (AF_INET, SOCK_RAW, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned_raw: socketpair opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	if (errno != EPERM)
	{
		fail("test_socketpair_banned_raw: socketpair not opened, but errno not EPERM: errno=%d\n", errno);
	}
# endif
}
END_TEST

START_TEST(test_socketpair_banned_packet)
{
	int twosocks[2];
	int a;

	printf("test_socketpair_banned_packet\n");
# ifdef SOCK_PACKET
	a = socketpair (AF_INET, SOCK_PACKET, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned_packet: socketpair opened, but shouldn't have been\n");
	}
#  ifdef HAVE_ERRNO_H
	if (errno != EPERM)
	{
		fail("test_socketpair_banned_packet: socketpair not opened, but errno not EPERM: errno=%d\n", errno);
	}
#  endif
# endif /* SOCK_PACKET */
}
END_TEST

START_TEST(test_getsockopt)
{
	int a;
	int sock;
	int err = 10;
	socklen_t sa = sizeof (int);

	printf("test_getsockopt\n");
	sock = socket (AF_INET, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		a = getsockopt (sock, SOL_IP, IP_TTL, &err, &sa);
		err = errno;
		close (sock);
		if ( a < 0 )
		{
			fail("test_getsockopt: socket option not read, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_getsockopt: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_getsockopt6)
{
	int a;
	int sock;
	int err = 10;
	socklen_t sa = sizeof (int);

	printf("test_getsockopt6\n");
	sock = socket (AF_INET6, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		a = getsockopt (sock, SOL_IP, IP_TTL, &err, &sa);
		err = errno;
		close (sock);
		if ( a < 0 )
		{
			fail("test_getsockopt6: socket option not read, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_getsockopt6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_getsockopt_banned)
{
	int a;
	int sock;
	socklen_t sa;

	printf("test_getsockopt_banned\n");
	sock = socket (AF_INET, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		/*sa_in.sin_addr.s_addr = inet_addr ("127.0.0.1");*/
		sa = sizeof (addr);
		a = getsockopt (sock, SOL_IP, IP_PKTINFO, &addr, &sa);
		close (sock);
		if ( a >= 0 )
		{
			fail("test_getsockopt_banned: socket option read, but shouldn't have been\n");
		}
	}
	else
	{
		fail("test_getsockopt_banned: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_getsockopt_banned6)
{
	int a;
	int sock;
	socklen_t sa;

	printf("test_getsockopt_banned6\n");
	sock = socket (AF_INET6, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa = sizeof (addr6);
		a = getsockopt (sock, SOL_IP, IP_PKTINFO, &addr6, &sa);
		close (sock);
		if ( a >= 0 )
		{
			fail("test_getsockopt_banned6: socket option read, but shouldn't have been\n");
		}
	}
	else
	{
		fail("test_getsockopt_banned6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_setsockopt)
{
	int a;
	int sock;
	int err = 10;

	printf("test_setsockopt\n");
	sock = socket (AF_INET, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		a = setsockopt (sock, SOL_IP, IP_TTL, &err, sizeof(int));
		err = errno;
		close (sock);
		if ( a < 0 )
		{
			fail("test_setsockopt: socket option not set, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_setsockopt: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_setsockopt6)
{
	int a;
	int sock;
	int err = 10;

	printf("test_setsockopt6\n");
	sock = socket (AF_INET6, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		a = setsockopt (sock, SOL_IP, IP_TTL, &err, sizeof(int));
		err = errno;
		close (sock);
		if ( a < 0 )
		{
			fail("test_setsockopt6: socket option not set, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_setsockopt6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_setsockopt_banned)
{
	int a;
	int sock;
	socklen_t sa;

	printf("test_setsockopt_banned\n");
	sock = socket (AF_INET, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa = sizeof (addr);
		a = setsockopt (sock, SOL_IP, IP_PKTINFO, &addr, sa);
		close (sock);
		if ( a >= 0 )
		{
			fail("test_setsockopt_banned: socket option set, but shouldn't have been\n");
		}
	}
	else
	{
		fail("test_setsockopt_banned: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_setsockopt_banned6)
{
	int a;
	int sock;
	socklen_t sa;

	printf("test_setsockopt_banned6\n");
	sock = socket (AF_INET6, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa = sizeof (addr6);
		a = setsockopt (sock, SOL_IP, IP_PKTINFO, &addr6, sa);
		close (sock);
		if ( a >= 0 )
		{
			fail("test_setsockopt_banned6: socket option set, but shouldn't have been\n");
		}
	}
	else
	{
		fail("test_setsockopt_banned6: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_UNISTD_H
# ifndef LHIP_ENABLE_GUI_APPS
START_TEST(test_gethostname)
{
	int a;

	printf("test_gethostname\n");
	a = gethostname (buf, sizeof(buf));
	ck_assert_int_eq(a, 0);
	if (buf != NULL)
	{
		if (strncmp (buf, "localhost", strlen (buf)) != 0)
		{
			fail("test_gethostname: buf contains something else than 'localhost': '%s'\n", buf);
		}
	}
}
END_TEST
# endif /* ! LHIP_ENABLE_GUI_APPS */
#endif /* HAVE_UNISTD_H */

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

static void setup_net_test(void) /* checked */
{
#ifdef HAVE_SYS_SOCKET_H
	const unsigned char localhost_ipv6[16]
		= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

	addr = inet_addr ("127.0.0.1");
	sa_in.sin_addr.s_addr = inet_addr ("127.0.0.1");
	sa_in.sin_family = AF_INET;
	sa_in.sin_port = 53;

	memcpy (&(addr6.s6_addr), localhost_ipv6, sizeof (localhost_ipv6));
	memcpy (&(sa_in6.sin6_addr.s6_addr), localhost_ipv6, sizeof (localhost_ipv6));
	sa_in6.sin6_family = AF_INET6;
	sa_in6.sin6_port = 53;
#endif
}

static void teardown_net_test(void)
{

}

static Suite * lhip_create_suite(void)
{
	Suite * s = suite_create("libhideip");

	TCase * tests_net = tcase_create("net");

#ifdef HAVE_NETDB_H
	tcase_add_test(tests_net, test_gethostbyaddr);
	tcase_add_test(tests_net, test_gethostbyaddr6);
# ifdef HAVE_GETHOSTBYADDR_R
	tcase_add_test(tests_net, test_gethostbyaddr_r);
	tcase_add_test(tests_net, test_gethostbyaddr_r6);
# endif
	tcase_add_test(tests_net, test_gethostbyname);
	tcase_add_test(tests_net, test_gethostbyname_banned);
# ifdef HAVE_GETHOSTBYNAME_R
	tcase_add_test(tests_net, test_gethostbyname_r);
	tcase_add_test(tests_net, test_gethostbyname_r_banned);
# endif
	tcase_add_test(tests_net, test_gethostbyname2);
	tcase_add_test(tests_net, test_gethostbyname2_banned);
	tcase_add_test(tests_net, test_gethostbyname2_banned6);
# ifdef HAVE_GETHOSTBYNAME2_R
	tcase_add_test(tests_net, test_gethostbyname2_r);
	tcase_add_test(tests_net, test_gethostbyname2_r_banned);
	tcase_add_test(tests_net, test_gethostbyname2_r_banned6);
# endif
	tcase_add_test(tests_net, test_gethostent);
# ifdef HAVE_GETHOSTENT_R
	tcase_add_test(tests_net, test_gethostent_r);
# endif
# ifdef HAVE_GETIPNODEBYADDR
	tcase_add_test(tests_net, test_getipnodebyaddr);
	tcase_add_test(tests_net, test_getipnodebyaddr6);
# endif
# ifdef HAVE_GETIPNODEBYNAME
	tcase_add_test(tests_net, test_getipnodebyname);
	tcase_add_test(tests_net, test_getipnodebyname6);
# endif
# ifdef HAVE_SYS_SOCKET_H
	tcase_add_test(tests_net, test_getnameinfo);
	tcase_add_test(tests_net, test_getaddrinfo);
	tcase_add_test(tests_net, test_getaddrinfo_banned);
	tcase_add_test(tests_net, test_getaddrinfo_banned6);
# endif
#endif /* HAVE_NETDB_H */
#ifdef HAVE_IFADDRS_H
	tcase_add_test(tests_net, test_getifaddrs);
#endif
#ifdef HAVE_SYS_SOCKET_H
	tcase_add_test(tests_net, test_socket_inet);
	tcase_add_test(tests_net, test_socket_unix);
	tcase_add_test(tests_net, test_socket_inet6);
	tcase_add_test(tests_net, test_socket_banned_netlink);
	tcase_add_test(tests_net, test_socket_banned_raw);
	tcase_add_test(tests_net, test_socket_banned_raw6);
	tcase_add_test(tests_net, test_recvmsg);
	tcase_add_test(tests_net, test_sendmsg);
	tcase_add_test(tests_net, test_getsockname);
	tcase_add_test(tests_net, test_getsockname6);
	tcase_add_test(tests_net, test_bind);
	tcase_add_test(tests_net, test_bind6);
	tcase_add_test(tests_net, test_bind_banned);
	tcase_add_test(tests_net, test_bind_banned6);
	tcase_add_test(tests_net, test_socketpair);
	tcase_add_test(tests_net, test_socketpair_banned_netlink);
	tcase_add_test(tests_net, test_socketpair_banned_raw);
	tcase_add_test(tests_net, test_socketpair_banned_packet);
	tcase_add_test(tests_net, test_getsockopt);
	tcase_add_test(tests_net, test_getsockopt6);
	tcase_add_test(tests_net, test_getsockopt_banned);
	tcase_add_test(tests_net, test_getsockopt_banned6);
	tcase_add_test(tests_net, test_setsockopt);
	tcase_add_test(tests_net, test_setsockopt6);
	tcase_add_test(tests_net, test_setsockopt_banned);
	tcase_add_test(tests_net, test_setsockopt_banned6);
#endif
#ifdef HAVE_UNISTD_H
# ifndef LHIP_ENABLE_GUI_APPS
	tcase_add_test(tests_net, test_gethostname);
# endif
#endif

/* ====================== */

	tcase_add_checked_fixture(tests_net, &setup_net_test, &teardown_net_test);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_net, 30);

	suite_add_tcase(s, tests_net);

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
