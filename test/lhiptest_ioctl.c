/*
 * A library for hiding local IP address.
 *	-- unit test for I/O CTL functions.
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

#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#else
# define IFF_BROADCAST 0x2
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
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

static char buf[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);
static const unsigned char __lhip_localhost_ipv4[4] = {127, 0, 0, 1};
static const unsigned char __lhip_localhost_ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const unsigned char __lhip_fake_mac[6] = {1, 2, 3, 4, 5, 6};

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

/**
 * Checks if the given MAC address is anonymized (contains 01:02:03:04:05:06)
 * @return 1 if OK
 */
static void verify_mac(void * macaddr)
{
	if ( macaddr == NULL )
	{
		return;
	}
	if ( memcmp (macaddr, __lhip_fake_mac, sizeof (__lhip_fake_mac)) == 0 )
	{
		return;
	}
	fail("MAC address contains something else than '01:02:03:04:05:06': '0x%x'\n", *((int *)macaddr));
}

/* ====================== I/O CTL functions */

#ifdef HAVE_SYS_IOCTL_H
START_TEST(test_ioctl)
{
	int fd;
	int a;
	int err;
	printf("test_ioctl\n");
	fd = open("/dev/ttyS0", O_RDONLY);
	if ( fd >= 0 )
	{
# define TCGETS 0x5401
		a = ioctl(fd, TCGETS, buf);
		err = errno;
		close(fd);
		if ( a < 0 )
		{
			fail("test_ioctl: ioctl not performed, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_ioctl: device not opened: errno=%d\n", errno);
	}
}
END_TEST

# ifdef SIOCGIFADDR
START_TEST(test_ioctl_banned1)
{
	int fd;
	int a;
	int err;
	struct ifreq reqs;

	printf("test_ioctl_banned1: SIOCGIFADDR\n");
	fd = socket (AF_INET, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(reqs.ifr_name, "eth0", sizeof(reqs.ifr_name));
		reqs.ifr_name[sizeof(reqs.ifr_name)-1] = '\0';
		a = ioctl(fd, SIOCGIFADDR, &reqs);
		if ( a < 0 )
		{
			err = errno;
			if ( errno == ENODEV )
			{
				/* device not found - try another default */
				strncpy(reqs.ifr_name, "eno1", sizeof(reqs.ifr_name));
				reqs.ifr_name[sizeof(reqs.ifr_name)-1] = '\0';
				a = ioctl(fd, SIOCGIFADDR, &reqs);
				if ( a < 0 )
				{
					err = errno;
					close(fd);
					fail("test_ioctl_banned1: SIOCGIFADDR: ioctl not performed, but should have been: errno=%d\n", err);
				}
			}
			else
			{
				close(fd);
				fail("test_ioctl_banned1: SIOCGIFADDR: ioctl not performed, but should have been (2): errno=%d\n", err);
			}
		}
		if ( reqs.ifr_ifru.ifru_addr.sa_family == AF_INET )
		{
			verify_ipv4 (&(((struct sockaddr_in *)
				&(reqs.ifr_addr))->sin_addr));
		}
		else if ( reqs.ifr_ifru.ifru_addr.sa_family == AF_INET6 )
		{
			verify_ipv6 (&(((struct sockaddr_in6 *)
				&(reqs.ifr_addr))->sin6_addr));
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned1: SIOCGIFADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST

/*
Many sources say that SIOCGIFADDR is only for IPv4
START_TEST(test_ioctl_banned1_ipv6)
{
	int fd;
	int a;
	int err;
	struct ifreq reqs;

	printf("test_ioctl_banned1_ipv6: SIOCGIFADDR\n");
	fd = socket (AF_INET6, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(reqs.ifr_name, "eth0", sizeof(reqs.ifr_name));
		reqs.ifr_name[sizeof(reqs.ifr_name)-1] = '\0';
/ * doesn't help:
err = 1;
a = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &err, sizeof(err));
* /
		a = ioctl(fd, SIOCGIFADDR, &reqs);
		if ( a < 0 )
		{
			err = errno;
			close(fd);
			fail("test_ioctl_banned1_ipv6: SIOCGIFADDR: ioctl not performed, but should have been: errno=%d\n", err);
		}
		if ( reqs.ifr_ifru.ifru_addr.sa_family == AF_INET )
		{
			verify_ipv4 (&(((struct sockaddr_in *)
				&(reqs.ifr_addr))->sin_addr));
		}
		else if ( reqs.ifr_ifru.ifru_addr.sa_family == AF_INET6 )
		{
			verify_ipv6 (&(((struct sockaddr_in6 *)
				&(reqs.ifr_addr))->sin6_addr));
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned1_ipv6: SIOCGIFADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST
*/
# endif

# if (defined SIOCGIFCONF) && (defined HAVE_MALLOC)
START_TEST(test_ioctl_banned2)
{
	int fd;
	int a;
	int err;
	struct ifconf cfg;
	size_t buf_index;
	unsigned int req_index;
	struct ifreq * addrs;

	printf("test_ioctl_banned2: SIOCGIFCONF\n");
	fd = socket (AF_INET, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		cfg.ifc_len = 100 * sizeof (struct ifreq);
		cfg.ifc_req = (struct ifreq *) malloc ((size_t) cfg.ifc_len);
		if ( cfg.ifc_req != NULL )
		{
			memset (cfg.ifc_req, 0, (size_t) cfg.ifc_len);
			a = ioctl(fd, SIOCGIFCONF, &cfg);
			if ( a < 0 )
			{
				err = errno;
				close(fd);
				free (cfg.ifc_req);
				fail("test_ioctl_banned2: SIOCGIFCONF: ioctl not performed, but should have been: errno=%d\n", err);
			}
			if ( cfg.ifc_len > 0 )
			{
				buf_index = 0;
				req_index = 0;
				while ( buf_index <= (unsigned int)cfg.ifc_len )
				{
					addrs = (struct ifreq *) &(cfg.ifc_req[req_index]);
					if ( addrs != NULL )
					{
						if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET )
						{
							verify_ipv4 (&(((struct sockaddr_in *)
								&(addrs->ifr_addr))->sin_addr));
						}
						else if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET6 )
						{
							verify_ipv6 (&(((struct sockaddr_in6 *)
								&(addrs->ifr_addr))->sin6_addr));
						}
						buf_index += sizeof (struct ifreq);
					}
					else
					{
						break;
					}
					req_index++;
				}
			}
			free (cfg.ifc_req);
		}
		else
		{
			fail("test_ioctl_banned2: SIOCGIFCONF: memory NOT allocated\n");
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned2: SIOCGIFCONF: socket not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_ioctl_banned2_ipv6)
{
	int fd;
	int a;
	int err;
	struct ifconf cfg;
	size_t buf_index;
	unsigned int req_index;
	struct ifreq * addrs;

	printf("test_ioctl_banned2_ipv6: SIOCGIFCONF\n");
	fd = socket (AF_INET6, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		cfg.ifc_len = 100 * sizeof (struct ifreq);
		cfg.ifc_req = (struct ifreq *) malloc ((size_t) cfg.ifc_len);
		if ( cfg.ifc_req != NULL )
		{
			memset (cfg.ifc_req, 0, (size_t) cfg.ifc_len);
			a = ioctl(fd, SIOCGIFCONF, &cfg);
			if ( a < 0 )
			{
				err = errno;
				close(fd);
				free (cfg.ifc_req);
				fail("test_ioctl_banned2_ipv6: SIOCGIFCONF: ioctl not performed, but should have been: errno=%d\n", err);
			}
			if ( cfg.ifc_len > 0 )
			{
				buf_index = 0;
				req_index = 0;
				while ( buf_index <= (unsigned int)cfg.ifc_len )
				{
					addrs = (struct ifreq *) &(cfg.ifc_req[req_index]);
					if ( addrs != NULL )
					{
						if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET )
						{
							verify_ipv4 (&(((struct sockaddr_in *)
								&(addrs->ifr_addr))->sin_addr));
						}
						else if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET6 )
						{
							verify_ipv6 (&(((struct sockaddr_in6 *)
								&(addrs->ifr_addr))->sin6_addr));
						}
						buf_index += sizeof (struct ifreq);
					}
					else
					{
						break;
					}
					req_index++;
				}
			}
			free (cfg.ifc_req);
		}
		else
		{
			fail("test_ioctl_banned2_ipv6: SIOCGIFCONF: memory NOT allocated\n");
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned2_ipv6: SIOCGIFCONF: socket not opened: errno=%d\n", errno);
	}
}
END_TEST
# endif /* (defined SIOCGIFCONF) && (defined HAVE_MALLOC) */

# ifdef SIOCGIFHWADDR
START_TEST(test_ioctl_banned3)
{
	int fd;
	int a;
	int err;
	struct ifreq reqs;

	printf("test_ioctl_banned3: SIOCGIFHWADDR\n");
	fd = socket (AF_INET, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(reqs.ifr_name, "eth0", sizeof(reqs.ifr_name));
		reqs.ifr_name[sizeof(reqs.ifr_name)-1] = '\0';
		a = ioctl(fd, SIOCGIFHWADDR, &reqs);
		if ( a < 0 )
		{
			err = errno;
			if ( errno == ENODEV )
			{
				/* device not found - try another default */
				strncpy(reqs.ifr_name, "eno1", sizeof(reqs.ifr_name));
				reqs.ifr_name[sizeof(reqs.ifr_name)-1] = '\0';
				a = ioctl(fd, SIOCGIFHWADDR, &reqs);
				if ( a < 0 )
				{
					err = errno;
					close(fd);
					fail("test_ioctl_banned3: SIOCGIFHWADDR: ioctl not performed, but should have been: errno=%d\n", err);
				}
			}
			else
			{
				close(fd);
				fail("test_ioctl_banned3: SIOCGIFHWADDR: ioctl not performed, but should have been (2): errno=%d\n", err);
			}
		}
		verify_mac (&(reqs.ifr_addr.sa_data));
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned3: SIOCGIFHWADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_ioctl_banned3_ipv6)
{
	int fd;
	int a;
	int err;
	struct ifreq reqs;

	printf("test_ioctl_banned3_ipv6: SIOCGIFHWADDR\n");
	fd = socket (AF_INET6, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(reqs.ifr_name, "eth0", sizeof(reqs.ifr_name));
		reqs.ifr_name[sizeof(reqs.ifr_name)-1] = '\0';
		a = ioctl(fd, SIOCGIFHWADDR, &reqs);
		if ( a < 0 )
		{
			err = errno;
			if ( errno == ENODEV )
			{
				/* device not found - try another default */
				strncpy(reqs.ifr_name, "eno1", sizeof(reqs.ifr_name));
				reqs.ifr_name[sizeof(reqs.ifr_name)-1] = '\0';
				a = ioctl(fd, SIOCGIFHWADDR, &reqs);
				if ( a < 0 )
				{
					err = errno;
					close(fd);
					fail("test_ioctl_banned3_ipv6: SIOCGIFHWADDR: ioctl not performed, but should have been: errno=%d\n", err);
				}
			}
			else
			{
				close(fd);
				fail("test_ioctl_banned3_ipv6: SIOCGIFHWADDR: ioctl not performed, but should have been (2): errno=%d\n", err);
			}
		}
		verify_mac (&(reqs.ifr_addr.sa_data));
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned3_ipv6: SIOCGIFHWADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST
# endif

/*#define LHIP_COMPILE_TEST*/

#ifdef LHIP_COMPILE_TEST
# define SIOCGLIFADDR 1
# define SIOCGLIFHWADDR 1
# define SIOCGLIFCONF 1
# define __solaris__ 1
struct lifreq
{
# define IFHWADDRLEN	6
# define IFNAMSIZ	IF_NAMESIZE
	union
	{
		char lifr_name[IFNAMSIZ];	/* Interface name, e.g. "en0".  */
	} lifr_ifrn;

	union
	{
		struct sockaddr lifr_addr;
		struct sockaddr lifr_dstaddr;
		struct sockaddr lifr_broadaddr;
		struct sockaddr lifr_netmask;
		struct sockaddr lifr_hwaddr;
		short int lifr_flags;
		int lifr_ivalue;
		int lifr_mtu;
		struct ifmap lifr_map;
		char lifr_slave[IFNAMSIZ];	/* Just fits the size */
		char lifr_newname[IFNAMSIZ];
		__caddr_t lifr_data;
	} lifr_ifru;
};

# define lifr_name        lifr_ifrn.lifr_name      /* interface name       */
# define lifr_addr        lifr_ifru.lifr_addr      /* address              */

struct lifconf
{
	int	lifc_len;			/* Size of buffer.  */
	union
	{
		__caddr_t lifc_buf;
		struct lifreq *lifc_req;
	} lifc_ifcu;
};
# define lifc_buf lifc_ifcu.lifc_buf               /* buffer address       */
# define lifc_req lifc_ifcu.lifc_req               /* array of structures  */

#endif /* LHIP_COMPILE_TEST */

# if (defined SIOCGLIFADDR) && (defined __solaris__) && (defined AF_INET6)
START_TEST(test_ioctl_banned4)
{
	int fd;
	int a;
	int err;
	struct lifreq lreqs;

	printf("test_ioctl_banned4: SIOCGLIFADDR\n");
	fd = socket (AF_INET, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(lreqs.lifr_name, "eth0", sizeof(lreqs.lifr_name));
		lreqs.lifr_name[sizeof(lreqs.lifr_name)-1] = '\0';
		a = ioctl(fd, SIOCGLIFADDR, &lreqs);
		if ( a < 0 )
		{
			err = errno;
			close(fd);
			fail("test_ioctl_banned4: SIOCGLIFADDR: ioctl not performed, but should have been: errno=%d\n", err);
		}
		if ( lreqs.lifr_addr.sa_family == AF_INET )
		{
			verify_ipv4 (&(((struct sockaddr_in *)
				&(lreqs.lifr_addr))->sin_addr));
		}
		else if ( lreqs.lifr_addr.sa_family == AF_INET6 )
		{
			verify_ipv6 (&(((struct sockaddr_in6 *)
				&(lreqs.lifr_addr))->sin6_addr));
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned4: SIOCGLIFADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_ioctl_banned4_ipv6)
{
	int fd;
	int a;
	int err;
	struct lifreq lreqs;

	printf("test_ioctl_banned4_ipv6: SIOCGLIFADDR\n");
	fd = socket (AF_INET6, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(lreqs.lifr_name, "eth0", sizeof(lreqs.lifr_name));
		lreqs.lifr_name[sizeof(lreqs.lifr_name)-1] = '\0';
		a = ioctl(fd, SIOCGLIFADDR, &lreqs);
		if ( a < 0 )
		{
			err = errno;
			close(fd);
			fail("test_ioctl_banned4_ipv6: SIOCGLIFADDR: ioctl not performed, but should have been: errno=%d\n", err);
		}
		if ( lreqs.lifr_addr.sa_family == AF_INET )
		{
			verify_ipv4 (&(((struct sockaddr_in *)
				&(lreqs.lifr_addr))->sin_addr));
		}
		else if ( lreqs.lifr_addr.sa_family == AF_INET6 )
		{
			verify_ipv6 (&(((struct sockaddr_in6 *)
				&(lreqs.lifr_addr))->sin6_addr));
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned4_ipv6: SIOCGLIFADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST
# endif /* #if (defined SIOCGLIFADDR) && (defined __solaris__) && (defined AF_INET6) */

# if (defined SIOCGLIFCONF) && (defined __solaris__) && (defined AF_INET6)
START_TEST(test_ioctl_banned5)
{
	int fd;
	int a;
	int err;
	struct lifconf lcfg;
	struct lifreq * laddrs;
	size_t buf_index;
	unsigned int req_index;

	printf("test_ioctl_banned5: SIOCGLIFCONF\n");
	fd = socket (AF_INET, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		memset (&lcfg, 0, sizeof (struct lifconf));
		lcfg.lifc_len = 100 * sizeof (struct lifreq);
		lcfg.lifc_req = (struct lifreq *) malloc ((size_t) lcfg.lifc_len);
		if ( lcfg.lifc_req != NULL )
		{
			a = ioctl(fd, SIOCGLIFCONF, &lcfg);
			if ( a < 0 )
			{
				err = errno;
				close(fd);
				fail("test_ioctl_banned5: SIOCGLIFCONF: ioctl not performed, but should have been: errno=%d\n", err);
			}
			if ( lcfg.lifc_len > 0 )
			{
				buf_index = 0;
				req_index = 0;
				while ( buf_index <= (unsigned int)lcfg.lifc_len )
				{
					laddrs = (struct lifreq *) &(lcfg.lifc_req[req_index]);
					if ( laddrs != NULL )
					{
						if ( laddrs->lifr_addr.sa_family == AF_INET )
						{
							verify_ipv4 (&(((struct sockaddr_in *)
								&(laddrs->lifr_addr))->sin_addr));
						}
						else if ( laddrs->lifr_addr.sa_family == AF_INET6 )
						{
							verify_ipv6 (&(((struct sockaddr_in6 *)
								&(laddrs->lifr_addr))->sin6_addr));
						}
						buf_index += sizeof (struct lifreq);
					}
					else
					{
						break;
					}
					req_index++;
				}
			}
			free (lcfg.lifc_req);
		}
		else
		{
			fail("test_ioctl_banned5: SIOCGIFCONF: memory NOT allocated\n");
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned5: SIOCGLIFCONF: socket not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_ioctl_banned5_ipv6)
{
	int fd;
	int a;
	int err;
	struct lifconf lcfg;
	struct lifreq * laddrs;
	size_t buf_index;
	unsigned int req_index;

	printf("test_ioctl_banned5_ipv6: SIOCGLIFCONF\n");
	fd = socket (AF_INET6, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		memset (&lcfg, 0, sizeof (struct lifconf));
		lcfg.lifc_len = 100 * sizeof (struct lifreq);
		lcfg.lifc_req = (struct lifreq *) malloc ((size_t) lcfg.lifc_len);
		if ( lcfg.lifc_req != NULL )
		{
			a = ioctl(fd, SIOCGLIFCONF, &lcfg);
			if ( a < 0 )
			{
				err = errno;
				close(fd);
				fail("test_ioctl_banned5_ipv6: SIOCGLIFCONF: ioctl not performed, but should have been: errno=%d\n", err);
			}
			if ( lcfg.lifc_len > 0 )
			{
				buf_index = 0;
				req_index = 0;
				while ( buf_index <= (unsigned int)lcfg.lifc_len )
				{
					laddrs = (struct lifreq *) &(lcfg.lifc_req[req_index]);
					if ( laddrs != NULL )
					{
						if ( laddrs->lifr_addr.sa_family == AF_INET )
						{
							verify_ipv4 (&(((struct sockaddr_in *)
								&(laddrs->lifr_addr))->sin_addr));
						}
						else if ( laddrs->lifr_addr.sa_family == AF_INET6 )
						{
							verify_ipv6 (&(((struct sockaddr_in6 *)
								&(laddrs->lifr_addr))->sin6_addr));
						}
						buf_index += sizeof (struct lifreq);
					}
					else
					{
						break;
					}
					req_index++;
				}
			}
			free (lcfg.lifc_req);
		}
		else
		{
			fail("test_ioctl_banned5_ipv6: SIOCGIFCONF: memory NOT allocated\n");
		}
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned5_ipv6: SIOCGLIFCONF: socket not opened: errno=%d\n", errno);
	}
}
END_TEST
# endif /* (defined SIOCGLIFCONF) && (defined __solaris__) && (defined AF_INET6) */

# if (defined SIOCGLIFHWADDR) && (defined __solaris__) && (defined AF_INET6)
START_TEST(test_ioctl_banned6)
{
	int fd;
	int a;
	int err;
	struct lifreq lreqs;

	printf("test_ioctl_banned6: SIOCGLIFHWADDR\n");
	fd = socket (AF_INET, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(lreqs.lifr_name, "eth0", sizeof(lreqs.lifr_name));
		lreqs.lifr_name[sizeof(lreqs.lifr_name)-1] = '\0';
		a = ioctl(fd, SIOCGLIFHWADDR, &lreqs);
		if ( a < 0 )
		{
			err = errno;
			close(fd);
			fail("test_ioctl_banned6: SIOCGLIFHWADDR: ioctl not performed, but should have been: errno=%d\n", err);
		}
		verify_mac (&(lreqs.lifr_addr.sa_data));
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned6: SIOCGLIFHWADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_ioctl_banned6_ipv6)
{
	int fd;
	int a;
	int err;
	struct lifreq lreqs;

	printf("test_ioctl_banned6_ipv6: SIOCGLIFHWADDR\n");
	fd = socket (AF_INET6, SOCK_STREAM, 0);
	if ( fd >= 0 )
	{
		strncpy(lreqs.lifr_name, "eth0", sizeof(lreqs.lifr_name));
		lreqs.lifr_name[sizeof(lreqs.lifr_name)-1] = '\0';
		a = ioctl(fd, SIOCGLIFHWADDR, &lreqs);
		if ( a < 0 )
		{
			err = errno;
			close(fd);
			fail("test_ioctl_banned6_ipv6: SIOCGLIFHWADDR: ioctl not performed, but should have been: errno=%d\n", err);
		}
		verify_mac (&(lreqs.lifr_addr.sa_data));
		close(fd);
	}
	else
	{
		fail("test_ioctl_banned6_ipv6: SIOCGLIFHWADDR: socket not opened: errno=%d\n", errno);
	}
}
END_TEST
# endif /* (defined SIOCGLIFHWADDR) && (defined __solaris__) && (defined AF_INET6) */

#endif /* HAVE_SYS_IOCTL_H */

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

#ifdef HAVE_SYS_IOCTL_H
	TCase * tests_ioctl = tcase_create("ioctl");
#endif

#ifdef HAVE_SYS_IOCTL_H
	tcase_add_test(tests_ioctl, test_ioctl);
# ifdef SIOCGIFADDR
	tcase_add_test(tests_ioctl, test_ioctl_banned1);
	/*tcase_add_test(tests_ioctl, test_ioctl_banned1_ipv6); SIOCGIFADDR is for IPv4 */
# endif
# if (defined SIOCGIFCONF) && (defined HAVE_MALLOC)
	tcase_add_test(tests_ioctl, test_ioctl_banned2);
	tcase_add_test(tests_ioctl, test_ioctl_banned2_ipv6);
# endif
# ifdef SIOCGIFHWADDR
	tcase_add_test(tests_ioctl, test_ioctl_banned3);
	tcase_add_test(tests_ioctl, test_ioctl_banned3_ipv6);
# endif
# if (defined SIOCGLIFADDR) && (defined __solaris__) && (defined AF_INET6)
	tcase_add_test(tests_ioctl, test_ioctl_banned4);
	tcase_add_test(tests_ioctl, test_ioctl_banned4_ipv6);
# endif
# if (defined SIOCGLIFCONF) && (defined __solaris__) && (defined AF_INET6)
	tcase_add_test(tests_ioctl, test_ioctl_banned5);
	tcase_add_test(tests_ioctl, test_ioctl_banned5_ipv6);
# endif
# if (defined SIOCGLIFHWADDR) && (defined __solaris__) && (defined AF_INET6)
	tcase_add_test(tests_ioctl, test_ioctl_banned6);
	tcase_add_test(tests_ioctl, test_ioctl_banned6_ipv6);
# endif
#endif
#ifdef HAVE_SYS_IOCTL_H
	tcase_set_timeout(tests_ioctl, 30);
#endif

#ifdef HAVE_SYS_IOCTL_H
	suite_add_tcase(s, tests_ioctl);
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
