/*
 * A library for hiding local IP address.
 *	-- unit test.
 *
 * Copyright (C) 2015-2017 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL))
	/* need RTLD_NEXT and dlvsym(), so define _GNU_SOURCE */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE	1
# endif
# include <dlfcn.h>
# ifndef RTLD_NEXT
#  define RTLD_NEXT ((void *) -1l)
# endif
#else
# ifdef LHIP_ANSIC
#  error Dynamic loading functions missing.
# endif
#endif

#include <libhideip.h>
#include <check.h>

/* compatibility with older check versions */
#ifndef ck_abort
# define ck_abort() ck_abort_msg(NULL)
# define ck_abort_msg fail
# define ck_assert(C) ck_assert_msg(C, NULL)
# define ck_assert_msg fail_unless
#endif

#ifndef _ck_assert_int
# define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
# define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
# define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
#endif

#ifndef _ck_assert_str
# define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
# define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
# define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
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

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#else
# define S_IRUSR 0600
# define S_IWUSR 0400
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

#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#else
# define IFF_BROADCAST 0x2
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif

#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif

#ifdef HAVE_PCAP_H
# include <pcap.h>
#else
# ifdef HAVE_PCAP_PCAP_H
#  include <pcap/pcap.h>
# endif
#endif

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#if (defined LHIP_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
# define LHIP_CAN_USE_BANS 1
#else
# undef LHIP_CAN_USE_BANS
#endif

#if (defined LHIP_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
# define LHIP_CAN_USE_ENV 1
#else
# undef LHIP_CAN_USE_ENV
#endif

#define LHIP_TEST_FILENAME "zz1"
#define LHIP_TEST_FILE_LENGTH 3
#define LHIP_LINK_FILENAME "zz1link"
#define LHIP_TEST_BANNED_FILENAME "/etc/hosts"
#define LHIP_TEST_BANNED_FILENAME_SHORT "hosts"
#define LHIP_TEST_BANNED_LINKNAME "banlink"

/* ====================== File functions */

#ifdef HAVE_SYS_SOCKET_H
static in_addr_t addr;
static struct in6_addr addr6;
static struct sockaddr_in sa_in;
static struct sockaddr_in6 sa_in6;
#endif

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
		fail("test_openat_banned: file opened, but shouldn't be (1)\n");
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
			fail("test_openat_banned: file opened, but shouldn't be (2)\n");
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
		fail("test_openat_banned: dir not opened, but should be: errno=%d\n", errno);
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
		fail("test_openat_link: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LHIP_LINK_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		r = unlink (LHIP_LINK_FILENAME);
		if (r != 0)
		{
			fail("test_openat_link: link could not be deleted: errno=%d, r=%d\n", errno, r);
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
		fail("test_openat_link_banned: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LHIP_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fail("test_openat_link_banned: file opened, but shouldn't be\n");
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
		fail("test_fopen_banned: file opened, but shouldn't be\n");
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
		fail("test_fopen_link: link could not be created: errno=%d, r=%d\n", errno, r);
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
		fail("test_fopen_link_banned: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_TEST_BANNED_LINKNAME, "r");
	if (f != NULL)
	{
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fclose(f);
		fail("test_fopen_link_banned: file opened, but shouldn't be\n");
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
			fail("test_freopen_banned: file opened, but shouldn't be\n");
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
		fail("test_freopen_stdout_banned: file opened, but shouldn't be\n");
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
		fail("test_freopen_link: link could not be created: errno=%d, r=%d\n", errno, r);
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
		fail("test_freopen_link_banned: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LHIP_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LHIP_TEST_BANNED_LINKNAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			unlink (LHIP_TEST_BANNED_LINKNAME);
			fail("test_freopen_link_banned: file opened, but shouldn't be\n");
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
		fail("test_freopen_link_banned_stdout: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	f = freopen(LHIP_TEST_BANNED_LINKNAME, "r", stdout);
	if (f != NULL)
	{
		fclose(f);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fail("test_freopen_link_banned_stdout: file opened, but shouldn't be\n");
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
		fail("test_open_banned: file opened, but shouldn't be\n");
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
		fail("test_open_link: link could not be created: errno=%d, r=%d\n", errno, r);
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
		fail("test_open_link_banned: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	fd = open(LHIP_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LHIP_TEST_BANNED_LINKNAME);
		fail("test_open_link_banned: file opened, but shouldn't be\n");
	}
	r = errno;
	unlink (LHIP_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
# endif
}
END_TEST
#endif /* HAVE_SYMLINK */

#ifdef LHIP_CAN_USE_BANS
START_TEST(test_banned_in_userfile_prog)
{
	int fd;
	FILE * user_ban_file;
	char * user_ban_file_name;
	const char * home_env;
	int err;
	long file_len;

	printf("test_banned_in_userfile_prog\n");

	home_env = getenv("HOME");
	user_ban_file_name = (char *) malloc (strlen (home_env) + 1
		+ strlen (LHIP_BANNING_USERFILE) + 1);
	if ( user_ban_file_name == NULL )
	{
		fail("test_banned_in_userfile_prog: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (user_ban_file_name, home_env);
	strcat (user_ban_file_name, "/");
	strcat (user_ban_file_name, LHIP_BANNING_USERFILE);

	user_ban_file = fopen (user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (user_ban_file_name);
		fail("test_banned_in_userfile_prog: cannot open user file: errno=%d\n", err);
	}

	fseek (user_ban_file, 0, SEEK_END);
	file_len = ftell (user_ban_file);
	fwrite ("\nlhiptest\n", 1, strlen("\nlhiptest\n"), user_ban_file);
	fclose (user_ban_file);

	fd = open(LHIP_TEST_BANNED_FILENAME, O_RDONLY);
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
		fail("test_banned_in_userfile_prog: file not opened: errno=%d\n", err);
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

	printf("test_banned_in_env_prog\n");

	res = setenv(LHIP_BANNING_ENV, env_ban_file_name, 1);
	if ( res != 0 )
	{
		fail("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (env_ban_file_name, "a+");
	if ( env_ban_file == NULL )
	{
		fail("test_banned_in_env_prog: cannot open user file: errno=%d\n", errno);
	}

	fseek (env_ban_file, 0, SEEK_END);
	file_len = ftell (env_ban_file);
	fwrite ("\nlhiptest\n", 1, strlen("\nlhiptest\n"), env_ban_file);
	fclose (env_ban_file);

	fd = open(LHIP_TEST_BANNED_FILENAME, O_RDONLY);
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
		fail("test_banned_in_env_prog: file not opened: errno=%d\n", err);
	}
}
END_TEST
#endif

/* ====================== Network functions */
static const unsigned char __lhip_localhost_ipv4[4] = {127, 0, 0, 1};
static const unsigned char __lhip_localhost_ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const unsigned char __lhip_fake_mac[6] = {1, 2, 3, 4, 5, 6};
#define LHIP_MAXHOSTLEN 16384
#if defined(__GNUC__) && __GNUC__ >= 3
# define LHIP_ALIGN(x) __attribute__((aligned(x)))
#else
# define LHIP_ALIGN(x)
#endif
static char buf[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);

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
		if (strncmp (h->h_name, "localhost", strlen (h->h_name)) != 0)
		{
			fail("h->h_name contains something else than 'localhost': '%s'\n", h->h_name);
		}
	}
	if (h->h_aliases != NULL)
	{
		i = 0;
		while ( h->h_aliases[i] != NULL )
		{
			if ( strncmp (h->h_aliases[i],
				"localhost", strlen (h->h_aliases[i])) != 0 )
			{
				fail("h->h_aliases[%d] contains something else than 'localhost': '%s'\n",
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
		fail("test_socket_inet: socket not opened, but should be: errno=%d\n", errno);
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
		fail("test_socket_unix: socket not opened, but should be: errno=%d\n", errno);
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
		fail("test_socket_inet6: socket not opened, but should be: errno=%d\n", errno);
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
		fail("test_socket_banned_netlink: socket opened, but shouldn't be\n");
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
		fail("test_socket_banned_raw: socket opened, but shouldn't be\n");
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
		fail("test_socket_banned_raw6: socket opened, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_recvmsg)
{
	int a;

	printf("test_recvmsg\n");
	a = recvmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_recvmsg: data received, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_sendmsg)
{
	int a;

	printf("test_sendmsg\n");
	a = sendmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_sendmsg: data sent, but shouldn't be\n");
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
		fail("test_getsockname: socket not opened, but should be: errno=%d\n", errno);
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
		fail("test_getsockname6: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_bind: socket not bound, but should be: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_bind: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_bind6: socket not bound, but should be: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_bind6: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_bind_banned: socket bound, but shouldn't be\n");
		}
	}
	else
	{
		fail("test_bind_banned: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_bind_banned6: socket bound, but shouldn't be\n");
		}
	}
	else
	{
		fail("test_bind_banned6: socket not opened, but should be: errno=%d\n", errno);
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
		fail("test_socket_banned: socketpair not opened, but should be: errno=%d\n", errno);
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
		fail("test_socketpair_banned_netlink: socketpair opened, but shouldn't be\n");
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
		fail("test_socketpair_banned_raw: socketpair opened, but shouldn't be\n");
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
		fail("test_socketpair_banned_packet: socketpair opened, but shouldn't be\n");
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
			fail("test_getsockopt: socket option not read, but should be: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_getsockopt: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_getsockopt6: socket option not read, but should be: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_getsockopt6: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_getsockopt_banned: socket option read, but shouldn't be\n");
		}
	}
	else
	{
		fail("test_getsockopt_banned: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_getsockopt_banned6: socket option read, but shouldn't be\n");
		}
	}
	else
	{
		fail("test_getsockopt_banned6: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_setsockopt: socket option not set, but should be: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_setsockopt: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_setsockopt6: socket option not set, but should be: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_setsockopt6: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_setsockopt_banned: socket option set, but shouldn't be\n");
		}
	}
	else
	{
		fail("test_setsockopt_banned: socket not opened, but should be: errno=%d\n", errno);
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
			fail("test_setsockopt_banned6: socket option set, but shouldn't be\n");
		}
	}
	else
	{
		fail("test_setsockopt_banned6: socket not opened, but should be: errno=%d\n", errno);
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

/* ====================== Execution functions */

#ifdef HAVE_UNISTD_H
START_TEST(test_execve)
{
	int a;
	char progname[] = "/bin/cat";
	char fname[] = LHIP_TEST_FILENAME;
	char * args[] = { NULL, NULL, NULL };
	char * envp[] = { NULL };

	printf("test_execve\n");
	args[0] = progname;
	args[1] = fname;
	a = execve (progname, args, envp);
	fail("test_execve: the program didn't run, but it should"); /* should never be reached */
}
END_TEST

START_TEST(test_execve_banned)
{
	int a;
	char * args[] = { NULL };

	printf("test_execve_banned\n");
	a = execve ("/sbin/ifconfig", args, NULL);
	ck_assert_int_ne(a, 0);
}
END_TEST
#endif /* HAVE_UNISTD_H */

START_TEST(test_system)
{
	int a;

	printf("test_system\n");
	a = system ("cat " LHIP_TEST_FILENAME);
	ck_assert_int_eq(a, 0);
}
END_TEST

START_TEST(test_system_banned)
{
	int a;

	printf("test_system_banned\n");
	a = system ("/sbin/ifconfig");
	ck_assert_int_ne(a, 0);
}
END_TEST

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
			fail("test_ioctl: ioctl not performed, but should be: errno=%d\n", err);
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
			close(fd);
			fail("test_ioctl_banned1: SIOCGIFADDR: ioctl not performed, but should be: errno=%d\n", err);
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
			fail("test_ioctl_banned1_ipv6: SIOCGIFADDR: ioctl not performed, but should be: errno=%d\n", err);
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
	unsigned int buf_index;
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
				fail("test_ioctl_banned2: SIOCGIFCONF: ioctl not performed, but should be: errno=%d\n", err);
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
	unsigned int buf_index;
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
				fail("test_ioctl_banned2_ipv6: SIOCGIFCONF: ioctl not performed, but should be: errno=%d\n", err);
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
			close(fd);
			fail("test_ioctl_banned3: SIOCGIFHWADDR: ioctl not performed, but should be: errno=%d\n", err);
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
			close(fd);
			fail("test_ioctl_banned3_ipv6: SIOCGIFHWADDR: ioctl not performed, but should be: errno=%d\n", err);
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
			fail("test_ioctl_banned4: SIOCGLIFADDR: ioctl not performed, but should be: errno=%d\n", err);
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
			fail("test_ioctl_banned4_ipv6: SIOCGLIFADDR: ioctl not performed, but should be: errno=%d\n", err);
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
	unsigned int buf_index;
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
				fail("test_ioctl_banned5: SIOCGLIFCONF: ioctl not performed, but should be: errno=%d\n", err);
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
	unsigned int buf_index;
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
				fail("test_ioctl_banned5_ipv6: SIOCGLIFCONF: ioctl not performed, but should be: errno=%d\n", err);
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
			fail("test_ioctl_banned6: SIOCGLIFHWADDR: ioctl not performed, but should be: errno=%d\n", err);
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
			fail("test_ioctl_banned6_ipv6: SIOCGLIFHWADDR: ioctl not performed, but should be: errno=%d\n", err);
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

/* ====================== Name resolver functions */

#ifdef HAVE_RESOLV_H
START_TEST(test_res_query)
{
	int a;

	printf("test_res_query\n");
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
	a = res_querydomain("mail", "google.com", C_ANY, T_A, (u_char *)buf, sizeof (buf));
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
	a = res_mkquery(QUERY, "localhost", C_ANY, T_A, NULL, 0, NULL, (u_char *)buf, sizeof (buf));
	if ( a >= 0 )
	{
		fail("test_res_mkquery_banned: query succeeded, but shouldn't have\n");
	}
}
END_TEST
#endif /* HAVE_RESOLV_H */


/* ====================== Packet capture functions */

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
START_TEST(test_pcap_lookupdev)
{
	char * pcap_dev;

	printf("test_pcap_lookupdev\n");
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

	printf("test_pcap_lookupnet\n");
	a = pcap_lookupnet ("eth0", &ip, &mask, buf);
	ck_assert_int_eq(a, -1);
}
END_TEST

START_TEST(test_pcap_create)
{
	pcap_t * ret;

	printf("test_pcap_create\n");
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

	printf("test_pcap_open_dead\n");
	ret = pcap_open_dead (100, 100);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_dead: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_open_live)
{
	pcap_t * ret;

	printf("test_pcap_open_live\n");
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

	printf("test_pcap_open_offline\n");
	ret = pcap_open_offline (LHIP_TEST_FILENAME, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_offline: capture opened, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_fopen_offline)
{
	pcap_t * ret;
	FILE *f;

	printf("test_pcap_fopen_offline\n");
	f = fopen(LHIP_TEST_FILENAME, "w+");
	if (f != NULL)
	{
		ret = pcap_fopen_offline (f, buf);
		if (ret != NULL)
		{
			pcap_close(ret);
			fclose(f);
			unlink (LHIP_TEST_FILENAME);
			fail("test_pcap_open_offline: capture opened, but shouldn't have been\n");
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

#if defined(WIN32)
START_TEST(test_pcap_hopen_offline)
{
	pcap_t * ret;

	printf("test_pcap_hopen_offline\n");
	ret = pcap_hopen_offline (0, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_hopen_offline: capture opened, but shouldn't have been\n");
	}
}
END_TEST
#endif /* WIN32 */

START_TEST(test_pcap_findalldevs)
{
	pcap_if_t * devs = NULL;
	int a;

	printf("test_pcap_findalldevs\n");
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

	TCase * tests_open = tcase_create("open");
	TCase * tests_exec = tcase_create("exec");
#ifdef HAVE_SYS_IOCTL_H
	TCase * tests_ioctl = tcase_create("ioctl");
#endif
	TCase * tests_net = tcase_create("net");
	TCase * tests_resolve = tcase_create("resolve");
#ifdef HAVE_SYS_UTSNAME_H
	TCase * tests_uname = tcase_create("uname");
#endif
#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	TCase * tests_pcap = tcase_create("pcap");
#endif

/* ====================== File functions */

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
#ifdef LHIP_CAN_USE_BANS
	tcase_add_test(tests_open, test_banned_in_userfile_prog);
#endif
#ifdef LHIP_CAN_USE_ENV
	tcase_add_test(tests_open, test_banned_in_env_prog);
#endif

/* ====================== Network functions */

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


/* ====================== Execution functions */

#ifdef HAVE_UNISTD_H
	/*tcase_add_test(tests_exec, test_execve);*/
	tcase_add_exit_test(tests_exec, test_execve, 0);
	tcase_add_test(tests_exec, test_execve_banned);
#endif
	tcase_add_test(tests_exec, test_system);
	tcase_add_test(tests_exec, test_system_banned);


/* ====================== I/O CTL functions */

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

/* ====================== Packet capture functions */

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	tcase_add_test(tests_pcap, test_pcap_lookupdev);
	tcase_add_test(tests_pcap, test_pcap_lookupnet);
	tcase_add_test(tests_pcap, test_pcap_create);
	tcase_add_test(tests_pcap, test_pcap_open_dead);
	tcase_add_test(tests_pcap, test_pcap_open_live);
	tcase_add_test(tests_pcap, test_pcap_open_offline);
	tcase_add_test(tests_pcap, test_pcap_fopen_offline);
# if defined(WIN32)
	tcase_add_test(tests_pcap, test_pcap_hopen_offline);
# endif
	tcase_add_test(tests_pcap, test_pcap_findalldevs);
#endif

/* ====================== Name resolver functions */

#ifdef HAVE_RESOLV_H
	tcase_add_test(tests_resolve, test_res_query);
	tcase_add_test(tests_resolve, test_res_query_banned);
	tcase_add_test(tests_resolve, test_res_search);
	tcase_add_test(tests_resolve, test_res_search_banned);
	tcase_add_test(tests_resolve, test_res_querydomain);
	tcase_add_test(tests_resolve, test_res_querydomain_banned);
	tcase_add_test(tests_resolve, test_res_mkquery);
	tcase_add_test(tests_resolve, test_res_mkquery_banned);
#endif

/* ====================== System name functions */

#ifdef HAVE_SYS_UTSNAME_H
	tcase_add_test(tests_uname, test_uname);
#endif

/* ====================== */

	tcase_add_checked_fixture(tests_open, &setup_file_test, &teardown_file_test);
	tcase_add_checked_fixture(tests_exec, &setup_file_test, &teardown_file_test);
	tcase_add_checked_fixture(tests_net, &setup_net_test, &teardown_net_test);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_open, 30);
	tcase_set_timeout(tests_exec, 30);
#ifdef HAVE_SYS_IOCTL_H
	tcase_set_timeout(tests_ioctl, 30);
#endif
	tcase_set_timeout(tests_net, 30);
#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	tcase_set_timeout(tests_pcap, 30);
#endif
#ifdef HAVE_RESOLV_H
	tcase_set_timeout(tests_resolve, 30);
#endif
#ifdef HAVE_SYS_UTSNAME_H
	tcase_set_timeout(tests_uname, 30);
#endif


	suite_add_tcase(s, tests_open);
	suite_add_tcase(s, tests_exec);
#ifdef HAVE_SYS_IOCTL_H
	suite_add_tcase(s, tests_ioctl);
#endif
	suite_add_tcase(s, tests_net);
#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	suite_add_tcase(s, tests_pcap);
#endif
#ifdef HAVE_RESOLV_H
	suite_add_tcase(s, tests_resolve);
#endif
#ifdef HAVE_SYS_UTSNAME_H
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
