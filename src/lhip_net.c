/*
 * A library for hiding local IP address.
 *	-- network functions' replacements.
 *
 * Copyright (C) 2008-2009 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include "lhip_cfg.h"

#define _BSD_SOURCE 1
#define _SVID_SOURCE 1

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
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

#ifdef HAVE_STDLIB_H
# include <stdlib.h>		/* sys/socket.h */
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#if (!defined HAVE_NETINET_IN_H) && (!defined HAVE_SYS_SOCKET_H)
typedef unsigned short int sa_family_t;

struct sockaddr
  {
    unsigned short int sa_family;
    char sa_data[14];
  };

typedef unsigned short in_port_t;

typedef unsigned int in_addr_t;
struct in_addr
  {
    in_addr_t s_addr;
  };

struct in6_addr
  {
    union
      {
	unsigned char	u6_addr8[16];
	unsigned short u6_addr16[8];
	unsigned int u6_addr32[4];
      } in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
  };

struct sockaddr_in
{
	unsigned short int sin_family;
    in_port_t sin_port;			/* Port number.  */
    struct in_addr sin_addr;		/* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr) -
			   sizeof (sin_family) -
			   sizeof (in_port_t) -
			   sizeof (struct in_addr)];
};

struct sockaddr_in6
{
	unsigned short int sin6_family;
    in_port_t sin6_port;	/* Transport layer port # */
    unsigned int sin6_flowinfo;	/* IPv6 flow information */
    struct in6_addr sin6_addr;	/* IPv6 address */
    unsigned int sin6_scope_id;	/* IPv6 scope-id */
};
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_ASM_TYPES_H
# include <asm/types.h>		/* linux/netlink.h */
#else
typedef unsigned int __u32;
typedef unsigned short __u16;
#endif

#ifdef HAVE_LINUX_NETLINK_H
# include <linux/netlink.h>
#else
# define NETLINK_ROUTE		0	/* Routing/device hook		*/
/*# define NETLINK_ROUTE6		11	new systems use NETLINK_ROUTE for both IPv4 and IPv6 */
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* gethostname () */
#endif

#include "lhip_priv.h"

#ifndef HAVE_GETIPNODEBYNAME
extern struct hostent *getipnodebyname PARAMS((const char *name,
	int af, int flags, int *error_num));
#endif
#ifndef HAVE_GETIPNODEBYADDR
extern struct hostent *getipnodebyaddr PARAMS((const void *addr,
	size_t len, int af, int *error_num));
#endif

static const unsigned char __lhip_localhost_ipv4[4] = {LOCAL_IPV4_ADDR};
static const unsigned char __lhip_netmask_ipv4[4] = {LOCAL_IPV4_MASK};
static const unsigned char __lhip_localhost_ipv6[16] = {LOCAL_IPV6_ADDR};
static const unsigned char __lhip_netmask_ipv6[16] = {LOCAL_IPV6_MASK};

#ifndef HAVE_GETHOSTBYADDR_R
extern int gethostbyaddr_r (const void *addr, socklen_t len, int type,
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop);
#endif
#ifndef HAVE_GETHOSTBYNAME_R
extern int gethostbyname_r (const char *name,
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop);
#endif
#ifndef HAVE_GETHOSTBYNAME2_R
extern int gethostbyname2_r (const char *name, int af,
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop);
#endif
#ifndef HAVE_GETHOSTENT_R
extern int gethostent_r (
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop);
#endif

#ifndef AF_NETLINK
# ifdef AF_ROUTE
#  define AF_NETLINK AF_ROUTE
# else
#  define AF_NETLINK 16
# endif
#endif

#ifndef PF_NETLINK
# define PF_NETLINK AF_NETLINK
#endif

#define LHIP_MIN(a,b) ( ((a)<(b)) ? (a) : (b) )

/* =============================================================== */

struct hostent *
gethostbyaddr (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const void *addr, socklen_t len, int type)
#else
	addr, len, type)
	const void *addr;
	socklen_t len;
	int type;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyaddr()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyaddr_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( addr == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyaddr_location ()) (addr, len, type);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyaddr_location ()) (addr, len, type);
	}

	ret = (*__lhip_real_gethostbyaddr_location ()) (addr, len, type);
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

int
gethostbyaddr_r (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const void *addr, socklen_t len, int type,
	struct hostent *ret, char *buf, size_t buflen,
	struct hostent **result, int *h_errnop)
#else
	addr, len, type, ret, buf, buflen, result, h_errnop)
	const void *addr;
	socklen_t len;
	int type;
	struct hostent *ret;
	char *buf;
	size_t buflen;
	struct hostent **result;
	int *h_errnop;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyaddr_r()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyaddr_r_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (addr == NULL) || (ret == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyaddr_r_location ())
			(addr, len, type, ret, buf, buflen, result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyaddr_r_location ())
			(addr, len, type, ret, buf, buflen, result, h_errnop);
	}
	my_ret = (*__lhip_real_gethostbyaddr_r_location ())
		(addr, len, type, ret, buf, buflen, result, h_errnop);
	if ( my_ret == 0 )
	{
		__lhip_change_data (ret);
	}
	return my_ret;
}

/* =============================================================== */

struct hostent *
gethostbyname (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *name)
#else
	name)
	const char *name;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname_location ()) (name);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname_location ()) (name);
	}

	ret = (*__lhip_real_gethostbyname_location ()) (name);
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

int
gethostbyname_r (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *name,
	struct hostent *ret, char *buf, size_t buflen,
	struct hostent **result, int *h_errnop)
#else
	name, ret, buf, buflen, result, h_errnop)
	const char *name;
	struct hostent *ret;
	char *buf;
	size_t buflen;
	struct hostent **result;
	int *h_errnop;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname_r(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname_r_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (name == NULL) || (ret == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname_r_location ())
			(name, ret, buf, buflen, result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname_r_location ())
			(name, ret, buf, buflen, result, h_errnop);
	}

	my_ret = (*__lhip_real_gethostbyname_r_location ()) (name, ret, buf, buflen, result, h_errnop);
	if ( my_ret == 0 )
	{
		__lhip_change_data (ret);
	}
	return my_ret;
}

/* =============================================================== */

struct hostent *
gethostbyname2 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *name, int af)
#else
	name, af)
	const char *name;
	int af;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname2(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname2_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname2_location ()) (name, af);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname2_location ()) (name, af);
	}

	ret = (*__lhip_real_gethostbyname2_location ()) (name, af);
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

int
gethostbyname2_r (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *name, int af,
	struct hostent *ret, char *buf, size_t buflen,
	struct hostent **result, int *h_errnop)
#else
	name, af, ret, buf, buflen, result, h_errnop)
	const char *name;
	int af;
	struct hostent *ret;
	char *buf;
	size_t buflen;
	struct hostent **result;
	int *h_errnop;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname2_r(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname2_r_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (name == NULL) || (ret == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname2_r_location ())
			(name, af, ret, buf, buflen, result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostbyname2_r_location ())
			(name, af, ret, buf, buflen, result, h_errnop);
	}

	my_ret = (*__lhip_real_gethostbyname2_r_location ())
		(name, af, ret, buf, buflen, result, h_errnop);
	if ( my_ret == 0 )
	{
		__lhip_change_data (ret);
	}
	return my_ret;
}

/* =============================================================== */

struct hostent *
gethostent (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void)
#else
	)
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostent()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostent_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostent_location ()) ();
	}

	ret = (*__lhip_real_gethostent_location ()) ();
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

int
gethostent_r (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	struct hostent *ret, char *buf, size_t buflen,
	struct hostent **result, int *h_errnop)
#else
	ret, buf, buflen,result, h_errnop)
	struct hostent *ret;
	char *buf;
	size_t buflen;
	struct hostent **result;
	int *h_errnop;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostent_r()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostent_r_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( ret == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostent_r_location ()) (ret, buf, buflen,result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostent_r_location ()) (ret, buf, buflen,result, h_errnop);
	}

	my_ret = (*__lhip_real_gethostent_r_location ()) (ret, buf, buflen,result, h_errnop);
	if ( my_ret == 0 )
	{
		__lhip_change_data (ret);
	}
	return my_ret;
}

/* =============================================================== */

struct hostent *
getipnodebyaddr (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const void *addr, size_t len, int af, int *error_num)
#else
	addr, len, af, error_num)
	const void *addr;
	size_t len;
	int af;
	int *error_num;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getipnodebyaddr()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_getipnodebyaddr_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( addr == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getipnodebyaddr_location ()) (addr, len, af, error_num);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getipnodebyaddr_location ()) (addr, len, af, error_num);
	}

	ret = (*__lhip_real_getipnodebyaddr_location ()) (addr, len, af, error_num);
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

struct hostent *
getipnodebyname (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *name, int af, int flags, int *error_num)
#else
	name, af, flags, error_num)
	const char *name;
	int af;
	int flags;
	int *error_num;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getipnodebyname(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_getipnodebyname_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getipnodebyname_location ()) (name, af, flags, error_num);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getipnodebyname_location ()) (name, af, flags, error_num);
	}

	ret = (*__lhip_real_getipnodebyname_location ()) (name, af, flags, error_num);
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

int
getifaddrs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	struct ifaddrs **__ifap)
#else
	__ifap)
	struct ifaddrs **__ifap;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int ret;
	struct ifaddrs *tmp;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getifaddrs()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_getifaddrs_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( __ifap == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getifaddrs_location ()) (__ifap);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getifaddrs_location ()) (__ifap);
	}

	ret = (*__lhip_real_getifaddrs_location ()) (__ifap);
	if ( ret == 0 )
	{
		tmp = *__ifap;
		while ( tmp != NULL )
		{
			if ( tmp->ifa_addr->sa_family == AF_INET )
			{
#ifdef HAVE_MEMCPY
				memcpy ( &(((struct sockaddr_in *)(tmp->ifa_addr))->sin_addr),
					__lhip_localhost_ipv4,
					sizeof (__lhip_localhost_ipv4) );
#else
				for ( i = 0; i < sizeof (__lhip_localhost_ipv4); i++ )
				{
					((char *)&(((struct sockaddr_in *)(tmp->ifa_addr))->sin_addr))[i]
						= __lhip_localhost_ipv4[i];
				}
#endif
#ifdef HAVE_MEMCPY
				memcpy ( &(((struct sockaddr_in *)(tmp->ifa_netmask))->sin_addr),
					__lhip_netmask_ipv4,
					sizeof (__lhip_netmask_ipv4) );
#else
				for ( i = 0; i < sizeof (__lhip_netmask_ipv4); i++ )
				{
					((char *)&(((struct sockaddr_in *)(tmp->ifa_netmask))->sin_addr))[i]
						= __lhip_netmask_ipv4[i];
				}
#endif
				if ( (tmp->ifa_flags & IFF_BROADCAST) == IFF_BROADCAST )
				{
					/* change the broadcast address, too */
#ifdef HAVE_MEMCPY
					memcpy ( &(((struct sockaddr_in *)(tmp->ifa_broadaddr))->sin_addr),
						__lhip_netmask_ipv4,
						sizeof (__lhip_netmask_ipv4) );
#else
					for ( i = 0; i < sizeof (__lhip_netmask_ipv4); i++ )
					{
						((char *)&(((struct sockaddr_in *)(tmp->ifa_broadaddr))->sin_addr))[i]
							= __lhip_netmask_ipv4[i];
					}
#endif
				}
			}
			else if ( tmp->ifa_addr->sa_family == AF_INET6 )
			{
#ifdef HAVE_MEMCPY
				memcpy ( &(((struct sockaddr_in6 *)(tmp->ifa_addr))->sin6_addr),
					__lhip_localhost_ipv6,
					sizeof (__lhip_localhost_ipv6) );
#else
				for ( i = 0; i < sizeof (__lhip_localhost_ipv6); i++ )
				{
					((char *)&(((struct sockaddr_in6 *)(tmp->ifa_addr))->sin6_addr))[i]
						= __lhip_localhost_ipv6[i];
				}
#endif
#ifdef HAVE_MEMCPY
				memcpy ( &(((struct sockaddr_in6 *)(tmp->ifa_netmask))->sin6_addr),
					__lhip_netmask_ipv6,
					sizeof (__lhip_netmask_ipv6) );
#else
				for ( i = 0; i < sizeof (__lhip_netmask_ipv6); i++ )
				{
					((char *)&(((struct sockaddr_in6 *)(tmp->ifa_netmask))->sin6_addr))[i]
						= __lhip_netmask_ipv6[i];
				}
#endif
				if ( (tmp->ifa_flags & IFF_BROADCAST) == IFF_BROADCAST )
				{
					/* change the broadcast address, too */
#ifdef HAVE_MEMCPY
					memcpy ( &(((struct sockaddr_in6 *)(tmp->ifa_broadaddr))->sin6_addr),
						__lhip_netmask_ipv6,
						sizeof (__lhip_netmask_ipv6) );
#else
					for ( i = 0; i < sizeof (__lhip_netmask_ipv6); i++ )
					{
						((char *)&(((struct sockaddr_in6 *)(tmp->ifa_broadaddr))->sin6_addr))[i]
							= __lhip_netmask_ipv6[i];
					}
#endif
				}
			}
			tmp = tmp->ifa_next;
		}
	}
	return ret;
}

/* =============================================================== */

int
getnameinfo (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const struct sockaddr *sa, socklen_t salen,
	char *host, GETNAMEINFO_ARG4TYPE hostlen,
	char *serv, GETNAMEINFO_ARG6TYPE servlen, GETNAMEINFO_ARG7TYPE flags)
#else
	sa, salen, host, hostlen, serv, servlen, flags)
	const struct sockaddr *sa;
	socklen_t salen;
	char *host;
	GETNAMEINFO_ARG4TYPE hostlen;
	char *serv;
	GETNAMEINFO_ARG6TYPE servlen;
	GETNAMEINFO_ARG7TYPE flags;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getnameinfo(%s)\n", (host==NULL)? "null" : host);
	fflush (stderr);
#endif

	if ( __lhip_real_getnameinfo_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (sa == NULL) || (host == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getnameinfo_location ())
			(sa, salen, host, hostlen, serv, servlen, flags);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getnameinfo_location ())
			(sa, salen, host, hostlen, serv, servlen, flags);
	}

	ret = (*__lhip_real_getnameinfo_location ()) (sa, salen, host, hostlen, serv, servlen, flags);
	if ( ret == 0 )
	{
		if ( salen == sizeof (struct sockaddr_in) )
		{
			if ( memcmp ( &(((const struct sockaddr_in *)sa)->sin_addr),
				__lhip_localhost_ipv4,
				sizeof (__lhip_localhost_ipv4) ) == 0 )
			{
				strncpy (host, "localhost", hostlen);
			}
		}
		else if ( salen == sizeof (struct sockaddr_in6) )
		{
			if ( memcmp ( &(((const struct sockaddr_in6 *)sa)->sin6_addr),
				__lhip_localhost_ipv6,
				sizeof (__lhip_localhost_ipv6) ) == 0 )
			{
				strncpy (host, "localhost", hostlen);
			}
		}
	}
	return ret;
}

/* =============================================================== */

int
getaddrinfo (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *node, const char *service,
	const struct addrinfo *hints,
	struct addrinfo **res)
#else
	node, service, hints, res)
	const char *node;
	const char *service;
	const struct addrinfo *hints;
	struct addrinfo **res;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int ret;
	int i;
	struct addrinfo *tmp;
	struct hostent * our_name_ipv4;
	struct hostent * our_name_ipv6;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getaddrinfo(%s)\n", (node==NULL)? "null" : node);
	fflush (stderr);
#endif

	if ( __lhip_real_getaddrinfo_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (node == NULL) || (res == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getaddrinfo_location ()) (node, service, hints, res);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_getaddrinfo_location ()) (node, service, hints, res);
	}

	ret = (*__lhip_real_getaddrinfo_location ()) (node, service, hints, res);
	if ( (ret == 0) && (*res != NULL) )
	{
		our_name_ipv4 = __lhip_get_our_name_ipv4 ();
		our_name_ipv6 = __lhip_get_our_name_ipv6 ();
		if ( our_name_ipv4 != NULL )
		{
			if ( strcmp (node, our_name_ipv4->h_name) == 0 )
			{
				tmp = *res;
				do
				{
					if ( tmp->ai_family == AF_INET )
					{
#ifdef HAVE_MEMCPY
						memcpy (
							&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr),
							__lhip_localhost_ipv4,
							sizeof (__lhip_localhost_ipv4) );
#else
						for ( i = 0; i < sizeof (__lhip_localhost_ipv4); i++ )
						{
							((char *)&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr))[i]
								= __lhip_localhost_ipv4[i];
						}
#endif
					}
					else if ( tmp->ai_family == AF_INET6 )
					{
#ifdef HAVE_MEMCPY
						memcpy (
							&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr),
							__lhip_localhost_ipv6,
							sizeof (__lhip_localhost_ipv6) );
#else
						for ( i = 0; i < sizeof (__lhip_localhost_ipv6); i++ )
						{
							((char *)&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr))[i]
								= __lhip_localhost_ipv6[i];
						}
#endif
					}
					if (tmp->ai_canonname != NULL )
					{
						strncpy (tmp->ai_canonname, "localhost",
							strlen (tmp->ai_canonname) );
					}

					tmp = tmp->ai_next;
				} while ( tmp != NULL );
			}
			else if ( our_name_ipv4->h_aliases != NULL )
			{
				i=0;
				while ( our_name_ipv4->h_aliases[i] != NULL )
				{
					if ( strcmp (node, our_name_ipv4->h_aliases[i]) == 0 )
					{
						tmp = *res;
						do
						{
							if ( tmp->ai_family == AF_INET )
							{
#ifdef HAVE_MEMCPY
								memcpy (
									&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr),
									__lhip_localhost_ipv4,
									sizeof (__lhip_localhost_ipv4) );
#else
								for ( i = 0; i < sizeof (__lhip_localhost_ipv4); i++ )
								{
									((char *)&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr))[i]
										= __lhip_localhost_ipv4[i];
								}
#endif
							}
							else if ( tmp->ai_family == AF_INET6 )
							{
#ifdef HAVE_MEMCPY
								memcpy (
									&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr),
									__lhip_localhost_ipv6,
									sizeof (__lhip_localhost_ipv6) );
#else
								for ( i = 0; i < sizeof (__lhip_localhost_ipv6); i++ )
								{
									((char *)&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr))[i]
										= __lhip_localhost_ipv6[i];
								}
#endif
							}
							if (tmp->ai_canonname != NULL )
							{
								strncpy (tmp->ai_canonname, "localhost",
									strlen (tmp->ai_canonname) );
							}

							tmp = tmp->ai_next;
						} while ( tmp != NULL );
					}
					i++;
				}
			}
		}
		if ( our_name_ipv6 != NULL )
		{
			if ( strcmp (node, our_name_ipv6->h_name) == 0 )
			{
				tmp = *res;
				do
				{
					if ( tmp->ai_family == AF_INET )
					{
#ifdef HAVE_MEMCPY
						memcpy (
							&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr),
							__lhip_localhost_ipv4,
							sizeof (__lhip_localhost_ipv4) );
#else
						for ( i = 0; i < sizeof (__lhip_localhost_ipv4); i++ )
						{
							((char *)&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr))[i]
								= __lhip_localhost_ipv4[i];
						}
#endif
					}
					else if ( tmp->ai_family == AF_INET6 )
					{
#ifdef HAVE_MEMCPY
						memcpy (
							&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr),
							__lhip_localhost_ipv6,
							sizeof (__lhip_localhost_ipv6) );
#else
						for ( i = 0; i < sizeof (__lhip_localhost_ipv6); i++ )
						{
							((char *)&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr))[i]
								= __lhip_localhost_ipv6[i];
						}
#endif
					}
					if (tmp->ai_canonname != NULL )
					{
						strncpy (tmp->ai_canonname, "localhost",
							strlen (tmp->ai_canonname) );
					}

					tmp = tmp->ai_next;
				} while ( tmp != NULL );
			}
			else if ( our_name_ipv6->h_aliases != NULL )
			{
				i=0;
				while ( our_name_ipv6->h_aliases[i] != NULL )
				{
					if ( strcmp (node, our_name_ipv6->h_aliases[i]) == 0 )
					{
						tmp = *res;
						do
						{
							if ( tmp->ai_family == AF_INET )
							{
#ifdef HAVE_MEMCPY
								memcpy (
									&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr),
									__lhip_localhost_ipv4,
									sizeof (__lhip_localhost_ipv4) );
#else
								for ( i = 0; i < sizeof (__lhip_localhost_ipv4); i++ )
								{
									((char *)&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr))[i]
										= __lhip_localhost_ipv4[i];
								}
#endif
							}
							else if ( tmp->ai_family == AF_INET6 )
							{
#ifdef HAVE_MEMCPY
								memcpy (
									&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr),
									__lhip_localhost_ipv6,
									sizeof (__lhip_localhost_ipv6) );
#else
								for ( i = 0; i < sizeof (__lhip_localhost_ipv6); i++ )
								{
									((char *)&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr))[i]
										= __lhip_localhost_ipv6[i];
								}
#endif
							}
							if (tmp->ai_canonname != NULL )
							{
								strncpy (tmp->ai_canonname, "localhost",
									strlen (tmp->ai_canonname) );
							}

							tmp = tmp->ai_next;
						} while ( tmp != NULL );
					}
					i++;
				}
			}
		}
	}
	return ret;
}

/* =============================================================== */

int
socket (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	int domain, int type, int protocol)
#else
	domain, type, protocol)
	int domain;
	int type;
	int protocol;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: socket(%d, %d, %d)\n", domain, type, protocol);
	fflush (stderr);
#endif

	if ( __lhip_real_socket_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		return (*__lhip_real_socket_location ()) (domain, type, protocol);
	}

	if ( (domain == AF_NETLINK) || (domain == PF_NETLINK) || (protocol == NETLINK_ROUTE)
#ifdef NETLINK_ROUTE6
		|| (protocol == NETLINK_ROUTE6)
#endif
		)
	{
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return -1;
	}

	return (*__lhip_real_socket_location ()) (domain, type, protocol);
}

/* =============================================================== */

ssize_t
recvmsg (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	int s, struct msghdr *msg, int flags)
#else
	s, msg, flags)
	int s;
	struct msghdr *msg;
	int flags;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: recvmsg(%d)\n", s);
	fflush (stderr);
#endif

	if ( __lhip_real_recvmsg_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		return (*__lhip_real_recvmsg_location ()) (s, msg, flags);
	}

#ifdef HAVE_ERRNO_H
	errno = -EPERM;
#endif
	return -1;
}

/* =============================================================== */

ssize_t
sendmsg (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	int s, const struct msghdr *msg, int flags)
#else
	s, msg, flags)
	int s;
	const struct msghdr *msg;
	int flags;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: sendmsg(%d)\n", s);
	fflush (stderr);
#endif

	if ( __lhip_real_sendmsg_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		return (*__lhip_real_sendmsg_location ()) (s, msg, flags);
	}

#ifdef HAVE_ERRNO_H
	errno = -EPERM;
#endif
	return -1;
}

/* =============================================================== */

int
gethostname (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	char *name, size_t len)
#else
	name, len)
	char *name;
	size_t len;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
#ifndef HAVE_MEMSET
	size_t i;
#endif

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostname()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostname_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostname_location ()) (name, len);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_gethostname_location ()) (name, len);
	}

#ifdef HAVE_MEMSET
	memset (name, 0, len);
#else
	for ( i = 0; i < len; i++ )
	{
		name[i] = '\0';
	}
#endif
	strncpy (name, "localhost", LHIP_MIN (len, 10));
	return 0;
}
