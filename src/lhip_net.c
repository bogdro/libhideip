/*
 * LibHideIP - A library for hiding local IP address.
 *	-- network functions' replacements.
 *
 * Copyright (C) 2008-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
 * Parts of this file are Copyright (C) Free Software Foundation, Inc.
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

#include "lhip_cfg.h"

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
struct sockaddr
{
	unsigned short int sa_family;
	char sa_data[14];
};

typedef unsigned short int in_port_t;

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
		unsigned short int u6_addr16[8];
		unsigned int u6_addr32[4];
	} in6_u;
# define s6_addr		in6_u.u6_addr8
# define s6_addr16		in6_u.u6_addr16
# define s6_addr32		in6_u.u6_addr32
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
typedef unsigned short int __u16;
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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_GETIPNODEBYNAME
extern struct hostent *getipnodebyname LHIP_PARAMS ((const char *name,
	int af, int flags, int *error_num));
#endif
#ifndef HAVE_GETIPNODEBYADDR
extern struct hostent *getipnodebyaddr LHIP_PARAMS ((const void *addr,
	size_t len, int af, int *error_num));
#endif
#ifndef HAVE_GETHOSTBYADDR_R
extern int gethostbyaddr_r LHIP_PARAMS ((const void *addr, socklen_t len, int type,
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop));
#endif
#ifndef HAVE_GETHOSTBYNAME_R
extern int gethostbyname_r LHIP_PARAMS ((const char *name,
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop));
#endif
#ifndef HAVE_GETHOSTBYNAME2_R
extern int gethostbyname2_r LHIP_PARAMS ((const char *name, int af,
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop));
#endif
#ifndef HAVE_GETHOSTENT_R
extern int gethostent_r LHIP_PARAMS ((
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop));
#endif

#ifdef __cplusplus
}
#endif

static const unsigned char __lhip_zeroaddr_ipv4[4] = {0, 0, 0, 0};
static const unsigned char __lhip_zeroaddr_ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const char local_name[] = "localhost";

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

#ifdef TEST_COMPILE
# ifdef LHIP_ANSIC
#  define WAS_LHIP_ANSIC
# endif
# undef LHIP_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

/* =============================================================== */

struct hostent *
gethostbyaddr (
#ifdef LHIP_ANSIC
	const void *addr, socklen_t len, int type)
#else
	addr, len, type)
	const void *addr;
	socklen_t len;
	int type;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyaddr()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyaddr_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( addr == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostbyaddr_location ()) (addr, len, type);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
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
#ifdef LHIP_ANSIC
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
	LHIP_MAKE_ERRNO_VAR(err);
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyaddr_r()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyaddr_r_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (addr == NULL) || (ret == NULL) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostbyaddr_r_location ())
			(addr, len, type, ret, buf, buflen, result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
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
#ifdef LHIP_ANSIC
	const char *name)
#else
	name)
	const char *name;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname(%s)\n", (name == NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( name == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostbyname_location ()) (name);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
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
#ifdef LHIP_ANSIC
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
	LHIP_MAKE_ERRNO_VAR(err);
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname_r(%s)\n", (name == NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname_r_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (name == NULL) || (ret == NULL) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostbyname_r_location ())
			(name, ret, buf, buflen, result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostbyname_r_location ())
			(name, ret, buf, buflen, result, h_errnop);
	}

	my_ret = (*__lhip_real_gethostbyname_r_location ())
		(name, ret, buf, buflen, result, h_errnop);
	if ( my_ret == 0 )
	{
		__lhip_change_data (ret);
	}
	return my_ret;
}

/* =============================================================== */

struct hostent *
gethostbyname2 (
#ifdef LHIP_ANSIC
	const char *name, int af)
#else
	name, af)
	const char *name;
	int af;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname2(%s)\n", (name == NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname2_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( name == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostbyname2_location ()) (name, af);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
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
#ifdef LHIP_ANSIC
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
	LHIP_MAKE_ERRNO_VAR(err);
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostbyname2_r(%s)\n", (name == NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_gethostbyname2_r_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (name == NULL) || (ret == NULL) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostbyname2_r_location ())
			(name, af, ret, buf, buflen, result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
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
#ifdef LHIP_ANSIC
	void)
#else
	)
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostent()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostent_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
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
#ifdef LHIP_ANSIC
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
	LHIP_MAKE_ERRNO_VAR(err);
	int my_ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostent_r()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostent_r_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( ret == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostent_r_location ())
			(ret, buf, buflen, result, h_errnop);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_gethostent_r_location ())
			(ret, buf, buflen, result, h_errnop);
	}

	my_ret = (*__lhip_real_gethostent_r_location ())
		(ret, buf, buflen, result, h_errnop);
	if ( my_ret == 0 )
	{
		__lhip_change_data (ret);
	}
	return my_ret;
}

/* =============================================================== */

struct hostent *
getipnodebyaddr (
#ifdef LHIP_ANSIC
	const void *addr, size_t len, int af, int *error_num)
#else
	addr, len, af, error_num)
	const void *addr;
	size_t len;
	int af;
	int *error_num;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getipnodebyaddr()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_getipnodebyaddr_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( addr == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getipnodebyaddr_location ())
			(addr, len, af, error_num);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getipnodebyaddr_location ())
			(addr, len, af, error_num);
	}

	ret = (*__lhip_real_getipnodebyaddr_location ())
		(addr, len, af, error_num);
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

struct hostent *
getipnodebyname (
#ifdef LHIP_ANSIC
	const char *name, int af, int flags, int *error_num)
#else
	name, af, flags, error_num)
	const char *name;
	int af;
	int flags;
	int *error_num;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	struct hostent * ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getipnodebyname(%s)\n", (name == NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lhip_real_getipnodebyname_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( name == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getipnodebyname_location ())
			(name, af, flags, error_num);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getipnodebyname_location ())
			(name, af, flags, error_num);
	}

	ret = (*__lhip_real_getipnodebyname_location ())
		(name, af, flags, error_num);
	if ( ret != NULL )
	{
		__lhip_change_data (ret);
	}
	return ret;
}

/* =============================================================== */

int
getifaddrs (
#ifdef LHIP_ANSIC
	struct ifaddrs **__ifap)
#else
	__ifap)
	struct ifaddrs **__ifap;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	int ret;
	struct ifaddrs *tmp;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getifaddrs()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_getifaddrs_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __ifap == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getifaddrs_location ()) (__ifap);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getifaddrs_location ()) (__ifap);
	}
	ret = (*__lhip_real_getifaddrs_location ()) (__ifap);
	if ( ret == 0 )
	{
		tmp = *__ifap;
		while ( tmp != NULL )
		{
			if ( tmp->ifa_addr == NULL )
			{
				tmp = tmp->ifa_next;
				continue;
			}
			if ( tmp->ifa_netmask != NULL )
			{
				if ( tmp->ifa_netmask->sa_family == AF_INET )
				{
					__lhip_set_ipv4_mask_value (
						&(((struct sockaddr_in *)(tmp->ifa_netmask))->sin_addr));
				}
				else if ( tmp->ifa_netmask->sa_family == AF_INET6 )
				{
					__lhip_set_ipv6_mask_value (
						&(((struct sockaddr_in6 *)(tmp->ifa_netmask))->sin6_addr));
				}
			}
			if ( (tmp->ifa_flags & IFF_BROADCAST) == IFF_BROADCAST )
			{
				/* change the broadcast address, too */
				if ( tmp->ifa_broadaddr != NULL )
				{
					if ( tmp->ifa_broadaddr->sa_family == AF_INET )
					{
						__lhip_set_ipv4_mask_value (
							&(((struct sockaddr_in *)(tmp->ifa_broadaddr))
							->sin_addr));
					}
					else if ( tmp->ifa_broadaddr->sa_family == AF_INET6 )
					{
						__lhip_set_ipv6_mask_value (
							&(((struct sockaddr_in6 *)(tmp->ifa_broadaddr))
							->sin6_addr));
					}
				}
			}
			if ( tmp->ifa_addr->sa_family == AF_INET )
			{
				__lhip_set_ipv4_value (
					&(((struct sockaddr_in *)(tmp->ifa_addr))->sin_addr));
			}
			else if ( tmp->ifa_addr->sa_family == AF_INET6 )
			{
				__lhip_set_ipv6_value (
					&(((struct sockaddr_in6 *)(tmp->ifa_addr))->sin6_addr));
			}
			tmp = tmp->ifa_next;
		} /* while ( tmp != NULL ) */
	}
	return ret;
}

/* =============================================================== */

int
getnameinfo (
#ifdef LHIP_ANSIC
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
	LHIP_MAKE_ERRNO_VAR(err);
	int ret;
	char addr1[LHIP_MAX (sizeof (struct in_addr), sizeof (struct in6_addr))];
	char * addrs[2];
	struct hostent h;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getnameinfo(%s)\n", (host == NULL)? "null" : host);
	fflush (stderr);
#endif

	if ( __lhip_real_getnameinfo_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (sa == NULL) || (host == NULL) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getnameinfo_location ())
			(sa, salen, host, hostlen, serv, servlen, flags);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getnameinfo_location ())
			(sa, salen, host, hostlen, serv, servlen, flags);
	}

	ret = (*__lhip_real_getnameinfo_location ()) (sa, salen, host, hostlen, serv, servlen, flags);
	if ( ret == 0 )
	{
		if ( salen == sizeof (struct sockaddr_in) )
		{
			h.h_name = NULL;
			h.h_aliases = NULL;
			h.h_addrtype = AF_INET;
			h.h_length = sizeof (struct in_addr);
			addrs[0] = addr1;
			addrs[1] = NULL;
			h.h_addr_list = addrs;
			LHIP_MEMCOPY ( h.h_addr_list[0],
				&(((const struct sockaddr_in *)sa)->sin_addr.s_addr),
				sizeof (struct in_addr) );
			h.h_addr_list[1] = NULL;
			if ( (__lhip_check_ipv4_value ( &(((const struct sockaddr_in *)sa)->sin_addr)) == 1)
				||
				(memcmp ( &(((const struct sockaddr_in *)sa)->sin_addr),
					__lhip_zeroaddr_ipv4,
					sizeof (__lhip_zeroaddr_ipv4) ) == 0)
				||
				(__lhip_is_local_addr (&h) != 0) )
			{
				strncpy (host, local_name, hostlen - 1);
				host[hostlen-1] = '\0';
			}
		}
		else if ( salen == sizeof (struct sockaddr_in6) )
		{
			h.h_name = NULL;
			h.h_aliases = NULL;
			h.h_addrtype = AF_INET6;
			h.h_length = sizeof (struct in6_addr);
			addrs[0] = addr1;
			addrs[1] = NULL;
			h.h_addr_list = addrs;
			LHIP_MEMCOPY ( h.h_addr_list[0],
				&(((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr),
				sizeof (struct in6_addr) );
			h.h_addr_list[1] = NULL;
			if ( (__lhip_check_ipv6_value ( &(((const struct sockaddr_in6 *)sa)->sin6_addr)) == 1)
				||
				(memcmp ( &(((const struct sockaddr_in6 *)sa)->sin6_addr),
					__lhip_zeroaddr_ipv6,
					sizeof (__lhip_zeroaddr_ipv6) ) == 0)
				||
				(__lhip_is_local_addr (&h) != 0) )
			{
				strncpy (host, local_name, hostlen - 1);
				host[hostlen-1] = '\0';
			}
		}
	}
	return ret;
}

/* =============================================================== */

int
getaddrinfo (
#ifdef LHIP_ANSIC
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
	LHIP_MAKE_ERRNO_VAR(err);
	int ret;
	int j;
	struct addrinfo *tmp;
	struct hostent * our_name_ipv4;
	struct hostent * our_name_ipv6;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getaddrinfo(%s)\n", (node == NULL)? "null" : node);
	fflush (stderr);
#endif

	if ( __lhip_real_getaddrinfo_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (node == NULL) || (res == NULL) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_getaddrinfo_location ()) (node, service, hints, res);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
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
				while ( tmp != NULL )
				{
					if ( (tmp->ai_family == AF_INET) && (tmp->ai_addr != NULL) )
					{
						__lhip_set_ipv4_value (
							&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr));
					}
					else if ( (tmp->ai_family == AF_INET6) && (tmp->ai_addr != NULL) )
					{
						__lhip_set_ipv6_value (
							&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr));
					}
					if ( tmp->ai_canonname != NULL )
					{
						strncpy (tmp->ai_canonname, local_name,
							strlen (tmp->ai_canonname) + 1 );
					}

					tmp = tmp->ai_next;
				}
			}
			else if ( our_name_ipv4->h_aliases != NULL )
			{
				j = 0;
				while ( our_name_ipv4->h_aliases[j] != NULL )
				{
					if ( strcmp (node, our_name_ipv4->h_aliases[j]) == 0 )
					{
						tmp = *res;
						do
						{
							if ( (tmp->ai_family == AF_INET) && (tmp->ai_addr != NULL) )
							{
								__lhip_set_ipv4_value (
									&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr));
							}
							else if ( (tmp->ai_family == AF_INET6) && (tmp->ai_addr != NULL) )
							{
								__lhip_set_ipv6_value (
									&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr));
							}
							if ( tmp->ai_canonname != NULL )
							{
								strncpy (tmp->ai_canonname, local_name,
									strlen (tmp->ai_canonname) + 1 );
							}

							tmp = tmp->ai_next;
						} while ( tmp != NULL );
					}
					j++;
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
					if ( (tmp->ai_family == AF_INET) && (tmp->ai_addr != NULL) )
					{
						__lhip_set_ipv4_value (
							&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr));
					}
					else if ( (tmp->ai_family == AF_INET6) && (tmp->ai_addr != NULL) )
					{
						__lhip_set_ipv6_value (
							&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr));
					}
					if ( tmp->ai_canonname != NULL )
					{
						strncpy (tmp->ai_canonname, local_name,
							strlen (tmp->ai_canonname) + 1 );
					}

					tmp = tmp->ai_next;
				} while ( tmp != NULL );
			}
			else if ( our_name_ipv6->h_aliases != NULL )
			{
				j = 0;
				while ( our_name_ipv6->h_aliases[j] != NULL )
				{
					if ( strcmp (node, our_name_ipv6->h_aliases[j]) == 0 )
					{
						tmp = *res;
						do
						{
							if ( (tmp->ai_family == AF_INET) && (tmp->ai_addr != NULL) )
							{
								__lhip_set_ipv4_value (
									&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr));
							}
							else if ( (tmp->ai_family == AF_INET6) && (tmp->ai_addr != NULL) )
							{
								__lhip_set_ipv6_value (
									&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr));
							}
							if ( tmp->ai_canonname != NULL )
							{
								strncpy (tmp->ai_canonname, local_name,
									strlen (tmp->ai_canonname) + 1 );
							}

							tmp = tmp->ai_next;
						} while ( tmp != NULL );
					}
					j++;
				}
			}
		}
	}
	return ret;
}

/* =============================================================== */

int
socket (
#ifdef LHIP_ANSIC
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
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_socket_location ()) (domain, type, protocol);
	}

	if ( (domain == AF_NETLINK)
#ifdef PF_NETLINK
# if PF_NETLINK != AF_NETLINK
		|| (domain == PF_NETLINK)
# endif
#endif
		|| (type == SOCK_RAW)
#ifdef SOCK_PACKET
		|| (type == SOCK_PACKET)
#endif
		/* can catch too many calls, because some socket types
		   allow any value for the protocol and still work.
		|| (protocol == PF_NETLINK)*/
		/* will catch too many sockets, because NETLINK_ROUTE = 0,
		   which is an often-used value for inet sockets.
		|| (protocol == NETLINK_ROUTE)*/
		/* will be caucght by "type == SOCK_RAW" anyway.
		|| (protocol == IPPROTO_RAW)*/
		/* can cause all the problems mentioned above.
#ifdef NETLINK_ROUTE6
		|| (protocol == NETLINK_ROUTE6)
#endif
		*/
		)
	{
		LHIP_SET_ERRNO_PERM();
		return -1;
	}

	return (*__lhip_real_socket_location ()) (domain, type, protocol);
}

/* =============================================================== */

ssize_t
recvmsg (
#ifdef LHIP_ANSIC
	int s, struct msghdr *msg, int flags)
#else
	s, msg, flags)
	int s;
	struct msghdr *msg;
	int flags;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: recvmsg(%d)\n", s);
	fflush (stderr);
#endif

	if ( __lhip_real_recvmsg_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_recvmsg_location ()) (s, msg, flags);
	}

	LHIP_SET_ERRNO_PERM();
	return -1;
}

/* =============================================================== */

ssize_t
sendmsg (
#ifdef LHIP_ANSIC
	int s, const struct msghdr *msg, int flags)
#else
	s, msg, flags)
	int s;
	const struct msghdr *msg;
	int flags;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: sendmsg(%d)\n", s);
	fflush (stderr);
#endif

	if ( __lhip_real_sendmsg_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_sendmsg_location ()) (s, msg, flags);
	}

	LHIP_SET_ERRNO_PERM();
	return -1;
}

/* =============================================================== */

int
gethostname (
#ifdef LHIP_ANSIC
	char * name, size_t len)
#else
	name, len)
	char * name;
	size_t len;
#endif
{
#ifndef LHIP_ENABLE_GUI_APPS
	LHIP_MAKE_ERRNO_VAR(err);
#endif

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: gethostname()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_gethostname_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

#ifndef LHIP_ENABLE_GUI_APPS
	if ( ( name == NULL ) || ( len == 0 ) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_gethostname_location ()) (name, len);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_gethostname_location ()) (name, len);
	}

	LHIP_MEMSET (name, 0, len);
	strncpy (name, local_name, len-1);
	return 0;
#else /* ! LHIP_ENABLE_GUI_APPS */
	return (*__lhip_real_gethostname_location ()) (name, len);
#endif /* LHIP_ENABLE_GUI_APPS */
}

/* =============================================================== */

int
getsockopt (
#ifdef LHIP_ANSIC
	int s, int level, int optname, void * optval, socklen_t * optlen)
#else
	s, level, optname, optval, optlen)
	int s;
	int level;
	int optname;
	void *optval;
	socklen_t *optlen;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getsockopt()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_getsockopt_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (optval == NULL) || (optlen == NULL) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_getsockopt_location ())
			(s, level, optname, optval, optlen);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_getsockopt_location ())
			(s, level, optname, optval, optlen);
	}
#if (defined SOL_IP) && (defined IP_PKTINFO)
	if ( (level == SOL_IP) && (optname == IP_PKTINFO) )
	{
		LHIP_SET_ERRNO_PERM();
		return -1;
	}
#endif
	return (*__lhip_real_getsockopt_location ())
		(s, level, optname, optval, optlen);
}

/* =============================================================== */

int
setsockopt (
#ifdef LHIP_ANSIC
	int s, int level, int optname, const void * optval, socklen_t optlen)
#else
	s, level, optname, optval, optlen)
	int s;
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: setsockopt()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_setsockopt_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( optval == NULL )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_setsockopt_location ())
			(s, level, optname, optval, optlen);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_setsockopt_location ())
			(s, level, optname, optval, optlen);
	}

#if (defined SOL_IP) && (defined IP_PKTINFO)
	if ( (level == SOL_IP) && (optname == IP_PKTINFO) )
	{
		LHIP_SET_ERRNO_PERM();
		return -1;
	}
#endif
	return (*__lhip_real_setsockopt_location ())
		(s, level, optname, optval, optlen);
}

/* =============================================================== */

/* problem with type portability - skip checking these 2 functions */
#if (defined TEST_COMPILE) && (defined WAS_LHIP_ANSIC)
# define LHIP_ANSIC 1
#endif

int
getsockname (
#ifdef LHIP_ANSIC
	int s, struct sockaddr * name, socklen_t * namelen)
#else
	s, name, namelen)
	int s;
	struct sockaddr * name;
	socklen_t * namelen;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	int res;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: getsockname()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_getsockname_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (name == NULL) || (namelen == NULL) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_getsockname_location ()) (s, name, namelen);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_getsockname_location ()) (s, name, namelen);
	}

	res = (*__lhip_real_getsockname_location ()) (s, name, namelen);
	if ( res == 0 )
	{
		if ( name->sa_family == AF_INET )
		{
			__lhip_set_ipv4_value (
				&(((struct sockaddr_in *)name)->sin_addr));
		}
		else if ( name->sa_family == AF_INET6 )
		{
			__lhip_set_ipv6_value (
				&(((struct sockaddr_in6 *)name)->sin6_addr));
		}
	}
	return res;
}

/* =============================================================== */

int
bind (
#ifdef LHIP_ANSIC
	int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
#else
	sockfd, my_addr, addrlen)
	int sockfd;
	const struct sockaddr *my_addr;
	socklen_t addrlen;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: bind()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_bind_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( my_addr == NULL )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_bind_location ()) (sockfd, my_addr, addrlen);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_bind_location ()) (sockfd, my_addr, addrlen);
	}

	if ( my_addr->sa_family == AF_INET )
	{
		if ( (__lhip_check_ipv4_value ( &(((const struct sockaddr_in *)my_addr)->sin_addr)) != 1)
			&&
			(memcmp ( &(((const struct sockaddr_in *)my_addr)->sin_addr),
				__lhip_zeroaddr_ipv4,
				sizeof (__lhip_zeroaddr_ipv4) ) != 0) )
		{
			/* not 127.0.0.1 and not 0.0.0.0 address - forbid, to avoid guessing */
			LHIP_SET_ERRNO_PERM();
			return -1;
		}
	}
	else if ( my_addr->sa_family == AF_INET6 )
	{
		if ( (__lhip_check_ipv6_value ( &(((const struct sockaddr_in6 *)my_addr)->sin6_addr)) != 1)
			&&
			(memcmp ( &(((const struct sockaddr_in6 *)my_addr)->sin6_addr),
				__lhip_zeroaddr_ipv6,
				sizeof (__lhip_zeroaddr_ipv6) ) != 0) )
		{
			/* not ::1 and not ::0 address - forbid, to avoid guessing */
			LHIP_SET_ERRNO_PERM();
			return -1;
		}
	}
	return (*__lhip_real_bind_location ()) (sockfd, my_addr, addrlen);
}

/* =============================================================== */

#ifdef TEST_COMPILE
# undef LHIP_ANSIC
#endif

int
socketpair (
#ifdef LHIP_ANSIC
	int domain, int type, int protocol, int sv[2])
#else
	domain, type, protocol, sv)
	int domain;
	int type;
	int protocol;
	int sv[2];
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: socketpair(%d, %d, %d)\n", domain, type, protocol);
	fflush (stderr);
#endif

	if ( __lhip_real_socketpair_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_socketpair_location ()) (domain, type, protocol, sv);
	}

	if ( (domain == AF_NETLINK)
#ifdef PF_NETLINK
# if PF_NETLINK != AF_NETLINK
		|| (domain == PF_NETLINK)
# endif
#endif
		|| (type == SOCK_RAW)
#ifdef SOCK_PACKET
		|| (type == SOCK_PACKET)
#endif
		/* can catch too many calls, because some socket types
		   allow any value for the protocol and still work.
		|| (protocol == PF_NETLINK)*/
		/* will catch too many sockets, because NETLINK_ROUTE = 0,
		   which is an often-used value for inet sockets.
		|| (protocol == NETLINK_ROUTE)*/
		/* will be caucght by "type == SOCK_RAW" anyway.
		|| (protocol == IPPROTO_RAW)*/
		/* can cause all the problems mentioned above.
#ifdef NETLINK_ROUTE6
		|| (protocol == NETLINK_ROUTE6)
#endif
		*/
		)
	{
		LHIP_SET_ERRNO_PERM();
		return -1;
	}

	return (*__lhip_real_socketpair_location ()) (domain, type, protocol, sv);
}
