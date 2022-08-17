/*
 * A library for hiding local IP address.
 *	-- ioctl function replacement.
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

#define _GNU_SOURCE 1		/* getaddrinfo_a + struct gaicb in lhip_priv.h */

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# ifdef HAVE_VARARGS_H
#  include <varargs.h>
# endif
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>		/* sys/socket.h */
#endif

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
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

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#else
# define SIOCGIFADDR	0x8915
# define SIOCGIFCONF	0x8912
# define SIOCGIFHWADDR	0x8927
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#else
struct ifmap
{
	unsigned long int mem_start;
	unsigned long int mem_end;
	unsigned short int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
	/* 3 bytes spare */
};

struct ifreq
{
# define IFHWADDRLEN	6
# define IFNAMSIZ	IF_NAMESIZE
	union
	{
		char ifrn_name[IFNAMSIZ];	/* Interface name, e.g. "en0".  */
	} ifr_ifrn;

	union
	{
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[IFNAMSIZ];	/* Just fits the size */
		char ifru_newname[IFNAMSIZ];
		__caddr_t ifru_data;
	} ifr_ifru;
};

struct ifconf
{
	int	ifc_len;			/* Size of buffer.  */
	union
	{
		__caddr_t ifcu_buf;
		struct ifreq *ifcu_req;
	} ifc_ifcu;
};
# if (defined __solaris__) && (defined AF_INET6)
struct lifconf
{
	int	lifc_len;			/* Size of buffer.  */
	union
	{
		__caddr_t lifc_buf;
		struct lifreq *lifc_req;
	} lifc_ifcu;
};
#  define lifc_buf lifc_ifcu.lifc_buf               /* buffer address       */
#  define lifc_req lifc_ifcu.lifc_req               /* array of structures  */
# endif
#endif

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


#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lhip_priv.h"

/* =============================================================== */

int
ioctl (
#ifdef LHIP_ANSIC
	int d, unsigned long int request, ...)
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	d, request)
	int d;
	unsigned long int request;*/
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LHIP_ANSIC
	int d;
	unsigned long int request;
# endif
#endif
	void * data1 = NULL;
	void * data2 = NULL;
	int ret;
#if (defined SIOCGIFADDR) || (defined SIOCGIFCONF) || (defined SIOCGIFHWADDR)
	struct ifreq * addrs;
	struct ifconf * cfg;
	size_t buf_index;
	int req_index;
#endif
#if (defined __solaris__) && (defined AF_INET6)
	struct lifreq * laddrs;
	struct lifconf * lcfg;
#endif

	__lhip_main ();

	if ( __lhip_real_ioctl_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LHIP_ANSIC
	va_start (args, request);
# else
	va_start (args);
	d = va_arg (args, int);
	request = va_arg (args, unsigned long int);
# endif
	data1 = va_arg (args, void *);
	data2 = va_arg (args, void *);
#endif
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: ioctl(%d, %lu, ...)\n", d, request);
	fflush (stderr);
#endif

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		ret = (*__lhip_real_ioctl_location ()) (d, request, data1, data2);
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		LHIP_GET_ERRNO(err);
		va_end (args);
		LHIP_SET_ERRNO(err);
#endif
		return ret;
	}

	ret = (*__lhip_real_ioctl_location ()) (d, request, data1, data2);
	if ( ret >= 0 )
	{
#ifdef SIOCGIFADDR
		if ( request == SIOCGIFADDR )		/* get local protocol address */
		{
			addrs = (struct ifreq *) data1;
			if ( addrs != NULL )
			{
				if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET )
				{
					__lhip_set_ipv4_value (
						&(((struct sockaddr_in *)&(addrs->ifr_addr))->sin_addr));
				}
				else if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET6 )
				{
					__lhip_set_ipv6_value (
						&(((struct sockaddr_in6 *)&(addrs->ifr_addr))->sin6_addr));
				}
			}
		}
#endif /* SIOCGIFADDR */
#ifdef SIOCGIFCONF
		if ( request == SIOCGIFCONF )	/* get interface list */
		{
			cfg = (struct ifconf *) data1;
			if ( cfg != NULL )
			{
				if ( cfg->ifc_len > 0 )
				{
					buf_index = 0;
					req_index = 0;
					while ( buf_index <= (unsigned int)cfg->ifc_len )
					{
						addrs = (struct ifreq *) &(cfg->ifc_req[req_index]);
						if ( addrs != NULL )
						{
							if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET )
							{
								__lhip_set_ipv4_value (
									&(((struct sockaddr_in *)&(addrs->ifr_addr))->sin_addr));
							}
							else if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET6 )
							{
								__lhip_set_ipv6_value (
									&(((struct sockaddr_in6 *)&(addrs->ifr_addr))->sin6_addr));
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
			}
		}
#endif /* SIOCGIFCONF */
#ifdef SIOCGIFHWADDR
		if ( request == SIOCGIFHWADDR )	/* get local hardware address */
		{
			addrs = (struct ifreq *) data1;
			if ( addrs != NULL )
			{
				__lhip_set_mac_value (&(addrs->ifr_addr.sa_data));
			}
		}
#endif /* SIOCGIFHWADDR */
#if (defined SIOCGLIFADDR) && (defined __solaris__) && (defined AF_INET6)
		if ( request == SIOCGLIFADDR )		/* get local IPv6 protocol address */
		{
			laddrs = (struct lifreq *) data1;
			if ( laddrs != NULL )
			{
				if ( laddrs->lifr_addr.sa_family == AF_INET )
				{
					__lhip_set_ipv4_value (
						&(((struct sockaddr_in *)&(laddrs->lifr_addr))->sin_addr));
				}
				else if ( laddrs->lifr_addr.sa_family == AF_INET6 )
				{
					__lhip_set_ipv6_value (
						&(((struct sockaddr_in6 *)&(laddrs->lifr_addr))->sin6_addr));
				}
			}
		}
#endif /* SIOCGIFADDR */
#if (defined SIOCGLIFCONF) && (defined __solaris__) && (defined AF_INET6)
		if ( request == SIOCGLIFCONF )	/* get IPv6 interface list */
		{
			lcfg = (struct lifconf *) data1;
			if ( lcfg != NULL )
			{
				if ( lcfg->lifc_len > 0 )
				{
					buf_index = 0;
					req_index = 0;
					while ( buf_index <= (unsigned int)lcfg->lifc_len )
					{
						laddrs = (struct lifreq *) &(lcfg->lifc_req[req_index]);
						if ( laddrs != NULL )
						{
							if ( laddrs->lifr_addr.sa_family == AF_INET )
							{
								__lhip_set_ipv4_value (
									&(((struct sockaddr_in *)&(laddrs->lifr_addr))->sin_addr));
							}
							else if ( laddrs->lifr_addr.sa_family == AF_INET6 )
							{
								__lhip_set_ipv6_value (
									&(((struct sockaddr_in6 *)&(laddrs->lifr_addr))->sin6_addr));
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
			}
		}
#endif /* SIOCGLIFCONF */
#if (defined SIOCGLIFHWADDR) && (defined __solaris__) && (defined AF_INET6)
		if ( request == SIOCGLIFHWADDR )	/* get local hardware address for IPv6 interfaces */
		{
			laddrs = (struct lifreq *) data1;
			if ( laddrs != NULL )
			{
				__lhip_set_mac_value (
					&(laddrs->lifr_addr.sa_data));
			}
		}
#endif /* SIOCGIFHWADDR */
	}

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LHIP_GET_ERRNO(err);
	va_end (args);
	LHIP_SET_ERRNO(err);
#endif
	return ret;
}
