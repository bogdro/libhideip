/*
 * A library for hiding local IP address.
 *	-- ioctl function replacement.
 *
 * Copyright (C) 2008 Bogdan Drozdowski, bogdandr (at) op.pl
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
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lhip_priv.h"

static const unsigned char __lhip_localhost_ipv4[4] = {LOCAL_IPV4_ADDR};
static const unsigned char __lhip_netmask_ipv4[4] = {LOCAL_IPV4_MASK};
static const unsigned char __lhip_localhost_ipv6[16] = {LOCAL_IPV6_ADDR};
static const unsigned char __lhip_netmask_ipv6[16] = {LOCAL_IPV6_MASK};
static const unsigned char __lhip_fake_mac[6] = {1, 2, 3, 4, 5, 6};

/* =============================================================== */

int
ioctl (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	int d, unsigned long int request, ...)
#else
	d, request, ...)
	int d;
	unsigned long int request;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	va_list args;
	void * data1;
	void * data2;
	int ret;
	struct ifreq * addrs;
	struct ifconf * cfg;
	int buf_index;
	int req_index;
#ifndef HAVE_MEMCPY
	size_t i;
#endif

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: ioctl(%d, %lu, ...)\n", d, request);
	fflush (stderr);
#endif

	if ( __lhip_real_ioctl_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	va_start (args, request);
	data1 = va_arg (args, void *);
	data2 = va_arg (args, void *);

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret = (*__lhip_real_ioctl_location ()) (d, request, data1, data2);
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
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
# ifdef HAVE_MEMCPY
					memcpy (&(((struct sockaddr_in *)&(addrs->ifr_addr))->sin_addr),
						__lhip_localhost_ipv4,
						sizeof (__lhip_localhost_ipv4) );
# else
					for ( i = 0; i < sizeof (__lhip_localhost_ipv4); i++ )
					{
						((char *)&(((struct sockaddr_in *)&(addrs->ifr_addr))->sin_addr))[i]
							= __lhip_localhost_ipv4[i];
					}
# endif
				}
				else if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET6 )
				{
# ifdef HAVE_MEMCPY
					memcpy (&(((struct sockaddr_in6 *)&(addrs->ifr_addr))->sin6_addr),
						__lhip_localhost_ipv6,
						sizeof (__lhip_localhost_ipv6) );
# else
					for ( i = 0; i < sizeof (__lhip_localhost_ipv6); i++ )
					{
						((char *)&(((struct sockaddr_in6 *)&(addrs->ifr_addr))->sin6_addr))[i]
							= __lhip_localhost_ipv6[i];
					}
# endif
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
				buf_index = 0;
				req_index = 0;
				while ( buf_index <= cfg->ifc_len )
				{
					addrs = (struct ifreq *) &(cfg->ifc_req[req_index]);
					if ( addrs != NULL )
					{
						if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET )
						{
# ifdef HAVE_MEMCPY
							memcpy (&(((struct sockaddr_in *)&(addrs->ifr_addr))->sin_addr),
								__lhip_localhost_ipv4,
								sizeof (__lhip_localhost_ipv4) );
# else
							for ( i = 0; i < sizeof (__lhip_localhost_ipv4); i++ )
							{
								((char *)&(((struct sockaddr_in *)&(addrs->ifr_addr))->sin_addr))[i]
									= __lhip_localhost_ipv4[i];
							}
# endif
						}
						else if ( addrs->ifr_ifru.ifru_addr.sa_family == AF_INET6 )
						{
# ifdef HAVE_MEMCPY
							memcpy (&(((struct sockaddr_in6 *)&(addrs->ifr_ifru.ifru_addr))->sin6_addr),
								__lhip_localhost_ipv6,
								sizeof (__lhip_localhost_ipv6) );
# else
							for ( i = 0; i < sizeof (__lhip_localhost_ipv6); i++ )
							{
								((char *)&(((struct sockaddr_in6 *)&(addrs->ifr_addr))->sin6_addr))[i]
									= __lhip_localhost_ipv6[i];
							}
# endif
						}
						buf_index += sizeof (struct ifreq);
					}
					else break;
					req_index++;
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
# ifdef HAVE_MEMCPY
				memcpy (&(addrs->ifr_addr.sa_data),
					__lhip_fake_mac,
					sizeof (__lhip_fake_mac) );
# else
				for ( i = 0; i < sizeof (__lhip_fake_mac); i++ )
				{
					((char *)&(addrs->ifr_addr.sa_data))[i]
						= __lhip_fake_mac[i];
				}
# endif
			}
		}
#endif /* SIOCGIFHWADDR */
	}
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	va_end (args);
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return ret;
}

