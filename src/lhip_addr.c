/*
 * A library for hiding local IP address.
 *	-- getting the local address and checking for matches.
 *
 * Copyright (C) 2011 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#else
# ifdef HAVE_MALLOC_H
#  include <malloc.h>
# endif
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
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
			   sizeof (unsigned short int /*sin_family*/) -
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

#include "lhip_priv.h"

static struct hostent * __lhip_our_real_name_ipv4 = NULL;
static struct hostent * __lhip_our_real_name_ipv6 = NULL;
static struct addrinfo * __lhip_ai_all = NULL;
static const unsigned char __lhip_localhost_ipv4[4] = {LOCAL_IPV4_ADDR};
static const unsigned char __lhip_localhost_ipv6[16] = {LOCAL_IPV6_ADDR};
static char __lhip_our_hostname_v4[4097];
static char __lhip_our_hostname_v6[4097];
static char __lhip_our_gethostname[4097];
static struct utsname __lhip_uname_res;

static struct hostent __lhip_our_names_addr[LHIP_MAX_HOSTNAMES];
static struct hostent __lhip_tmp;
static unsigned int __lhip_number_of_hostnames = 0;
/*
static char * __lhip_our_hostnames[LHIP_MAX_HOSTNAMES];
static struct sockaddr * __lhip_our_addresses[LHIP_MAX_HOSTNAMES];
static unsigned int __lhip_number_of_addresses = 0;
*/

static int GCC_WARN_UNUSED_RESULT
__lhip_check_hostname_match PARAMS((const char * const host1, const char * const host2));

/* =============================================================== */

void __lhip_read_local_addresses (
#ifdef LHIP_ANSIC
	void
#endif
)
{
#ifdef HAVE_ERRNO_H
	int err = errno;
#endif
#if defined HAVE_ARPA_INET_H
	struct in_addr lhip_addr;
	struct in6_addr lhip_addr6;
#endif
	struct addrinfo ai_hints;
	struct addrinfo * __lhip_ai_all_tmp;
	struct addrinfo * tmp;
	int ai_res;
	struct sockaddr_in addr_ipv4;
	struct sockaddr_in6 addr_ipv6;
	struct hostent * hostent_res;
	int lhip_errno;
	size_t i, j;
#ifndef HAVE_MEMCPY
	size_t k;
#endif
	int localaddr_found = 0;
	__lhip_number_of_hostnames = 0;

	/* Get our host's addresses and names/aliases: */
	if ( __lhip_real_gethostname_location () != NULL )
	{
		ai_res = (*__lhip_real_gethostname_location ()) (__lhip_our_gethostname,
			sizeof (__lhip_our_gethostname) );
		if ( ai_res != 0 )
		{
#ifdef HAVE_MEMSET
			memset (__lhip_our_gethostname, 0, sizeof (__lhip_our_gethostname));
#else
			for ( i = 0; i < sizeof (__lhip_our_gethostname); i++ )
			{
				__lhip_our_gethostname[i] = '\0';
			}
#endif
		}
	}
	if ( __lhip_real_uname_location () != NULL )
	{
		ai_res = (*__lhip_real_uname_location ()) (&__lhip_uname_res);
		if ( ai_res != 0 )
		{
#ifdef HAVE_MEMSET
			memset (&__lhip_uname_res, 0, sizeof (struct utsname));
#else
			for ( i = 0; i < sizeof (struct utsname); i++ )
			{
				((char *)&__lhip_uname_res)[i] = '\0';
			}
#endif
		}
	}

#ifdef HAVE_ARPA_INET_H
	/* if malloc() is available, we can use gethostbyaddr() */
# ifndef HAVE_MALLOC
	if (__lhip_real_gethostbyaddr_r_location () != NULL)
	{
		ai_res = inet_aton ("127.0.0.1", &lhip_addr);
		if ( ai_res == 0 )
		{
			ai_res = (*__lhip_real_gethostbyaddr_r_location ())
					(&lhip_addr, sizeof (struct in_addr), AF_INET,
					&(__lhip_our_names_addr[__lhip_number_of_hostnames]),
					/* buffer: */
					__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
					&hostent_res, &lhip_errno);
			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				/* make a copy of the data */
				__lhip_tmp.h_name = NULL;
				__lhip_tmp.h_aliases = NULL;
				__lhip_tmp.h_addr_list = NULL;
				if ( hostent_res->h_name != NULL )
				{
					__lhip_tmp.h_name = (char *) malloc (strlen (hostent_res->h_name)+1);
					if ( __lhip_tmp.h_name != NULL )
					{
						strncpy ( __lhip_tmp.h_name, hostent_res->h_name,
							strlen (hostent_res->h_name)+1 );
					}
				}
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						j++;
					}
					/* "+1" for the NULL pointer */
					__lhip_tmp.h_aliases = (char **)
						malloc ((j+1) * sizeof (char *));
					if ( __lhip_tmp.h_aliases != NULL )
					{
						for ( i = 0; i < j; i++ )
						{
							__lhip_tmp.h_aliases[i] = (char *)
								malloc (strlen
									(hostent_res->h_aliases[i])+1);
							if ( __lhip_tmp.h_aliases[i] != NULL )
							{
								strncpy (__lhip_tmp.h_aliases[i],
									hostent_res->h_aliases[i],
									strlen (hostent_res->h_aliases[i])+1);
							}
						}
						/* end-of-list marker */
						__lhip_tmp.h_aliases[j] = NULL;
					}
				}
				if ( hostent_res->h_addr_list != NULL )
				{
					j = 0;
					while (hostent_res->h_addr_list[j] != NULL)
					{
						j++;
					}
					if ( j > 0 )
					{
						/* "+1" for the NULL pointer */
						__lhip_tmp.h_addr_list = (char **)
							malloc ((j+1) * sizeof (char *));
						if ( (__lhip_tmp.h_addr_list != NULL)
							&& (hostent_res->h_length > 0) )
						{
							for ( i = 0; i < j; i++ )
							{
								__lhip_tmp.h_addr_list[i] = (char *)
									malloc ((size_t) (hostent_res->h_length));
								if ( __lhip_tmp.h_addr_list[i] != NULL )
								{
#  ifdef HAVE_MEMCPY
									memcpy (__lhip_tmp.h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) (hostent_res->h_length));
#  else
									for (k=0; k < hostent_res->h_length; k++)
									{
										__lhip_tmp.h_addr_list[i][k] =
											hostent_res->h_addr_list[i][k];
									}
#  endif
								}
							}
							/* end-of-list marker */
							__lhip_tmp.h_addr_list[j] = NULL;
						}
					}
				}
#  ifdef HAVE_MEMCPY
				memcpy ( &(__lhip_our_names_addr[__lhip_number_of_hostnames]),
					&__lhip_tmp, sizeof (struct hostent) );
#  else
				for (k=0; k < sizeof (struct hostent); k++)
				{
					((char *)&(__lhip_our_names_addr[__lhip_number_of_hostnames]))[k] =
						((char *)&__lhip_tmp)[k];
				}
#  endif
				/* finished copying data */

				localaddr_found = 0;
				if ( hostent_res->h_name != NULL )
				{
					if ( __lhip_check_hostname_match (__lhip_our_gethostname,
						hostent_res->h_name) == 1 )
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
					}
				}
				if ( (hostent_res->h_aliases != NULL) && (localaddr_found == 0) )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						if ( __lhip_check_hostname_match (__lhip_our_gethostname,
							hostent_res->h_aliases[j]) == 1 )
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							break;
						}
						j++;
					}
				}
				if ( (hostent_res->h_name != NULL) && (localaddr_found == 0) )
				{
					if ( __lhip_check_hostname_match (__lhip_uname_res.nodename,
						hostent_res->h_name) == 1 )
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
					}
				}
				if ( (hostent_res->h_aliases != NULL) && (localaddr_found == 0) )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						if ( __lhip_check_hostname_match (
							__lhip_uname_res.nodename,
							hostent_res->h_aliases[j]) == 1 )
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							break;
						}
						j++;
					}
				}
				if ( (hostent_res->h_addr_list != NULL) && (localaddr_found == 0) )
				{
					i = 0;
					while ( hostent_res->h_addr_list[i] != NULL )
					{
						if ( (hostent_res->h_addrtype == AF_INET)
							&& (memcmp (hostent_res->h_addr_list[i],
								__lhip_localhost_ipv4,
								sizeof (__lhip_localhost_ipv4) ) == 0)
						)
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							if ( __lhip_number_of_hostnames >=
								sizeof (__lhip_our_names_addr)
								/sizeof (__lhip_our_names_addr[0]) )
							{
								break;
							}
						}
						if ( (hostent_res->h_addrtype == AF_INET6)
							&& (memcmp (hostent_res->h_addr_list[i],
								__lhip_localhost_ipv6,
								sizeof (__lhip_localhost_ipv6) ) == 0)
						)
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							if ( __lhip_number_of_hostnames >=
								sizeof (__lhip_our_names_addr)
								/sizeof (__lhip_our_names_addr[0]) )
							{
								break;
							}
						}
						i++;
					}
				}
				if ( localaddr_found == 0 )
				{
					/* Not found = not saved. Free the allocated memory */
					if ( __lhip_tmp.h_name != NULL ) free (__lhip_tmp.h_name);
					if ( __lhip_tmp.h_aliases != NULL )
					{
						j = 0;
						while ( __lhip_tmp.h_aliases[j] != NULL )
						{
							free (__lhip_tmp.h_aliases[j]);
							j++;
						}
						free (__lhip_tmp.h_aliases);
					}
					if ( __lhip_tmp.h_addr_list != NULL )
					{
						j = 0;
						while ( __lhip_tmp.h_addr_list[j] != NULL )
						{
							free (__lhip_tmp.h_addr_list[j]);
							j++;
						}
						free (__lhip_tmp.h_addr_list);
					}
				}
			} /* ai_res == 0 ... */
		} /* ai_res == 0 */
		/* IPv6: */
# ifdef HAVE_MEMCPY
		memcpy (&lhip_addr6, __lhip_localhost_ipv6, sizeof (__lhip_localhost_ipv6));
# else
		for ( k = 0; k < sizeof (__lhip_localhost_ipv6); k++ )
		{
			((char *)&(lhip_addr6))[k] = __lhip_localhost_ipv6[k];
		}
# endif
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_name = NULL;
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases = NULL;
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list = NULL;
		ai_res = (*__lhip_real_gethostbyaddr_r_location ())
				(&lhip_addr6, sizeof (struct in6_addr), AF_INET6,
				&(__lhip_our_names_addr[__lhip_number_of_hostnames]),
				/* buffer: */
				__lhip_our_hostname_v6, sizeof (__lhip_our_hostname_v6),
				&hostent_res, &lhip_errno);
		if ( (ai_res == 0) && (hostent_res != NULL) )
		{
			/* make a copy of the data */
			__lhip_tmp.h_name = NULL;
			__lhip_tmp.h_aliases = NULL;
			__lhip_tmp.h_addr_list = NULL;
			if ( hostent_res->h_name != NULL )
			{
				__lhip_tmp.h_name = (char *) malloc (strlen (hostent_res->h_name)+1);
				if ( __lhip_tmp.h_name != NULL )
				{
					strncpy ( __lhip_tmp.h_name, hostent_res->h_name,
						strlen (hostent_res->h_name)+1 );
				}
			}
			if ( hostent_res->h_aliases != NULL )
			{
				j = 0;
				while (hostent_res->h_aliases[j] != NULL)
				{
					j++;
				}
				/* "+1" for the NULL pointer */
				__lhip_tmp.h_aliases = (char **)
					malloc ((j+1) * sizeof (char *));
				if ( __lhip_tmp.h_aliases != NULL )
				{
					for ( i = 0; i < j; i++ )
					{
						__lhip_tmp.h_aliases[i] = (char *)
							malloc (strlen
								(hostent_res->h_aliases[i])+1);
						if ( __lhip_tmp.h_aliases[i] != NULL )
						{
							strncpy (__lhip_tmp.h_aliases[i],
								hostent_res->h_aliases[i],
								strlen (hostent_res->h_aliases[i])+1);
						}
					}
					/* end-of-list marker */
					__lhip_tmp.h_aliases[j] = NULL;
				}
			}
			if ( hostent_res->h_addr_list != NULL )
			{
				j = 0;
				while (hostent_res->h_addr_list[j] != NULL)
				{
					j++;
				}
				if ( j > 0 )
				{
					/* "+1" for the NULL pointer */
					__lhip_tmp.h_addr_list = (char **)
						malloc ((j+1) * sizeof (char *));
					if ( (__lhip_tmp.h_addr_list != NULL)
						&& (hostent_res->h_length > 0) )
					{
						for ( i = 0; i < j; i++ )
						{
							__lhip_tmp.h_addr_list[i] = (char *)
								malloc ((size_t) (hostent_res->h_length));
							if ( __lhip_tmp.h_addr_list[i] != NULL )
							{
#  ifdef HAVE_MEMCPY
								memcpy (__lhip_tmp.h_addr_list[i],
									hostent_res->h_addr_list[i],
									(size_t) (hostent_res->h_length));
#  else
								for (k=0; k < hostent_res->h_length; k++)
								{
									__lhip_tmp.h_addr_list[i][k] =
										hostent_res->h_addr_list[i][k];
								}
#  endif
							}
						}
						/* end-of-list marker */
						__lhip_tmp.h_addr_list[j] = NULL;
					}
				}
			}
#  ifdef HAVE_MEMCPY
			memcpy ( &(__lhip_our_names_addr[__lhip_number_of_hostnames]),
				&__lhip_tmp, sizeof (struct hostent) );
#  else
			for (k=0; k < sizeof (struct hostent); k++)
			{
				((char *)&(__lhip_our_names_addr[__lhip_number_of_hostnames]))[k] =
					((char *)&__lhip_tmp)[k];
			}
#  endif
			/* finished copying data */

			localaddr_found = 0;
			if ( hostent_res->h_name != NULL )
			{
				if ( __lhip_check_hostname_match (__lhip_our_gethostname,
					hostent_res->h_name) == 1 )
				{
					__lhip_number_of_hostnames++;
					localaddr_found = 1;
				}
			}
			if ( (hostent_res->h_aliases != NULL) && (localaddr_found == 0) )
			{
				j = 0;
				while (hostent_res->h_aliases[j] != NULL)
				{
					if ( __lhip_check_hostname_match (__lhip_our_gethostname,
						hostent_res->h_aliases[j]) == 1 )
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
						break;
					}
					j++;
				}
			}
			if ( (hostent_res->h_name != NULL) && (localaddr_found == 0) )
			{
				if ( __lhip_check_hostname_match (__lhip_uname_res.nodename,
					hostent_res->h_name) == 1 )
				{
					__lhip_number_of_hostnames++;
					localaddr_found = 1;
				}
			}
			if ( (hostent_res->h_aliases != NULL) && (localaddr_found == 0) )
			{
				j = 0;
				while (hostent_res->h_aliases[j] != NULL)
				{
					if ( __lhip_check_hostname_match (
						__lhip_uname_res.nodename,
						hostent_res->h_aliases[j]) == 1 )
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
						break;
					}
					j++;
				}
			}
			if ( (hostent_res->h_addr_list != NULL) && (localaddr_found == 0) )
			{
				i = 0;
				while ( hostent_res->h_addr_list[i] != NULL )
				{
					if ( (hostent_res->h_addrtype == AF_INET)
						&& (memcmp (hostent_res->h_addr_list[i],
							__lhip_localhost_ipv4,
							sizeof (__lhip_localhost_ipv4) ) == 0)
					)
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
						if ( __lhip_number_of_hostnames >=
							sizeof (__lhip_our_names_addr)
							/sizeof (__lhip_our_names_addr[0]) )
						{
							break;
						}
					}
					if ( (hostent_res->h_addrtype == AF_INET6)
						&& (memcmp (hostent_res->h_addr_list[i],
							__lhip_localhost_ipv6,
							sizeof (__lhip_localhost_ipv6) ) == 0)
					)
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
						if ( __lhip_number_of_hostnames >=
							sizeof (__lhip_our_names_addr)
							/sizeof (__lhip_our_names_addr[0]) )
						{
							break;
						}
					}
					i++;
				}
			}
			if ( localaddr_found == 0 )
			{
				/* Not found = not saved. Free the allocated memory */
				if ( __lhip_tmp.h_name != NULL ) free (__lhip_tmp.h_name);
				if ( __lhip_tmp.h_aliases != NULL )
				{
					j = 0;
					while ( __lhip_tmp.h_aliases[j] != NULL )
					{
						free (__lhip_tmp.h_aliases[j]);
						j++;
					}
					free (__lhip_tmp.h_aliases);
				}
				if ( __lhip_tmp.h_addr_list != NULL )
				{
					j = 0;
					while ( __lhip_tmp.h_addr_list[j] != NULL )
					{
						free (__lhip_tmp.h_addr_list[j]);
						j++;
					}
					free (__lhip_tmp.h_addr_list);
				}
			}
		} /* ai_res == 0 ... */
	}
	else
# endif
	if (__lhip_real_gethostbyaddr_location () != NULL)
	{
		ai_res = inet_aton ("127.0.0.1", &lhip_addr);
		if ( ai_res != 0 )
		{
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_name = NULL;
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases = NULL;
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list = NULL;
			__lhip_our_real_name_ipv4 = (*__lhip_real_gethostbyaddr_location ())
				(&lhip_addr, sizeof (struct in_addr), AF_INET);
			if ( __lhip_our_real_name_ipv4 != NULL )
			{
# ifdef HAVE_MALLOC
				if ( __lhip_our_real_name_ipv4->h_name != NULL )
				{
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_name
						= (char *) malloc (strlen (__lhip_our_real_name_ipv4->h_name) + 1);
					if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name != NULL )
					{
						strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name,
							__lhip_our_real_name_ipv4->h_name,
							strlen (__lhip_our_real_name_ipv4->h_name) + 1 );
					}
				}
				j = 0;
				if ( __lhip_our_real_name_ipv4->h_aliases != NULL )
				{
					while ( __lhip_our_real_name_ipv4->h_aliases[j] != NULL )
					{
						j++;
					}
				}
				__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases
					= (char **) malloc ( j * sizeof (char *) + 1);
				if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases != NULL )
				{
					for ( i=0; i < j; i++ )
					{
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] =
							(char *) malloc ( strlen
								(__lhip_our_real_name_ipv4->h_aliases[i]) + 1);
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] != NULL )
						{
							strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i],
								__lhip_our_real_name_ipv4->h_aliases[i],
								strlen (__lhip_our_real_name_ipv4->h_aliases[i]) + 1 );
						}
					}
				}
				j = 0;
				if ( __lhip_our_real_name_ipv4->h_addr_list != NULL )
				{
					while ( __lhip_our_real_name_ipv4->h_addr_list[j] != NULL )
					{
						j++;
					}
				}
				if ( __lhip_our_real_name_ipv4->h_length > 0 )
				{
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list
						= (char **) malloc ( j * sizeof (char *) + 1);
					if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list != NULL )
					{
						for ( i=0; i < j; i++ )
						{
							__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] =
								(char *) malloc ( (size_t) __lhip_our_real_name_ipv4->h_length );
							if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] != NULL )
							{
#  ifdef HAVE_MEMCPY
								memcpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i],
									__lhip_our_real_name_ipv4->h_addr_list[i],
									(size_t) __lhip_our_real_name_ipv4->h_length );
#  else
								for ( k=0; k < __lhip_our_real_name_ipv4->h_length; k++ )
								{
									__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i][k]
										= __lhip_our_real_name_ipv4->h_addr_list[i][k];
								}
#  endif
							}
						}
					}
				}
				__lhip_our_names_addr[__lhip_number_of_hostnames].h_addrtype
					= __lhip_our_real_name_ipv4->h_addrtype;
				__lhip_our_names_addr[__lhip_number_of_hostnames].h_length
					= __lhip_our_real_name_ipv4->h_length;
# else
				__lhip_our_names_addr[__lhip_number_of_hostnames]
					= *__lhip_our_real_name_ipv4;
# endif /* HAVE_MALLOC */
				__lhip_number_of_hostnames++;
			} /* __lhip_our_real_name_ipv4 != NULL */
		}
# ifdef HAVE_MEMCPY
		memcpy (&lhip_addr6, __lhip_localhost_ipv6, sizeof (__lhip_localhost_ipv6));
# else
		for ( k = 0; k < sizeof (__lhip_localhost_ipv6); k++ )
		{
			((char *)&(lhip_addr6))[k] = __lhip_localhost_ipv6[k];
		}
# endif
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_name = NULL;
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases = NULL;
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list = NULL;
		__lhip_our_real_name_ipv6 = (*__lhip_real_gethostbyaddr_location ())
			(&lhip_addr6, sizeof (struct in6_addr), AF_INET6);
		if ( __lhip_our_real_name_ipv6 != NULL )
		{
# ifdef HAVE_MALLOC
			if ( __lhip_our_real_name_ipv6->h_name != NULL )
			{
				__lhip_our_names_addr[__lhip_number_of_hostnames].h_name
					= (char *) malloc (strlen (__lhip_our_real_name_ipv6->h_name) + 1);
				if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name != NULL )
				{
					strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name,
						__lhip_our_real_name_ipv6->h_name,
						strlen (__lhip_our_real_name_ipv6->h_name) + 1 );
				}
			}
			j = 0;
			if ( __lhip_our_real_name_ipv6->h_aliases != NULL )
			{
				while ( __lhip_our_real_name_ipv6->h_aliases[j] != NULL )
				{
					j++;
				}
			}
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases
				= (char **) malloc ( j * sizeof (char *) + 1);
			if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases != NULL )
			{
				for ( i=0; i < j; i++ )
				{
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] =
						(char *) malloc ( strlen
							(__lhip_our_real_name_ipv6->h_aliases[i]) + 1);
					if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] != NULL )
					{
						strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i],
							__lhip_our_real_name_ipv6->h_aliases[i],
							strlen (__lhip_our_real_name_ipv6->h_aliases[i]) + 1 );
					}
				}
			}
			j = 0;
			if ( __lhip_our_real_name_ipv6->h_addr_list != NULL )
			{
				while ( __lhip_our_real_name_ipv6->h_addr_list[j] != NULL )
				{
					j++;
				}
			}
			if ( __lhip_our_real_name_ipv6->h_length > 0 )
			{
				__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list
					= (char **) malloc ( j * sizeof (char *) + 1);
				if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list != NULL )
				{
					for ( i=0; i < j; i++ )
					{
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] =
							(char *) malloc ( (size_t) __lhip_our_real_name_ipv6->h_length );
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] != NULL )
						{
#  ifdef HAVE_MEMCPY
							memcpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i],
								__lhip_our_real_name_ipv6->h_addr_list[i],
								(size_t) __lhip_our_real_name_ipv6->h_length );
#  else
							for ( k=0; k < __lhip_our_real_name_ipv6->h_length; k++ )
							{
								__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i][k]
									= __lhip_our_real_name_ipv6->h_addr_list[i][k];
							}
#  endif
						}
					}
				}
			}
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_addrtype
				= __lhip_our_real_name_ipv6->h_addrtype;
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_length
				= __lhip_our_real_name_ipv6->h_length;
# else
			__lhip_our_names_addr[__lhip_number_of_hostnames]
				= *__lhip_our_real_name_ipv6;
# endif /* HAVE_MALLOC */
			__lhip_number_of_hostnames++;
		} /* __lhip_our_real_name_ipv4 != NULL */
	}

#endif	/* HAVE_ARPA_INET_H */

	if (__lhip_real_gethostbyname_r_location () != NULL)
	{
		if (__lhip_our_gethostname[0] != '\0')
		{
			ai_res = (*__lhip_real_gethostbyname_r_location ()) (__lhip_our_gethostname,
				&(__lhip_our_names_addr[__lhip_number_of_hostnames]),
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&hostent_res, &lhip_errno);
			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				/* copy the data to our buffers */
				__lhip_tmp.h_name = NULL;
				__lhip_tmp.h_aliases = NULL;
				__lhip_tmp.h_addr_list = NULL;
				if ( hostent_res->h_name != NULL )
				{
					__lhip_tmp.h_name = (char *) malloc (strlen (hostent_res->h_name)+1);
					if ( __lhip_tmp.h_name != NULL )
					{
						strncpy ( __lhip_tmp.h_name, hostent_res->h_name,
							strlen (hostent_res->h_name)+1 );
					}
				}
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						j++;
					}
					/* "+1" for the NULL pointer */
					__lhip_tmp.h_aliases = (char **)
						malloc ((j+1) * sizeof (char *));
					if ( __lhip_tmp.h_aliases != NULL )
					{
						for ( i = 0; i < j; i++ )
						{
							__lhip_tmp.h_aliases[i] = (char *)
								malloc (strlen
									(hostent_res->h_aliases[i])+1);
							if ( __lhip_tmp.h_aliases[i] != NULL )
							{
								strncpy (__lhip_tmp.h_aliases[i],
									hostent_res->h_aliases[i],
									strlen (hostent_res->h_aliases[i])+1);
							}
						}
						/* end-of-list marker */
						__lhip_tmp.h_aliases[j] = NULL;
					}
				}
				if ( hostent_res->h_addr_list != NULL )
				{
					j = 0;
					while (hostent_res->h_addr_list[j] != NULL)
					{
						j++;
					}
					if ( j > 0 )
					{
						/* "+1" for the NULL pointer */
						__lhip_tmp.h_addr_list = (char **)
							malloc ((j+1) * sizeof (char *));
						if ( (__lhip_tmp.h_addr_list != NULL)
							&& (hostent_res->h_length > 0) )
						{
							for ( i = 0; i < j; i++ )
							{
								__lhip_tmp.h_addr_list[i] = (char *)
									malloc ((size_t) (hostent_res->h_length));
								if ( __lhip_tmp.h_addr_list[i] != NULL )
								{
#ifdef HAVE_MEMCPY
									memcpy (__lhip_tmp.h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) (hostent_res->h_length));
#else
									for (k=0; k < hostent_res->h_length; k++)
									{
										__lhip_tmp.h_addr_list[i][k] =
											hostent_res->h_addr_list[i][k];
									}
#endif
								}
							}
							/* end-of-list marker */
							__lhip_tmp.h_addr_list[j] = NULL;
						}
					}
				}
#ifdef HAVE_MEMCPY
				memcpy ( &(__lhip_our_names_addr[__lhip_number_of_hostnames]),
					&__lhip_tmp, sizeof (struct hostent) );
#else
				for (k=0; k < sizeof (struct hostent); k++)
				{
					((char *)&(__lhip_our_names_addr[__lhip_number_of_hostnames]))[k] =
						((char *)&__lhip_tmp)[k];
				}
#endif
				__lhip_number_of_hostnames++;
			}
		}
		if ( __lhip_uname_res.nodename[0] != '\0' )
		{
			ai_res = (*__lhip_real_gethostbyname_r_location ()) (__lhip_our_gethostname,
				&(__lhip_our_names_addr[__lhip_number_of_hostnames]),
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&hostent_res, &lhip_errno);
			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				/* copy the data to our buffers */
				__lhip_tmp.h_name = NULL;
				__lhip_tmp.h_aliases = NULL;
				__lhip_tmp.h_addr_list = NULL;
				if ( hostent_res->h_name != NULL )
				{
					__lhip_tmp.h_name = (char *) malloc (strlen (hostent_res->h_name)+1);
					if ( __lhip_tmp.h_name != NULL )
					{
						strncpy ( __lhip_tmp.h_name, hostent_res->h_name,
							strlen (hostent_res->h_name)+1 );
					}
				}
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						j++;
					}
					/* "+1" for the NULL pointer */
					__lhip_tmp.h_aliases = (char **)
						malloc ((j+1) * sizeof (char *));
					if ( __lhip_tmp.h_aliases != NULL )
					{
						for ( i = 0; i < j; i++ )
						{
							__lhip_tmp.h_aliases[i] = (char *)
								malloc (strlen
									(hostent_res->h_aliases[i])+1);
							if ( __lhip_tmp.h_aliases[i] != NULL )
							{
								strncpy (__lhip_tmp.h_aliases[i],
									hostent_res->h_aliases[i],
									strlen (hostent_res->h_aliases[i])+1);
							}
						}
						/* end-of-list marker */
						__lhip_tmp.h_aliases[j] = NULL;
					}
				}
				if ( hostent_res->h_addr_list != NULL )
				{
					j = 0;
					while (hostent_res->h_addr_list[j] != NULL)
					{
						j++;
					}
					if ( j > 0 )
					{
						/* "+1" for the NULL pointer */
						__lhip_tmp.h_addr_list = (char **)
							malloc ((j+1) * sizeof (char *));
						if ( (__lhip_tmp.h_addr_list != NULL)
							&& (hostent_res->h_length > 0) )
						{
							for ( i = 0; i < j; i++ )
							{
								__lhip_tmp.h_addr_list[i] = (char *)
									malloc ((size_t) (hostent_res->h_length));
								if ( __lhip_tmp.h_addr_list[i] != NULL )
								{
#ifdef HAVE_MEMCPY
									memcpy (__lhip_tmp.h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) (hostent_res->h_length));
#else
									for (k=0; k < hostent_res->h_length; k++)
									{
										__lhip_tmp.h_addr_list[i][k] =
											hostent_res->h_addr_list[i][k];
									}
#endif
								}
							}
							/* end-of-list marker */
							__lhip_tmp.h_addr_list[j] = NULL;
						}
					}
				}
#ifdef HAVE_MEMCPY
				memcpy ( &(__lhip_our_names_addr[__lhip_number_of_hostnames]),
					&__lhip_tmp, sizeof (struct hostent) );
#else
				for (k=0; k < sizeof (struct hostent); k++)
				{
					((char *)&(__lhip_our_names_addr[__lhip_number_of_hostnames]))[k] =
						((char *)&__lhip_tmp)[k];
				}
#endif
				__lhip_number_of_hostnames++;
			}
		}
	}
	else if (__lhip_real_gethostbyname_location () != NULL)
	{
		if ( __lhip_our_gethostname[0] != '\0' )
		{
			hostent_res = (*__lhip_real_gethostbyname_location ()) (__lhip_our_gethostname);
			if ( hostent_res != NULL )
			{
				/* copy the data to our buffers */
				__lhip_tmp.h_name = NULL;
				__lhip_tmp.h_aliases = NULL;
				__lhip_tmp.h_addr_list = NULL;
				if ( hostent_res->h_name != NULL )
				{
					__lhip_tmp.h_name = (char *) malloc (strlen (hostent_res->h_name)+1);
					if ( __lhip_tmp.h_name != NULL )
					{
						strncpy ( __lhip_tmp.h_name, hostent_res->h_name,
							strlen (hostent_res->h_name)+1 );
					}
				}
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						j++;
					}
					/* "+1" for the NULL pointer */
					__lhip_tmp.h_aliases = (char **)
						malloc ((j+1) * sizeof (char *));
					if ( __lhip_tmp.h_aliases != NULL )
					{
						for ( i = 0; i < j; i++ )
						{
							__lhip_tmp.h_aliases[i] = (char *)
								malloc (strlen
									(hostent_res->h_aliases[i])+1);
							if ( __lhip_tmp.h_aliases[i] != NULL )
							{
								strncpy (__lhip_tmp.h_aliases[i],
									hostent_res->h_aliases[i],
									strlen (hostent_res->h_aliases[i])+1);
							}
						}
						/* end-of-list marker */
						__lhip_tmp.h_aliases[j] = NULL;
					}
				}
				if ( hostent_res->h_addr_list != NULL )
				{
					j = 0;
					while (hostent_res->h_addr_list[j] != NULL)
					{
						j++;
					}
					if ( j > 0 )
					{
						/* "+1" for the NULL pointer */
						__lhip_tmp.h_addr_list = (char **)
							malloc ((j+1) * sizeof (char *));
						if ( (__lhip_tmp.h_addr_list != NULL)
							&& (hostent_res->h_length > 0) )
						{
							for ( i = 0; i < j; i++ )
							{
								__lhip_tmp.h_addr_list[i] = (char *)
									malloc ((size_t) (hostent_res->h_length));
								if ( __lhip_tmp.h_addr_list[i] != NULL )
								{
#ifdef HAVE_MEMCPY
									memcpy (__lhip_tmp.h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) (hostent_res->h_length));
#else
									for (k=0; k < hostent_res->h_length; k++)
									{
										__lhip_tmp.h_addr_list[i][k] =
											hostent_res->h_addr_list[i][k];
									}
#endif
								}
							}
							/* end-of-list marker */
							__lhip_tmp.h_addr_list[j] = NULL;
						}
					}
				}
#ifdef HAVE_MEMCPY
				memcpy ( &(__lhip_our_names_addr[__lhip_number_of_hostnames]),
					&__lhip_tmp, sizeof (struct hostent) );
#else
				for (k=0; k < sizeof (struct hostent); k++)
				{
					((char *)&(__lhip_our_names_addr[__lhip_number_of_hostnames]))[k] =
						((char *)&__lhip_tmp)[k];
				}
#endif
				__lhip_number_of_hostnames++;
			}
		}
		if ( __lhip_uname_res.nodename[0] != '\0' )
		{
			hostent_res = (*__lhip_real_gethostbyname_location ()) (__lhip_uname_res.nodename);
			if ( hostent_res != NULL )
			{
				/* copy the data to our buffers */
				__lhip_tmp.h_name = NULL;
				__lhip_tmp.h_aliases = NULL;
				__lhip_tmp.h_addr_list = NULL;
				if ( hostent_res->h_name != NULL )
				{
					__lhip_tmp.h_name = (char *) malloc (strlen (hostent_res->h_name)+1);
					if ( __lhip_tmp.h_name != NULL )
					{
						strncpy ( __lhip_tmp.h_name, hostent_res->h_name,
							strlen (hostent_res->h_name)+1 );
					}
				}
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						j++;
					}
					/* "+1" for the NULL pointer */
					__lhip_tmp.h_aliases = (char **)
						malloc ((j+1) * sizeof (char *));
					if ( __lhip_tmp.h_aliases != NULL )
					{
						for ( i = 0; i < j; i++ )
						{
							__lhip_tmp.h_aliases[i] = (char *)
								malloc (strlen
									(hostent_res->h_aliases[i])+1);
							if ( __lhip_tmp.h_aliases[i] != NULL )
							{
								strncpy (__lhip_tmp.h_aliases[i],
									hostent_res->h_aliases[i],
									strlen (hostent_res->h_aliases[i])+1);
							}
						}
						/* end-of-list marker */
						__lhip_tmp.h_aliases[j] = NULL;
					}
				}
				if ( hostent_res->h_addr_list != NULL )
				{
					j = 0;
					while (hostent_res->h_addr_list[j] != NULL)
					{
						j++;
					}
					if ( j > 0 )
					{
						/* "+1" for the NULL pointer */
						__lhip_tmp.h_addr_list = (char **)
							malloc ((j+1) * sizeof (char *));
						if ( (__lhip_tmp.h_addr_list != NULL)
							&& (hostent_res->h_length > 0) )
						{
							for ( i = 0; i < j; i++ )
							{
								__lhip_tmp.h_addr_list[i] = (char *)
									malloc ((size_t) (hostent_res->h_length));
								if ( __lhip_tmp.h_addr_list[i] != NULL )
								{
#ifdef HAVE_MEMCPY
									memcpy (__lhip_tmp.h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) (hostent_res->h_length));
#else
									for (k=0; k < hostent_res->h_length; k++)
									{
										__lhip_tmp.h_addr_list[i][k] =
											hostent_res->h_addr_list[i][k];
									}
#endif
								}
							}
							/* end-of-list marker */
							__lhip_tmp.h_addr_list[j] = NULL;
						}
					}
				}
#ifdef HAVE_MEMCPY
				memcpy ( &(__lhip_our_names_addr[__lhip_number_of_hostnames]),
					&__lhip_tmp, sizeof (struct hostent) );
#else
				for (k=0; k < sizeof (struct hostent); k++)
				{
					((char *)&(__lhip_our_names_addr[__lhip_number_of_hostnames]))[k] =
						((char *)&__lhip_tmp)[k];
				}
#endif
				__lhip_number_of_hostnames++;
			}
		}
	}
	if (__lhip_real_getaddrinfo_location () != NULL)
	{
#ifdef HAVE_MEMSET
		memset (&ai_hints, 0, sizeof (struct addrinfo));
#else
		for ( i = 0; i < sizeof (struct addrinfo); i++ )
		{
			((char *)&(ai_hints))[i] = '\0';
		}
#endif
		ai_hints.ai_flags = /*AI_NUMERICHOST |*/ AI_CANONNAME;
		ai_hints.ai_family = AF_UNSPEC;
		ai_hints.ai_socktype = 0;
		ai_hints.ai_protocol = 0;
		ai_hints.ai_addr = NULL;
		ai_hints.ai_canonname = NULL;
		ai_hints.ai_next = NULL;
		ai_res = (*__lhip_real_getaddrinfo_location ()) ("127.0.0.1", NULL /* service */,
			&ai_hints, &__lhip_ai_all);
		if ( ai_res != 0 )
		{
			__lhip_ai_all = NULL;
		}
		if ( __lhip_uname_res.nodename[0] != '\0' )
		{
			ai_hints.ai_flags = AI_CANONNAME;
			ai_hints.ai_family = AF_UNSPEC;
			ai_hints.ai_socktype = 0;
			ai_hints.ai_protocol = 0;
			ai_hints.ai_addr = NULL;
			ai_hints.ai_canonname = NULL;
			ai_hints.ai_next = NULL;
			ai_res = (*__lhip_real_getaddrinfo_location ()) (__lhip_uname_res.nodename,
				NULL /* service */, &ai_hints, &__lhip_ai_all_tmp);
			if ( ai_res == 0 )
			{
				if ( __lhip_ai_all == NULL )
				{
					__lhip_ai_all = __lhip_ai_all_tmp;
				}
				else
				{
					/* join the lists: */
					tmp = __lhip_ai_all;
					do
					{
						if ( tmp->ai_next == NULL ) break;
						tmp = tmp->ai_next;
					} while (1==1);
					tmp->ai_next = __lhip_ai_all_tmp;
				}
			}
		}
		if ( __lhip_our_gethostname[0] != '\0' )
		{
			ai_hints.ai_flags = AI_CANONNAME;
			ai_hints.ai_family = AF_UNSPEC;
			ai_hints.ai_socktype = 0;
			ai_hints.ai_protocol = 0;
			ai_hints.ai_addr = NULL;
			ai_hints.ai_canonname = NULL;
			ai_hints.ai_next = NULL;
			ai_res = (*__lhip_real_getaddrinfo_location ()) (__lhip_our_gethostname,
				NULL /* service */, &ai_hints, &__lhip_ai_all_tmp);
			if ( ai_res == 0 )
			{
				if ( __lhip_ai_all == NULL )
				{
					__lhip_ai_all = __lhip_ai_all_tmp;
				}
				else
				{
					/* join the lists: */
					tmp = __lhip_ai_all;
					do
					{
						if ( tmp->ai_next == NULL ) break;
						tmp = tmp->ai_next;
					} while (1==1);
					tmp->ai_next = __lhip_ai_all_tmp;
				}
			}
		}
	}

	if (__lhip_real_gethostent_r_location () != NULL)
	{
		do
		{
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_name = NULL;
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases = NULL;
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list = NULL;
			ai_res = (*__lhip_real_gethostent_r_location ()) (
				&(__lhip_our_names_addr[__lhip_number_of_hostnames]),
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&hostent_res, &lhip_errno);

			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				/* make a copy of the data */
				__lhip_tmp.h_name = NULL;
				__lhip_tmp.h_aliases = NULL;
				__lhip_tmp.h_addr_list = NULL;
				if ( hostent_res->h_name != NULL )
				{
					__lhip_tmp.h_name = (char *) malloc (strlen (hostent_res->h_name)+1);
					if ( __lhip_tmp.h_name != NULL )
					{
						strncpy ( __lhip_tmp.h_name, hostent_res->h_name,
							strlen (hostent_res->h_name)+1 );
					}
				}
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						j++;
					}
					/* "+1" for the NULL pointer */
					__lhip_tmp.h_aliases = (char **)
						malloc ((j+1) * sizeof (char *));
					if ( __lhip_tmp.h_aliases != NULL )
					{
						for ( i = 0; i < j; i++ )
						{
							__lhip_tmp.h_aliases[i] = (char *)
								malloc (strlen
									(hostent_res->h_aliases[i])+1);
							if ( __lhip_tmp.h_aliases[i] != NULL )
							{
								strncpy (__lhip_tmp.h_aliases[i],
									hostent_res->h_aliases[i],
									strlen (hostent_res->h_aliases[i])+1);
							}
						}
						/* end-of-list marker */
						__lhip_tmp.h_aliases[j] = NULL;
					}
				}
				if ( (hostent_res->h_addr_list != NULL)
						&& (hostent_res->h_length > 0) )
				{
					j = 0;
					while (hostent_res->h_addr_list[j] != NULL)
					{
						j++;
					}
					if ( j > 0 )
					{
						/* "+1" for the NULL pointer */
						__lhip_tmp.h_addr_list = (char **)
							malloc ((j+1) * sizeof (char *));
						if ( __lhip_tmp.h_addr_list != NULL )
						{
							for ( i = 0; i < j; i++ )
							{
								__lhip_tmp.h_addr_list[i] = (char *)
									malloc ((size_t) (hostent_res->h_length));
								if ( __lhip_tmp.h_addr_list[i] != NULL )
								{
#  ifdef HAVE_MEMCPY
									memcpy (__lhip_tmp.h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) (hostent_res->h_length));
#  else
									for (k=0; k < hostent_res->h_length; k++)
									{
										__lhip_tmp.h_addr_list[i][k] =
											hostent_res->h_addr_list[i][k];
									}
#  endif
								}
							}
							/* end-of-list marker */
							__lhip_tmp.h_addr_list[j] = NULL;
						}
					}
				}
#  ifdef HAVE_MEMCPY
				memcpy ( &(__lhip_our_names_addr[__lhip_number_of_hostnames]),
					&__lhip_tmp, sizeof (struct hostent) );
#  else
				for (k=0; k < sizeof (struct hostent); k++)
				{
					((char *)&(__lhip_our_names_addr[__lhip_number_of_hostnames]))[k] =
						((char *)&__lhip_tmp)[k];
				}
#  endif
				/* finished copying data */

				localaddr_found = 0;
				if ( hostent_res->h_name != NULL )
				{
					if ( __lhip_check_hostname_match (__lhip_our_gethostname,
						hostent_res->h_name) == 1 )
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
						if ( __lhip_number_of_hostnames >=
							sizeof (__lhip_our_names_addr)
							/sizeof (__lhip_our_names_addr[0]) )
						{
							break;
						}
					}
				}
				if ( localaddr_found != 0 ) continue;
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						if ( __lhip_check_hostname_match (
							__lhip_our_gethostname,
							hostent_res->h_aliases[j]) == 1 )
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							break;
						}
						j++;
					}
					if ( __lhip_number_of_hostnames >=
						sizeof (__lhip_our_names_addr)
						/sizeof (__lhip_our_names_addr[0]) )
					{
						break;
					}
				}
				if ( localaddr_found != 0 ) continue;
				if ( hostent_res->h_name != NULL )
				{
					if ( __lhip_check_hostname_match (
						__lhip_uname_res.nodename,
						hostent_res->h_name) == 1 )
					{
						__lhip_number_of_hostnames++;
						localaddr_found = 1;
						if ( __lhip_number_of_hostnames >=
							sizeof (__lhip_our_names_addr)
							/sizeof (__lhip_our_names_addr[0]) )
						{
							break;
						}
					}
				}
				if ( localaddr_found != 0 ) continue;
				if ( hostent_res->h_aliases != NULL )
				{
					j = 0;
					while (hostent_res->h_aliases[j] != NULL)
					{
						if ( __lhip_check_hostname_match (
							__lhip_uname_res.nodename,
							hostent_res->h_aliases[j]) == 1 )
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							break;
						}
						j++;
					}
					if ( __lhip_number_of_hostnames >=
						sizeof (__lhip_our_names_addr)
						/sizeof (__lhip_our_names_addr[0]) )
					{
						break;
					}
				}
				if ( localaddr_found != 0 ) continue;
				if ( hostent_res->h_addr_list != NULL )
				{
					i = 0;
					while ( hostent_res->h_addr_list[i] != NULL )
					{
						if ( (hostent_res->h_addrtype == AF_INET)
							&& (memcmp (hostent_res->h_addr_list[i],
								__lhip_localhost_ipv4,
								sizeof (__lhip_localhost_ipv4) ) == 0)
						)
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							if ( __lhip_number_of_hostnames >=
								sizeof (__lhip_our_names_addr)
								/sizeof (__lhip_our_names_addr[0]) )
							{
								break;
							}
						}
						if ( (hostent_res->h_addrtype == AF_INET6)
							&& (memcmp (hostent_res->h_addr_list[i],
								__lhip_localhost_ipv6,
								sizeof (__lhip_localhost_ipv6) ) == 0)
						)
						{
							__lhip_number_of_hostnames++;
							localaddr_found = 1;
							if ( __lhip_number_of_hostnames >=
								sizeof (__lhip_our_names_addr)
								/sizeof (__lhip_our_names_addr[0]) )
							{
								break;
							}
						}
						i++;
					}
				}
				if ( localaddr_found == 0 )
				{
					/* Not found = not saved. Free the allocated memory */
					if ( __lhip_tmp.h_name != NULL ) free (__lhip_tmp.h_name);
					if ( __lhip_tmp.h_aliases != NULL )
					{
						j = 0;
						while ( __lhip_tmp.h_aliases[j] != NULL )
						{
							free (__lhip_tmp.h_aliases[j]);
							j++;
						}
						free (__lhip_tmp.h_aliases);
					}
					if ( __lhip_tmp.h_addr_list != NULL )
					{
						j = 0;
						while ( __lhip_tmp.h_addr_list[j] != NULL )
						{
							free (__lhip_tmp.h_addr_list[j]);
							j++;
						}
						free (__lhip_tmp.h_addr_list);
					}
				}
			}
		} while ( (ai_res == 0) && (hostent_res != NULL) );
	}
	else if (__lhip_real_gethostent_location () != NULL)
	{
#ifndef HAVE_MALLOC
		localaddr_found = 0;
#endif
		do
		{
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_name = NULL;
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases = NULL;
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list = NULL;
			hostent_res = (*__lhip_real_gethostent_location ()) ();
			if ( hostent_res == NULL ) break;
			i = 0;
			while ( hostent_res->h_addr_list[i] != NULL )
			{
				if ( (hostent_res->h_addrtype == AF_INET)
					&& (memcmp (hostent_res->h_addr_list[i],
						__lhip_localhost_ipv4,
						sizeof (__lhip_localhost_ipv4) ) == 0) )
				{
#ifdef HAVE_MALLOC
					if ( hostent_res->h_name != NULL )
					{
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_name
							= (char *) malloc (strlen (hostent_res->h_name) + 1);
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name != NULL )
						{
							strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name,
								hostent_res->h_name,
								strlen (hostent_res->h_name) + 1 );
						}
					}
					j = 0;
					if ( hostent_res->h_aliases != NULL )
					{
						while ( hostent_res->h_aliases[j] != NULL )
						{
							j++;
						}
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases
							= (char **) malloc ( j * sizeof (char *) + 1);
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases != NULL )
						{
							for ( i=0; i < j; i++ )
							{
								__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] =
									(char *) malloc ( strlen
										(hostent_res->h_aliases[i]) + 1);
								if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] != NULL )
								{
									strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i],
										hostent_res->h_aliases[i],
										strlen (hostent_res->h_aliases[i]) + 1 );
								}
							}
						}
					}
					j = 0;
					if ( hostent_res->h_addr_list != NULL )
					{
						while ( hostent_res->h_addr_list[j] != NULL )
						{
							j++;
						}
					}
					if ( hostent_res->h_length > 0 )
					{
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list
							= (char **) malloc ( j * sizeof (char *) + 1);
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list != NULL )
						{
							for ( i=0; i < j; i++ )
							{
								__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] =
									(char *) malloc ( (size_t) hostent_res->h_length );
								if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] != NULL )
								{
#  ifdef HAVE_MEMCPY
									memcpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) hostent_res->h_length );
#  else
									for ( k=0; k < hostent_res->h_length; k++ )
									{
										__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i][k]
											= hostent_res->h_addr_list[i][k];
									}
#  endif
								}
							}
						}
					}
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_addrtype
						= hostent_res->h_addrtype;
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_length
						= hostent_res->h_length;
# else
					__lhip_our_names_addr[__lhip_number_of_hostnames]
						= *hostent_res;
					localaddr_found = 1;
# endif /* HAVE_MALLOC */
					__lhip_number_of_hostnames++;
					if ( __lhip_number_of_hostnames >=
						sizeof (__lhip_our_names_addr)
						/sizeof (__lhip_our_names_addr[0]) )
					{
						break;
					}
				}
				else if ( (hostent_res->h_addrtype == AF_INET6)
					&& (memcmp (hostent_res->h_addr_list[i],
						__lhip_localhost_ipv6,
						sizeof (__lhip_localhost_ipv6) ) == 0) )
				{
#ifdef HAVE_MALLOC
					if ( hostent_res->h_name != NULL )
					{
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_name
							= (char *) malloc (strlen (hostent_res->h_name) + 1);
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name != NULL )
						{
							strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_name,
								hostent_res->h_name,
								strlen (hostent_res->h_name) + 1 );
						}
					}
					j = 0;
					if ( hostent_res->h_aliases != NULL )
					{
						while ( hostent_res->h_aliases[j] != NULL )
						{
							j++;
						}
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases
							= (char **) malloc ( j * sizeof (char *) + 1);
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases != NULL )
						{
							for ( i=0; i < j; i++ )
							{
								__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] =
									(char *) malloc ( strlen
										(hostent_res->h_aliases[i]) + 1);
								if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] != NULL )
								{
									strncpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i],
										hostent_res->h_aliases[i],
										strlen (hostent_res->h_aliases[i]) + 1 );
								}
							}
						}
					}
					j = 0;
					if ( hostent_res->h_addr_list != NULL )
					{
						while ( hostent_res->h_addr_list[j] != NULL )
						{
							j++;
						}
					}
					if ( hostent_res->h_length > 0 )
					{
						__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list
							= (char **) malloc ( j * sizeof (char *) + 1);
						if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list != NULL )
						{
							for ( i=0; i < j; i++ )
							{
								__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] =
									(char *) malloc ( (size_t) hostent_res->h_length );
								if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] != NULL )
								{
#  ifdef HAVE_MEMCPY
									memcpy ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i],
										hostent_res->h_addr_list[i],
										(size_t) hostent_res->h_length );
#  else
									for ( k=0; k < hostent_res->h_length; k++ )
									{
										__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i][k]
											= hostent_res->h_addr_list[i][k];
									}
#  endif
								}
							}
						}
					}
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_addrtype
						= hostent_res->h_addrtype;
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_length
						= hostent_res->h_length;
# else
					__lhip_our_names_addr[__lhip_number_of_hostnames]
						= *hostent_res;
					localaddr_found = 1;
# endif /* HAVE_MALLOC */
					__lhip_number_of_hostnames++;
					if ( __lhip_number_of_hostnames >=
						sizeof (__lhip_our_names_addr)
						/sizeof (__lhip_our_names_addr[0]) )
					{
						break;
					}
				}
				i++;
			}
		} while ( (hostent_res != NULL)
#ifndef HAVE_MALLOC
			&& (localaddr_found == 0)
#endif
			);
	}

	if (__lhip_real_getnameinfo_location () != NULL)
	{
		addr_ipv4.sin_family = AF_INET;
#ifdef HAVE_MEMCPY
		memcpy (&(addr_ipv4.sin_addr.s_addr), __lhip_localhost_ipv4,
			sizeof (struct in_addr));
#else
		for ( k = 0; k < sizeof (struct in_addr); k++ )
		{
			((char *)&(addr_ipv4.sin_addr.s_addr))[k] = __lhip_localhost_ipv4[k];
		}
#endif
		ai_res = (*__lhip_real_getnameinfo_location ()) ((struct sockaddr *)&addr_ipv4,
			sizeof (struct sockaddr_in), __lhip_our_hostname_v4,
			sizeof (__lhip_our_hostname_v4), NULL, 0, 0);
		if ( ai_res != 0 )
		{
#ifdef HAVE_MEMSET
			memset (__lhip_our_hostname_v4, 0, sizeof (__lhip_our_hostname_v4));
#else
			for ( i = 0; i < sizeof (__lhip_our_hostname_v4); i++ )
			{
				__lhip_our_hostname_v4[i] = '\0';
			}
#endif
		}
		addr_ipv6.sin6_family = AF_INET6;
#ifdef HAVE_MEMCPY
		memcpy (&(addr_ipv6.sin6_addr), __lhip_localhost_ipv6,
			sizeof (struct in6_addr));
#else
		for ( k = 0; k < sizeof (struct in6_addr); k++ )
		{
			((char *)&(addr_ipv6.sin6_addr))[k] = __lhip_localhost_ipv6[k];
		}
#endif
		ai_res = (*__lhip_real_getnameinfo_location ()) ((struct sockaddr *)&addr_ipv6,
			sizeof (struct sockaddr_in6), __lhip_our_hostname_v6,
			sizeof (__lhip_our_hostname_v6), NULL, 0, 0);
		if ( ai_res != 0 )
		{
#ifdef HAVE_MEMSET
			memset (__lhip_our_hostname_v6, 0, sizeof (__lhip_our_hostname_v6));
#else
			for ( i = 0; i < sizeof (__lhip_our_hostname_v6); i++ )
			{
				__lhip_our_hostname_v6[i] = '\0';
			}
#endif
		}
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
#ifdef LHIP_DEBUG
	fprintf (stderr, "LibHideIP: Got addresses and aliases:\n");
	fflush (stderr);
# ifndef HAVE_MALLOC
	if ( __lhip_our_real_name_ipv4 != NULL )
	{
		fprintf (stderr, "LibHideIP: 1: name=%s, lhip_addr=0x%x\n",
			(__lhip_our_real_name_ipv4->h_name == NULL)? "null" :
				__lhip_our_real_name_ipv4->h_name);
		if (__lhip_our_real_name_ipv4.h_addr_list != NULL )
		{
			j = 0;
			while ( __lhip_our_real_name_ipv4.h_addr_list[j] != NULL )
			{
				fprintf (stderr, ", lhip_addr=0x%x",
					((struct in_addr *)(__lhip_our_real_name_ipv4.h_addr_list[j]))->s_addr
					);
				fflush (stderr);
				j++;
			}
		}
		fprintf (stderr, "\n");
		fflush (stderr);
	}
	if ( __lhip_our_real_name_ipv6 != NULL )
	{
		fprintf (stderr, "LibHideIP: 2: name=%s, lhip_addr=0x%x\n",
			(__lhip_our_real_name_ipv6->h_name == NULL)? "null" :
				__lhip_our_real_name_ipv6->h_name);
		if (__lhip_our_real_name_ipv6.h_addr_list != NULL )
		{
			j = 0;
			while ( __lhip_our_real_name_ipv6.h_addr_list[j] != NULL )
			{
				fprintf (stderr, ", lhip_addr=0x%x",
					((struct in_addr *)(__lhip_our_real_name_ipv6.h_addr_list[j]))->s_addr
					);
				fflush (stderr);
				j++;
			}
		}
		fprintf (stderr, "\n");
		fflush (stderr);
	}
# else
	fprintf (stderr, "HAVE_MALLOC, so skipping gethostbyaddr()\n");
	fflush (stderr);
# endif
	if ( __lhip_ai_all != NULL )
	{
		tmp = __lhip_ai_all;
		while ( tmp != NULL )
		{
			fprintf (stderr, "LibHideIP: 3: name=%s, lhip_addr=0x%x\n",
				(tmp->ai_canonname == NULL)? "null" : tmp->ai_canonname,
				((struct sockaddr_in *)(tmp->ai_addr))->sin_addr.s_addr);
			fflush (stderr);
			tmp = tmp->ai_next;
		}
	}
	fprintf (stderr, "LibHideIP: 4: name_v4=%s\n",
		(__lhip_our_hostname_v4 == NULL)? "null" : __lhip_our_hostname_v4);
	fflush (stderr);
	fprintf (stderr, "LibHideIP: 5: name_v6=%s\n",
		(__lhip_our_hostname_v6 == NULL)? "null" : __lhip_our_hostname_v6);
	fflush (stderr);
	for ( i=0; i < __lhip_number_of_hostnames; i++ )
	{
		fprintf (stderr, "LibHideIP: 6+%d: name=%s", i,
			(__lhip_our_names_addr[i].h_name == NULL)? "null" :
				__lhip_our_names_addr[i].h_name);
		if (__lhip_our_names_addr[i].h_addr_list != NULL )
		{
			j = 0;
			while ( __lhip_our_names_addr[i].h_addr_list[j] != NULL )
			{
				fprintf (stderr, ", lhip_addr=0x%x",
					((struct in_addr *)(__lhip_our_names_addr[i].h_addr_list[j]))->s_addr
					);
				fflush (stderr);
				j++;
			}
		}
		fprintf (stderr, "\n");
		fflush (stderr);
	}
	fprintf (stderr, "LibHideIP: 7: name=%s\n", __lhip_uname_res.nodename);
	fflush (stderr);
	fprintf (stderr, "LibHideIP: 8: name=%s\n", __lhip_our_gethostname);
	fflush (stderr);
#endif	/* LHIP_DEBUG */
}

/* =============================================================== */

struct hostent *
__lhip_get_our_name_ipv4 (
#ifdef LHIP_ANSIC
	void
#endif
)
{
	return __lhip_our_real_name_ipv4;
}

/* =============================================================== */

struct hostent *
__lhip_get_our_name_ipv6 (
#ifdef LHIP_ANSIC
	void
#endif
)
{
	return __lhip_our_real_name_ipv6;
}

/* =============================================================== */

int
__lhip_is_local_addr (
#ifdef LHIP_ANSIC
	const struct hostent * const h)
#else
	h)
	const struct hostent * const h;
#endif
{
	int i, j;
	unsigned int hi;
	struct addrinfo *tmp;

	if ( h == NULL ) return 0;
#ifndef HAVE_MALLOC
	if ( __lhip_our_real_name_ipv4 != NULL )
	{
		if ( __lhip_our_real_name_ipv4->h_name != NULL )
		{
			if ( h->h_name != NULL )
			{
				if ( __lhip_check_hostname_match (
					__lhip_our_real_name_ipv4->h_name,
					h->h_h_name) == 1 ) return 1;
			}
			if ( h->h_aliases != NULL )
			{
				i = 0;
				while (h->h_aliases[i] != NULL)
				{
					if ( __lhip_check_hostname_match (
						__lhip_our_real_name_ipv4->h_name,
						h->h_aliases[i]) == 1 ) return 1;
					i++;
				}
			}
		}
	}
	if ( __lhip_our_real_name_ipv6 != NULL )
	{
		if ( __lhip_our_real_name_ipv6->h_name != NULL )
		{
			if ( h->h_name != NULL )
			{
				if ( __lhip_check_hostname_match (
					__lhip_our_real_name_ipv6->h_name,
					h->h_name) == 1 ) return 1;
			}
			if ( h->h_aliases != NULL )
			{
				i = 0;
				while (h->h_aliases[i] != NULL)
				{
					if ( __lhip_check_hostname_match (
						__lhip_our_real_name_ipv6->h_name,
						h->h_aliases[i]) == 1 ) return 1;
					i++;
				}
			}
		}
	}
#endif	/* ! HAVE_MALLOC */

	if ( __lhip_our_real_name_ipv4 != NULL )
	{
		if ( __lhip_our_real_name_ipv4->h_aliases != NULL )
		{
			i = 0;
			while (__lhip_our_real_name_ipv4->h_aliases[i] != NULL)
			{
				if ( h->h_name != NULL )
				{
					if ( __lhip_check_hostname_match (
						__lhip_our_real_name_ipv4->h_aliases[i],
						h->h_name) == 1 ) return 1;
				}
				if ( h->h_aliases != NULL )
				{
					j = 0;
					while (h->h_aliases[j] != NULL)
					{
						if ( __lhip_check_hostname_match (
							__lhip_our_real_name_ipv4->h_aliases[i],
							h->h_aliases[j]) == 1 ) return 1;
						j++;
					}
				}
				i++;
			}
		}
	}

	if ( __lhip_our_real_name_ipv6 != NULL )
	{
		if ( __lhip_our_real_name_ipv6->h_aliases != NULL )
		{
			i = 0;
			while (__lhip_our_real_name_ipv6->h_aliases[i] != NULL)
			{
				if ( h->h_name != NULL )
				{
					if ( __lhip_check_hostname_match (
						__lhip_our_real_name_ipv6->h_aliases[i],
						h->h_name) == 1 ) return 1;
					}
				if ( h->h_aliases != NULL )
				{
					j = 0;
					while (h->h_aliases[j] != NULL)
					{
						if ( __lhip_check_hostname_match (
							__lhip_our_real_name_ipv6->h_aliases[i],
							h->h_aliases[i]) == 1 ) return 1;
						j++;
					}
				}
				i++;
			}
		}
	}

	if ( (h->h_addrtype == AF_INET) && (h->h_addr_list != NULL) && (__lhip_our_real_name_ipv4 != NULL) )
	{
		if ( __lhip_our_real_name_ipv4->h_addr_list != NULL )
		{
			i = 0;
			while (__lhip_our_real_name_ipv4->h_addr_list[i] != NULL)
			{
				j = 0;
				while (h->h_addr_list[j] != NULL)
				{
					if ( memcmp (__lhip_our_real_name_ipv4->h_addr_list[i],
						h->h_addr_list[j], sizeof (struct in_addr)) == 0 )
					{
						return 1;
					}
					j++;
				}
				i++;
			}
		}
	}

	if ( (h->h_addrtype == AF_INET6) && (h->h_addr_list != NULL) && (__lhip_our_real_name_ipv6 != NULL) )
	{
		if ( __lhip_our_real_name_ipv6->h_addr_list != NULL )
		{
			i = 0;
			while (__lhip_our_real_name_ipv6->h_addr_list[i] != NULL)
			{
				j = 0;
				while (h->h_addr_list[j] != NULL)
				{
					if ( memcmp (__lhip_our_real_name_ipv6->h_addr_list[i],
						h->h_addr_list[j], sizeof (struct in_addr)) == 0 )
					{
						return 1;
					}
					j++;
				}
				i++;
			}
		}
	}

	if ( __lhip_ai_all != NULL )
	{
		tmp = __lhip_ai_all;
		while ( tmp != NULL )
		{
			if (tmp->ai_canonname != NULL)
			{
				if ( h->h_name != NULL )
				{
					if ( __lhip_check_hostname_match (tmp->ai_canonname,
						h->h_name) == 1 ) return 1;
				}
				if ( h->h_aliases != NULL )
				{
					i = 0;
					while (h->h_aliases[i] != NULL)
					{
						if ( __lhip_check_hostname_match (tmp->ai_canonname,
							h->h_aliases[i]) == 1 ) return 1;
						i++;
					}
				}
			}
			if ( tmp->ai_family == AF_INET )
			{
				if (h->h_addr_list != NULL)
				{
					j = 0;
					while (h->h_addr_list[j] != NULL)
					{
						if ( memcmp (
							&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr),
							h->h_addr_list[j], sizeof (struct in_addr)) == 0 )
						{
							return 1;
						}
						j++;
					}
				}
			}
			else if ( tmp->ai_family == AF_INET6 )
			{
				if (h->h_addr_list != NULL)
				{
					j = 0;
					while (h->h_addr_list[j] != NULL)
					{
						if ( memcmp (
							&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr),
							h->h_addr_list[j], sizeof (struct in6_addr)) == 0 )
						{
							return 1;
						}
						j++;
					}
				}
			}
			tmp = tmp->ai_next;
		}
	}
	if ( __lhip_number_of_hostnames > 0 )
	{
		for ( hi=0; hi < __lhip_number_of_hostnames; hi++ )
		{
			if ( __lhip_our_names_addr[hi].h_name == NULL ) continue;
			if ( h->h_name != NULL )
			{
				if ( __lhip_check_hostname_match (__lhip_our_names_addr[hi].h_name,
					h->h_name) == 1 ) return 1;
			}
			if ( h->h_aliases != NULL )
			{
				i = 0;
				while (h->h_aliases[i] != NULL)
				{
					if ( __lhip_check_hostname_match (__lhip_our_names_addr[hi].h_name,
						h->h_aliases[i]) == 1 ) return 1;
					i++;
				}
			}
		}
	}

	if ( h->h_name != NULL )
	{
		if ( __lhip_check_hostname_match (__lhip_our_hostname_v4, h->h_name) == 1 )
			return 1;
	}
	if ( h->h_aliases != NULL )
	{
		i = 0;
		while (h->h_aliases[i] != NULL)
		{
			if ( __lhip_check_hostname_match (__lhip_our_hostname_v4, h->h_aliases[i]) == 1 )
				return 1;
			i++;
		}
	}

	if ( h->h_name != NULL )
	{
		if ( __lhip_check_hostname_match (__lhip_our_hostname_v6, h->h_name) == 1 )
			return 1;
	}
	if ( h->h_aliases != NULL )
	{
		i = 0;
		while (h->h_aliases[i] != NULL)
		{
			if ( __lhip_check_hostname_match (__lhip_our_hostname_v6, h->h_aliases[i]) == 1 )
				return 1;
			i++;
		}
	}

	if ( h->h_name != NULL )
	{
		if ( __lhip_check_hostname_match (__lhip_uname_res.nodename, h->h_name) == 1 )
			return 1;
	}
	if ( h->h_aliases != NULL )
	{
		i = 0;
		while (h->h_aliases[i] != NULL)
		{
			if ( __lhip_check_hostname_match (__lhip_uname_res.nodename, h->h_aliases[i]) == 1 )
				return 1;
			i++;
		}
	}

	if ( h->h_name != NULL )
	{
		if ( __lhip_check_hostname_match (__lhip_our_gethostname, h->h_name) == 1 )
			return 1;
	}
	if ( h->h_aliases != NULL )
	{
		i = 0;
		while (h->h_aliases[i] != NULL)
		{
			if ( __lhip_check_hostname_match (__lhip_our_gethostname, h->h_aliases[i]) == 1 )
				return 1;
			i++;
		}
	}

	return 0;
}

/* =============================================================== */

void
__lhip_change_data (
#ifdef LHIP_ANSIC
	struct hostent * const ret)
#else
	ret)
	struct hostent * const ret;
#endif
{
	int i;
#ifndef HAVE_MEMCPY
	size_t j;
#endif

	if ( ret == NULL ) return;
	if ( __lhip_is_local_addr (ret) != 0 )
	{
		/* change the data here */
		if ( ret->h_name != NULL )
		{
			strncpy (ret->h_name, "localhost", LHIP_MIN (strlen (ret->h_name)+1, 10));
		}
		ret->h_aliases = NULL;
		if ( (ret->h_addrtype == AF_INET) && (ret->h_addr_list != NULL) )
		{
			i = 0;
			while ( ret->h_addr_list[i] != NULL )
			{
#ifdef HAVE_MEMCPY
				memcpy (ret->h_addr_list[i],
					__lhip_localhost_ipv4,
					sizeof (__lhip_localhost_ipv4));
#else
				for ( j = 0; j < sizeof (__lhip_localhost_ipv4); j++ )
				{
					ret->h_addr_list[i][j] = __lhip_localhost_ipv4[j];
				}
#endif
				i++;
			}
		}
		else if ( (ret->h_addrtype == AF_INET6) && (ret->h_addr_list != NULL) )
		{
			i = 0;
			while ( ret->h_addr_list[i] != NULL )
			{
#ifdef HAVE_MEMCPY
				memcpy (ret->h_addr_list[i],
					__lhip_localhost_ipv6,
					sizeof (__lhip_localhost_ipv6));
#else
				for ( j = 0; j < sizeof (__lhip_localhost_ipv6); j++ )
				{
					ret->h_addr_list[i][j] = __lhip_localhost_ipv6[j];
				}
#endif
				i++;
			}
		}
	}
}

/* =============================================================== */

static int GCC_WARN_UNUSED_RESULT
__lhip_check_hostname_match (
#ifdef LHIP_ANSIC
	const char * const host1, const char * const host2)
#else
	host1, host2)
	const char * const host1;
	const char * const host2;
#endif
{
	const char * first_dot_1;
	const char * first_dot_2;

	if ( (host1 == NULL) || (host2 == NULL) ) return 0;
	if ( strcmp (host1, host2) == 0 ) return 1;
	first_dot_1 = strchr (host1, '.');
	first_dot_2 = strchr (host2, '.');
	if ( first_dot_1 != NULL )
	{
		if ( strncmp (host1, host2, (size_t)(first_dot_1 - host1)) == 0 ) return 1;
		if ( first_dot_2 != NULL )
		{
			if ( strncmp (host1, host2, (size_t)
				LHIP_MIN (first_dot_2 - host2, first_dot_1 - host1)) == 0 )
			{
				return 1;
			}
		}
	}
	if ( first_dot_2 != NULL )
	{
		if ( strncmp (host1, host2, (size_t)(first_dot_2 - host2)) == 0 ) return 1;
	}
	return 0;
}

/* =============================================================== */

void __lhip_free_local_addresses (
#ifdef LHIP_ANSIC
	void
#endif
)
{
	/*freeaddrinfo (__lhip_ai_all);*/
}
