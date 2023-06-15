/*
 * LibHideIP - A library for hiding local IP address.
 *	-- getting the local address, checking for matches and anonymizing.
 *
 * Copyright (C) 2011-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
static struct hostent __lhip_tmp;
static struct addrinfo * __lhip_ai_all = NULL;
static const unsigned char __lhip_localhost_ipv4[4] = {LHIP_LOCAL_IPV4_ADDR};
static const unsigned char __lhip_netmask_ipv4[4] = {LHIP_LOCAL_IPV4_MASK};
static const unsigned char __lhip_localhost_ipv6[16] = {LHIP_LOCAL_IPV6_ADDR};
static const unsigned char __lhip_netmask_ipv6[16] = {LHIP_LOCAL_IPV6_MASK};
static const unsigned char __lhip_fake_mac[6] = {1, 2, 3, 4, 5, 6};
#define LHIP_MAXHOSTLEN 16384
#if defined(__GNUC__) && __GNUC__ >= 3
# define LHIP_ALIGN(x) __attribute__((aligned(x)))
#else
# define LHIP_ALIGN(x)
#endif
static char __lhip_our_hostname_v4[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);
static char __lhip_our_hostname_v6[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);
static char __lhip_our_gethostname[LHIP_MAXHOSTLEN] LHIP_ALIGN(8);
static struct utsname __lhip_uname_res;

#undef LHIP_HOST_INCREMENT
#define LHIP_HOST_INCREMENT 100
#ifdef HAVE_MALLOC
static struct hostent * __lhip_our_names_addr = NULL;
static unsigned int __lhip_our_names_addr_size = 0;
#else
static struct hostent __lhip_our_names_addr[LHIP_MAX_HOSTNAMES];
static const unsigned int __lhip_our_names_addr_size = LHIP_MAX_HOSTNAMES;
#endif
static unsigned int __lhip_number_of_hostnames = 0;
static const char local_ip[] = "127.0.0.1";
/*
static char * __lhip_our_hostnames[LHIP_MAX_HOSTNAMES];
static struct sockaddr * __lhip_our_addresses[LHIP_MAX_HOSTNAMES];
static unsigned int __lhip_number_of_addresses = 0;
*/

static int GCC_WARN_UNUSED_RESULT
__lhip_check_hostname_match LHIP_PARAMS ((const char * const host1, const char * const host2));

static int
__lhip_is_local_address LHIP_PARAMS ((const struct hostent * const host));

static void
__lhip_add_local_address LHIP_PARAMS ((const struct hostent * const host));

static void
__lhip_get_address_info LHIP_PARAMS ((const char host[]));

static int GCC_WARN_UNUSED_RESULT
__lhip_check_hostent_match LHIP_PARAMS ((
	const struct hostent * const host1, const struct hostent * const host2));

#ifdef TEST_COMPILE
# undef LHIP_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

/* =============================================================== */

void __lhip_read_local_addresses (LHIP_VOID)
{
	LHIP_MAKE_ERRNO_VAR(err);
#ifdef HAVE_ARPA_INET_H
	struct in_addr lhip_addr;
	struct in6_addr lhip_addr6;
#endif
	int ai_res = 0;
	struct sockaddr_in addr_ipv4;
	struct sockaddr_in6 addr_ipv6;
	struct hostent * hostent_res = NULL;
	int lhip_errno = 0;
	size_t i;
#ifndef HAVE_MALLOC
	int localaddr_found = 0;
#endif
#ifdef HAVE_FUNC_GETHOSTBYADDR_R_5
	struct hostent_data hdata;
#endif

	__lhip_number_of_hostnames = 0;

	/* Get our host's addresses and names/aliases: */
	if ( __lhip_real_gethostname_location () != NULL )
	{
		ai_res = (*__lhip_real_gethostname_location ()) (__lhip_our_gethostname,
			sizeof (__lhip_our_gethostname) );
		if ( ai_res != 0 )
		{
			LHIP_MEMSET (__lhip_our_gethostname, 0, sizeof (__lhip_our_gethostname));
		}
	}
	if ( __lhip_real_uname_location () != NULL )
	{
		ai_res = (*__lhip_real_uname_location ()) (&__lhip_uname_res);
		if ( ai_res != 0 )
		{
			LHIP_MEMSET (&__lhip_uname_res, 0, sizeof (struct utsname));
		}
	}
#ifdef HAVE_ARPA_INET_H
	if ( __lhip_real_gethostbyaddr_r_location () != NULL )
	{
		ai_res = inet_aton (local_ip, &lhip_addr);
		if ( ai_res != 0 )
		{
#ifdef HAVE_FUNC_GETHOSTBYADDR_R_7
			ai_res = 0;
			hostent_res =
#else
			ai_res =
#endif
				(*__lhip_real_gethostbyaddr_r_location ())
					(&lhip_addr, sizeof (struct in_addr), AF_INET, &__lhip_tmp,
#ifdef HAVE_FUNC_GETHOSTBYADDR_R_8
					/* buffer: */
					__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
					&hostent_res, &lhip_errno);
#else /* ! HAVE_FUNC_GETHOSTBYADDR_R_8 */
# ifdef HAVE_FUNC_GETHOSTBYADDR_R_7
					/* buffer: */
					__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
					&lhip_errno);
# else
					&hdata);
# endif
#endif /* HAVE_FUNC_GETHOSTBYADDR_R_8 */
			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				if ( __lhip_is_local_address (hostent_res) == 1 )
				{
					__lhip_add_local_address (hostent_res);
				}
			} /* ai_res == 0 ... */
		} /* ai_res != 0 */
		/* IPv6: */
		__lhip_set_ipv6_value (&lhip_addr6);
#ifdef HAVE_FUNC_GETHOSTBYADDR_R_7
			ai_res = 0;
			hostent_res =
#else
			ai_res =
#endif
				(*__lhip_real_gethostbyaddr_r_location ())
					(&lhip_addr6, sizeof (struct in6_addr), AF_INET6, &__lhip_tmp,
#ifdef HAVE_FUNC_GETHOSTBYADDR_R_8
					/* buffer: */
					__lhip_our_hostname_v6, sizeof (__lhip_our_hostname_v6),
					&hostent_res, &lhip_errno);
#else /* ! HAVE_FUNC_GETHOSTBYADDR_R_8 */
# ifdef HAVE_FUNC_GETHOSTBYADDR_R_7
					/* buffer: */
					__lhip_our_hostname_v6, sizeof (__lhip_our_hostname_v6),
					&lhip_errno);
# else
					&hdata);
# endif
#endif /* HAVE_FUNC_GETHOSTBYADDR_R_8 */
		if ( (ai_res == 0) && (hostent_res != NULL) )
		{
			if ( __lhip_is_local_address (hostent_res) == 1 )
			{
				__lhip_add_local_address (hostent_res);
			}
		} /* ai_res == 0 ... */
	}
	else if ( __lhip_real_gethostbyaddr_location () != NULL )
	{
		ai_res = inet_aton (local_ip, &lhip_addr);
		if ( ai_res != 0 )
		{
			/* don't pass directly, we need the variable */
			__lhip_our_real_name_ipv4 = (*__lhip_real_gethostbyaddr_location ())
				(&lhip_addr, sizeof (struct in_addr), AF_INET);
			__lhip_add_local_address (__lhip_our_real_name_ipv4);
		}
		__lhip_set_ipv6_value (&lhip_addr6);
		/* don't pass directly, we need the variable */
		__lhip_our_real_name_ipv6 = (*__lhip_real_gethostbyaddr_location ())
			(&lhip_addr6, sizeof (struct in6_addr), AF_INET6);
		__lhip_add_local_address (__lhip_our_real_name_ipv6);
	}

#endif	/* HAVE_ARPA_INET_H */
	if ( __lhip_real_gethostbyname_r_location () != NULL )
	{
		if (__lhip_our_gethostname[0] != '\0')
		{
#ifdef HAVE_FUNC_GETHOSTBYNAME_R_5
			ai_res = 0;
			hostent_res =
#else
			ai_res =
#endif
				(*__lhip_real_gethostbyname_r_location ()) (
					__lhip_our_gethostname, &__lhip_tmp,
#ifdef HAVE_FUNC_GETHOSTBYNAME_R_6
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&hostent_res, &lhip_errno);
#else /* ! HAVE_FUNC_GETHOSTBYNAME_R_6 */
# ifdef HAVE_FUNC_GETHOSTBYNAME_R_5
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&lhip_errno);
# else /* ! HAVE_FUNC_GETHOSTBYNAME_R_5 */
				&hdata);
# endif /* HAVE_FUNC_GETHOSTBYNAME_R_5 */
#endif /* HAVE_FUNC_GETHOSTBYNAME_R_6 */
			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				__lhip_add_local_address (hostent_res);
			}
		}
		if ( __lhip_uname_res.nodename[0] != '\0' )
		{
#ifdef HAVE_FUNC_GETHOSTBYNAME_R_5
			ai_res = 0;
			hostent_res =
#else
			ai_res =
#endif
				(*__lhip_real_gethostbyname_r_location ()) (
					__lhip_uname_res.nodename, &__lhip_tmp,
#ifdef HAVE_FUNC_GETHOSTBYNAME_R_6
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&hostent_res, &lhip_errno);
#else /* ! HAVE_FUNC_GETHOSTBYNAME_R_6 */
# ifdef HAVE_FUNC_GETHOSTBYNAME_R_5
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&lhip_errno);
# else /* ! HAVE_FUNC_GETHOSTBYNAME_R_5 */
				&hdata);
# endif /* HAVE_FUNC_GETHOSTBYNAME_R_5 */
#endif /* HAVE_FUNC_GETHOSTBYNAME_R_6 */
			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				__lhip_add_local_address (hostent_res);
			}
		}
	}
	else if ( __lhip_real_gethostbyname_location () != NULL )
	{
		if ( __lhip_our_gethostname[0] != '\0' )
		{
			__lhip_add_local_address (
				(*__lhip_real_gethostbyname_location ()) (__lhip_our_gethostname));
		}
		if ( __lhip_uname_res.nodename[0] != '\0' )
		{
			__lhip_add_local_address (
				(*__lhip_real_gethostbyname_location ()) (__lhip_uname_res.nodename));
		}
	}

	if ( __lhip_real_getaddrinfo_location () != NULL )
	{
		__lhip_ai_all = NULL;
		__lhip_get_address_info (local_ip);
		__lhip_get_address_info (__lhip_uname_res.nodename);
		__lhip_get_address_info (__lhip_our_gethostname);
	}

	if ( __lhip_real_gethostent_r_location () != NULL )
	{
		do
		{
#ifdef HAVE_FUNC_GETHOSTENT_R_4
			ai_res = 0;
			hostent_res =
#else
			ai_res =
#endif
				(*__lhip_real_gethostent_r_location ()) (
					&__lhip_tmp,
#ifdef HAVE_FUNC_GETHOSTENT_R_5
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&hostent_res, &lhip_errno);
#else /* ! HAVE_FUNC_GETHOSTENT_R_5 */
# ifdef HAVE_FUNC_GETHOSTENT_R_4
				/* buffer: */
				__lhip_our_hostname_v4, sizeof (__lhip_our_hostname_v4),
				&lhip_errno);
# else /* ! HAVE_FUNC_GETHOSTENT_R_4 */
				&hdata);
# endif /* HAVE_FUNC_GETHOSTENT_R_4 */
#endif /* HAVE_FUNC_GETHOSTENT_R_5 */

			if ( (ai_res == 0) && (hostent_res != NULL) )
			{
				if ( __lhip_is_local_address (hostent_res) == 1 )
				{
					__lhip_add_local_address (hostent_res);
				}
			}
		} while ( (ai_res == 0) && (hostent_res != NULL) );
	}
	else if ( __lhip_real_gethostent_location () != NULL )
	{
		/* without malloc(), only one address can be copied -
		   next ones would overwrite the found one. */
#ifndef HAVE_MALLOC
		localaddr_found = 0;
#endif
		do
		{
			hostent_res = (*__lhip_real_gethostent_location ()) ();
			if ( hostent_res == NULL )
			{
				break;
			}
			i = 0;
			while ( hostent_res->h_addr_list[i] != NULL )
			{
				if ( (hostent_res->h_addrtype == AF_INET)
					&& (__lhip_check_ipv4_value ((struct in_addr *)
						hostent_res->h_addr_list[i]) == 1) )
				{
					__lhip_add_local_address (hostent_res);
#ifndef HAVE_MALLOC
					localaddr_found = 1;
#endif
				}
				else if ( (hostent_res->h_addrtype == AF_INET6)
					&& (__lhip_check_ipv6_value ((struct in6_addr *)
						(hostent_res->h_addr_list[i])) == 1) )
				{
					__lhip_add_local_address (hostent_res);
#ifndef HAVE_MALLOC
					localaddr_found = 1;
#endif
				}
				i++;
			}
		} while ( (hostent_res != NULL)
#ifndef HAVE_MALLOC
			&& (localaddr_found == 0)
#endif
			);
	}

	if ( __lhip_real_getnameinfo_location () != NULL )
	{
		addr_ipv4.sin_family = AF_INET;
		__lhip_set_ipv4_value (&(addr_ipv4.sin_addr));
		ai_res = (*__lhip_real_getnameinfo_location ()) ((struct sockaddr *)&addr_ipv4,
			sizeof (struct sockaddr_in), __lhip_our_hostname_v4,
			sizeof (__lhip_our_hostname_v4), NULL, 0, 0);
		if ( ai_res != 0 )
		{
			LHIP_MEMSET (__lhip_our_hostname_v4, 0, sizeof (__lhip_our_hostname_v4));
		}
		addr_ipv6.sin6_family = AF_INET6;
		__lhip_set_ipv6_value (&(addr_ipv6.sin6_addr));
		ai_res = (*__lhip_real_getnameinfo_location ()) ((struct sockaddr *)&addr_ipv6,
			sizeof (struct sockaddr_in6), __lhip_our_hostname_v6,
			sizeof (__lhip_our_hostname_v6), NULL, 0, 0);
		if ( ai_res != 0 )
		{
			LHIP_MEMSET (__lhip_our_hostname_v6, 0, sizeof (__lhip_our_hostname_v6));
		}
	}
#ifdef LHIP_DEBUG
	fprintf (stderr, "LibHideIP: Got addresses and aliases:\n");
	fflush (stderr);
	if ( __lhip_our_real_name_ipv4 != NULL )
	{
		fprintf (stderr, "LibHideIP: 1: name=%s, h_addr_list=0x%lx\n",
			(__lhip_our_real_name_ipv4->h_name == NULL)? "null" :
				__lhip_our_real_name_ipv4->h_name,
			(unsigned long int)__lhip_our_real_name_ipv4->h_addr_list);
		if ( __lhip_our_real_name_ipv4->h_addr_list != NULL )
		{
			int debug_j = 0;
			while ( __lhip_our_real_name_ipv4->h_addr_list[debug_j] != NULL )
			{
				fprintf (stderr, ", lhip_addr=0x%x",
					((struct in_addr *)(__lhip_our_real_name_ipv4->h_addr_list[debug_j]))->s_addr
					);
				fflush (stderr);
				debug_j++;
			}
		}
		fprintf (stderr, "\n");
		fflush (stderr);
	}
	if ( __lhip_our_real_name_ipv6 != NULL )
	{
		fprintf (stderr, "LibHideIP: 2: name=%s, h_addr_list=0x%lx\n",
			(__lhip_our_real_name_ipv6->h_name == NULL)? "null" :
				__lhip_our_real_name_ipv6->h_name,
			(unsigned long int)__lhip_our_real_name_ipv6->h_addr_list);
		if ( __lhip_our_real_name_ipv6->h_addr_list != NULL )
		{
			int debug_j = 0;
			while ( __lhip_our_real_name_ipv6->h_addr_list[debug_j] != NULL )
			{
				fprintf (stderr, ", lhip_addr=0x%x",
					((struct in_addr *)(__lhip_our_real_name_ipv6->h_addr_list[debug_j]))->s_addr
					);
				fflush (stderr);
				debug_j++;
			}
		}
		fprintf (stderr, "\n");
		fflush (stderr);
	}

	if ( __lhip_ai_all != NULL )
	{
		struct addrinfo * tmp = __lhip_ai_all;
		while ( tmp != NULL )
		{
			fprintf (stderr, "LibHideIP: 3: name=%s, lhip_addr=0x%x\n",
				(tmp->ai_canonname == NULL)? "null" : tmp->ai_canonname,
				((struct sockaddr_in *)(tmp->ai_addr))->sin_addr.s_addr);
			fflush (stderr);
			tmp = tmp->ai_next;
		}
	}
	fprintf (stderr, "LibHideIP: 4: name_v4=%s\n", __lhip_our_hostname_v4);
	fflush (stderr);
	fprintf (stderr, "LibHideIP: 5: name_v6=%s\n", __lhip_our_hostname_v6);
	fflush (stderr);
	for ( i = 0; i < __lhip_number_of_hostnames; i++ )
	{
		fprintf (stderr, "LibHideIP: 6+%lu: name=%s, h_addr_list=0x%lx, h_addrtype=%d, " \
			 "AF_INET=%d, AF_INET6=%d, h_length=%d\n", i,
			(__lhip_our_names_addr[i].h_name == NULL)? "null" :
				__lhip_our_names_addr[i].h_name,
			(unsigned long int)__lhip_our_names_addr[i].h_addr_list,
			__lhip_our_names_addr[i].h_addrtype,
			AF_INET, AF_INET6, __lhip_our_names_addr[i].h_length);
		if ( __lhip_our_names_addr[i].h_addr_list != NULL )
		{
			int debug_j = 0;
			while ( __lhip_our_names_addr[i].h_addr_list[debug_j] != NULL )
			{
				fprintf (stderr, "h_addr_list[%d]='0x%x'", debug_j,
					((struct in_addr *)(__lhip_our_names_addr[i].h_addr_list[debug_j]))->s_addr
					);
				fflush (stderr);
				debug_j++;
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

	LHIP_SET_ERRNO(err);
}

/* =============================================================== */

struct hostent *
__lhip_get_our_name_ipv4 (LHIP_VOID)
{
	return __lhip_our_real_name_ipv4;
}

/* =============================================================== */

struct hostent *
__lhip_get_our_name_ipv6 (LHIP_VOID)
{
	return __lhip_our_real_name_ipv6;
}

/* =============================================================== */

/**
 * Checks if the given hostent structures point to the same host
 *	(at least one address matches).
 * @param host1 the first host entry.
 * @param host2 the second host entry.
 * @return non-zero if the given hostent structures point to the same host.
 */
static int
__lhip_check_hostent_match (
#ifdef LHIP_ANSIC
	const struct hostent * const host1, const struct hostent * const host2)
#else
	host1, host2)
	const struct hostent * const host1;
	const struct hostent * const host2;
#endif
{
	int i, j;

	if ( (host1 == NULL) && (host2 == NULL) )
	{
		return 1;
	}
	else if ( ((host1 == NULL) && (host2 != NULL))
		|| ((host1 != NULL) && (host2 == NULL)) )
	{
		return 0;
	}
	if ( host1->h_name != NULL )
	{
		if ( host2->h_name != NULL )
		{
			if ( __lhip_check_hostname_match (
				host1->h_name,
				host2->h_name) == 1 )
			{
				return 1;
			}
		}
		if ( host2->h_aliases != NULL )
		{
			i = 0;
			while ( host2->h_aliases[i] != NULL )
			{
				if ( __lhip_check_hostname_match (
					host1->h_name,
					host2->h_aliases[i]) == 1 )
				{
					return 1;
				}
				i++;
			}
		}
	}

	if ( host1->h_aliases != NULL )
	{
		i = 0;
		while ( host1->h_aliases[i] != NULL )
		{
			if ( host2->h_name != NULL )
			{
				if ( __lhip_check_hostname_match (
					host1->h_aliases[i],
					host2->h_name) == 1 )
				{
					return 1;
				}
			}
			if ( host2->h_aliases != NULL )
			{
				j = 0;
				while ( host2->h_aliases[j] != NULL )
				{
					if ( __lhip_check_hostname_match (
						host1->h_aliases[i],
						host2->h_aliases[j]) == 1 )
					{
						return 1;
					}
					j++;
				}
			}
			i++;
		}
	}
	return 0;
}


/* =============================================================== */

/**
 * Checks if the given address is one of the known local addresses.
 * @param h the address to check.
 * @return non-zero if the given address is one of the known local addresses.
 */
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

	if ( h == NULL )
	{
		return 0;
	}

	if ( __lhip_check_hostent_match (__lhip_our_real_name_ipv4, h) == 1 )
	{
		return 1;
	}
	if ( __lhip_check_hostent_match (__lhip_our_real_name_ipv6, h) == 1 )
	{
		return 1;
	}

	if ( (h->h_addrtype == AF_INET)
		&& (h->h_addr_list != NULL)
		&& (__lhip_our_real_name_ipv4 != NULL) )
	{
		if ( __lhip_our_real_name_ipv4->h_addr_list != NULL )
		{
			i = 0;
			while ( __lhip_our_real_name_ipv4->h_addr_list[i] != NULL )
			{
				j = 0;
				while ( h->h_addr_list[j] != NULL )
				{
					if ( memcmp (__lhip_our_real_name_ipv4->h_addr_list[i],
						h->h_addr_list[j],
						sizeof (struct in_addr)) == 0 )
					{
						return 1;
					}
					j++;
				}
				i++;
			}
		}
	}

	if ( (h->h_addrtype == AF_INET6)
		&& (h->h_addr_list != NULL)
		&& (__lhip_our_real_name_ipv6 != NULL) )
	{
		if ( __lhip_our_real_name_ipv6->h_addr_list != NULL )
		{
			i = 0;
			while ( __lhip_our_real_name_ipv6->h_addr_list[i] != NULL )
			{
				j = 0;
				while ( h->h_addr_list[j] != NULL )
				{
					if ( memcmp (__lhip_our_real_name_ipv6->h_addr_list[i],
						h->h_addr_list[j],
						sizeof (struct in6_addr)) == 0 )
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
			if ( tmp->ai_canonname != NULL )
			{
				if ( h->h_name != NULL )
				{
					if ( __lhip_check_hostname_match (
						tmp->ai_canonname,
						h->h_name) == 1 )
					{
						return 1;
					}
				}
				if ( h->h_aliases != NULL )
				{
					i = 0;
					while ( h->h_aliases[i] != NULL )
					{
						if ( __lhip_check_hostname_match (
							tmp->ai_canonname,
							h->h_aliases[i]) == 1 )
						{
							return 1;
						}
						i++;
					}
				}
			}
			if ( tmp->ai_family == AF_INET )
			{
				if ( h->h_addr_list != NULL )
				{
					j = 0;
					while ( h->h_addr_list[j] != NULL )
					{
						if ( memcmp (
							&(((struct sockaddr_in *)(tmp->ai_addr))->sin_addr),
							h->h_addr_list[j],
							sizeof (struct in_addr)) == 0 )
						{
							return 1;
						}
						j++;
					}
				}
			}
			else if ( tmp->ai_family == AF_INET6 )
			{
				if ( h->h_addr_list != NULL )
				{
					j = 0;
					while ( h->h_addr_list[j] != NULL )
					{
						if ( memcmp (
							&(((struct sockaddr_in6 *)(tmp->ai_addr))->sin6_addr),
							h->h_addr_list[j],
							sizeof (struct in6_addr)) == 0 )
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
		for ( hi = 0; hi < __lhip_number_of_hostnames; hi++ )
		{
			if ( __lhip_check_hostent_match (
				&__lhip_our_names_addr[hi], h) == 1 )
			{
				return 1;
			}
		}
	}

	if ( h->h_name != NULL )
	{
		if ( __lhip_check_hostname_match (__lhip_our_hostname_v4,
			h->h_name) == 1 )
		{
			return 1;
		}
		if ( __lhip_check_hostname_match (__lhip_our_hostname_v6,
			h->h_name) == 1 )
		{
			return 1;
		}
		if ( __lhip_check_hostname_match (__lhip_uname_res.nodename,
			h->h_name) == 1 )
		{
			return 1;
		}
		if ( __lhip_check_hostname_match (__lhip_our_gethostname,
			h->h_name) == 1 )
		{
			return 1;
		}
	}
	if ( h->h_aliases != NULL )
	{
		i = 0;
		while ( h->h_aliases[i] != NULL )
		{
			if ( __lhip_check_hostname_match (__lhip_our_hostname_v4,
				h->h_aliases[i]) == 1 )
			{
				return 1;
			}
			if ( __lhip_check_hostname_match (__lhip_our_hostname_v6,
				h->h_aliases[i]) == 1 )
			{
				return 1;
			}
			if ( __lhip_check_hostname_match (__lhip_uname_res.nodename,
				h->h_aliases[i]) == 1 )
			{
				return 1;
			}
			if ( __lhip_check_hostname_match (__lhip_our_gethostname,
				h->h_aliases[i]) == 1 )
			{
				return 1;
			}
			i++;
		}
	}

	return 0;
}

/* =============================================================== */

/**
 * Changes the given hostent structure contents so that it contains only
 *  generic data (like "localhost" or "127.0.0.1")
 * @param ret the structure to change
 */
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
	size_t len;

	if ( ret == NULL )
	{
		return;
	}
	if ( __lhip_is_local_addr (ret) != 0 )
	{
		/* change the data here */
		if ( ret->h_name != NULL )
		{
			len = strlen (ret->h_name);
			LHIP_MEMSET (ret->h_name, 0, len);
			strncpy (ret->h_name, "localhost",
				LHIP_MIN (len+1, 10));
			ret->h_name[len] = '\0';
		}
		ret->h_aliases = NULL;
		if ( (ret->h_addrtype == AF_INET)
			&& (ret->h_addr_list != NULL) )
		{
			i = 0;
			while ( ret->h_addr_list[i] != NULL )
			{
				__lhip_set_ipv4_value (
					(struct in_addr *)(ret->h_addr_list[i]));
				i++;
			}
		}
		else if ( (ret->h_addrtype == AF_INET6)
			&& (ret->h_addr_list != NULL) )
		{
			i = 0;
			while ( ret->h_addr_list[i] != NULL )
			{
				__lhip_set_ipv6_value (
					(struct in6_addr *)(ret->h_addr_list[i]));
				i++;
			}
		}
	}
}

/* =============================================================== */

/**
 * Checks if the two given hostnames match (either fully or the parts
 *	before the first dots).
 * @param host1 the first host for comaring
 * @param host2 the second host for comaring
 * @return 1 if the two given hostnames match and 0 otherwise
 */
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

	if ( (host1 == NULL) || (host2 == NULL) )
	{
		return 0;
	}
	if ( strcmp (host1, host2) == 0 )
	{
		return 1;
	}
	first_dot_1 = strchr (host1, '.');
	first_dot_2 = strchr (host2, '.');
	if ( first_dot_1 != NULL )
	{
		if ( strncmp (host1, host2,
			(size_t)(first_dot_1 - host1)) == 0 )
		{
			return 1;
		}
		if ( first_dot_2 != NULL )
		{
			if ( strncmp (host1, host2, (size_t)
				LHIP_MIN (first_dot_2 - host2,
					first_dot_1 - host1)) == 0 )
			{
				return 1;
			}
		}
	}
	if ( first_dot_2 != NULL )
	{
		if ( strncmp (host1, host2,
			(size_t)(first_dot_2 - host2)) == 0 )
		{
			return 1;
		}
	}
	return 0;
}

/* =============================================================== */

void __lhip_free_local_addresses (LHIP_VOID)
{
#ifdef HAVE_MALLOC
	size_t i, j;

	if ( __lhip_our_names_addr != NULL )
	{
		for ( i = 0; i < __lhip_number_of_hostnames; i++ )
		{
			if ( __lhip_our_names_addr[i].h_name != NULL )
			{
				free (__lhip_our_names_addr[i].h_name);
				__lhip_our_names_addr[i].h_name = NULL;
			}
			if ( __lhip_our_names_addr[i].h_aliases != NULL )
			{
				j = 0;
				while ( __lhip_our_names_addr[i].h_aliases[j] != NULL )
				{
					free (__lhip_our_names_addr[i].h_aliases[j]);
					__lhip_our_names_addr[i].h_aliases[j] = NULL;
					j++;
				}
				free (__lhip_our_names_addr[i].h_aliases);
				__lhip_our_names_addr[i].h_aliases = NULL;
			}
			if ( __lhip_our_names_addr[i].h_addr_list != NULL )
			{
				j = 0;
				while ( __lhip_our_names_addr[i].h_addr_list[j] != NULL )
				{
					free (__lhip_our_names_addr[i].h_addr_list[j]);
					__lhip_our_names_addr[i].h_addr_list[j] = NULL;
					j++;
				}
				free (__lhip_our_names_addr[i].h_addr_list);
				__lhip_our_names_addr[i].h_addr_list = NULL;
			}
		}
		free (__lhip_our_names_addr);
		__lhip_our_names_addr = NULL;
	}
	if ( __lhip_ai_all != NULL )
	{
		freeaddrinfo (__lhip_ai_all);
		__lhip_ai_all = NULL;
	}
#endif
}

/* =============================================================== */

/**
 * Adds the given address to the local addresses.
 * @param host the address to add
 */
static void
__lhip_add_local_address (
#ifdef LHIP_ANSIC
	const struct hostent * const host)
#else
	host)
	const struct hostent * const host;
#endif
{
#ifdef HAVE_MALLOC
	size_t i, j;
# ifdef HAVE_REALLOC
	struct hostent * lhip_new_array;
# endif
#endif

#ifdef HAVE_MALLOC
	if ( (host != NULL)
		&& (__lhip_number_of_hostnames >= __lhip_our_names_addr_size) )
	{
		if ( __lhip_our_names_addr == NULL )
		{
			__lhip_our_names_addr = (struct hostent *) malloc (
				LHIP_HOST_INCREMENT * sizeof (struct hostent) );
		}
# ifdef HAVE_REALLOC
		else
		{
			lhip_new_array = (struct hostent *) realloc (
				__lhip_our_names_addr,
				(__lhip_number_of_hostnames + LHIP_HOST_INCREMENT)
				* sizeof (struct hostent) );
			if ( lhip_new_array != NULL )
			{
				__lhip_our_names_addr = lhip_new_array;
				__lhip_our_names_addr_size =
					__lhip_number_of_hostnames + LHIP_HOST_INCREMENT;
			}
		}
# endif
	}
#endif

	if ( (host != NULL)
		&& (__lhip_number_of_hostnames < __lhip_our_names_addr_size) )
	{
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_name = NULL;
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases = NULL;
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list = NULL;
#ifdef HAVE_MALLOC
		if ( host->h_name != NULL )
		{
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_name
				= LHIP_STRDUP (host->h_name);
		}
		j = 0;
		if ( host->h_aliases != NULL )
		{
			while ( host->h_aliases[j] != NULL )
			{
				j++;
			}
		}
		/* "+1" for the NULL pointer */
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases
			= (char **) malloc ( (j+1) * sizeof (char *));
		if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases != NULL )
		{
			/* end-of-list marker */
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[j] = NULL;
			for ( i = 0; i < j; i++ )
			{
				__lhip_our_names_addr[__lhip_number_of_hostnames].h_aliases[i] =
					LHIP_STRDUP (host->h_aliases[i]);
			}
		}
		j = 0;
		if ( host->h_addr_list != NULL )
		{
			while ( host->h_addr_list[j] != NULL )
			{
				j++;
			}
		}
		if ( host->h_length > 0 )
		{
			/* "+1" for the NULL pointer */
			__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list
				= (char **) malloc ( (j+1) * sizeof (char *));
			if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list != NULL )
			{
				/* end-of-list marker */
				__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[j] = NULL;
				for ( i = 0; i < j; i++ )
				{
					__lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] =
						(char *) malloc ( (size_t) host->h_length );
					if ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i] != NULL )
					{
						LHIP_MEMCOPY ( __lhip_our_names_addr[__lhip_number_of_hostnames].h_addr_list[i],
							host->h_addr_list[i],
							(size_t) host->h_length );
					}
				}
			}
		}
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_addrtype
			= host->h_addrtype;
		__lhip_our_names_addr[__lhip_number_of_hostnames].h_length
			= host->h_length;
#else
		__lhip_our_names_addr[__lhip_number_of_hostnames] = *host;
#endif /* HAVE_MALLOC */
		__lhip_number_of_hostnames++;
	} /* host != NULL */
}

/* =============================================================== */

/**
 * Checks if the given address is one of the local addresses.
 * @param host the address to check
 * @return 1 if the given address is one of the local addresses
 *	and 0 otherwise.
 */
static int
__lhip_is_local_address (
#ifdef LHIP_ANSIC
	const struct hostent * const host)
#else
	host)
	const struct hostent * const host;
#endif
{
	size_t i;

	if ( host == NULL )
	{
		return 0;
	}

	if ( host->h_name != NULL )
	{
		if ( __lhip_check_hostname_match (
			__lhip_our_gethostname,
			host->h_name) == 1 )
		{
			return 1;
		}
	}
	if ( host->h_aliases != NULL )
	{
		i = 0;
		while ( host->h_aliases[i] != NULL )
		{
			if ( __lhip_check_hostname_match (
				__lhip_our_gethostname,
				host->h_aliases[i]) == 1 )
			{
				return 1;
			}
			i++;
		}
	}
	if ( host->h_name != NULL )
	{
		if ( __lhip_check_hostname_match (
			__lhip_uname_res.nodename,
			host->h_name) == 1 )
		{
			return 1;
		}
	}
	if ( host->h_aliases != NULL )
	{
		i = 0;
		while ( host->h_aliases[i] != NULL )
		{
			if ( __lhip_check_hostname_match (
				__lhip_uname_res.nodename,
				host->h_aliases[i]) == 1 )
			{
				return 1;
			}
			i++;
		}
	}
	if ( host->h_addr_list != NULL )
	{
		i = 0;
		while ( host->h_addr_list[i] != NULL )
		{
			if ( (host->h_addrtype == AF_INET)
				&& (__lhip_check_ipv4_value ((struct in_addr *)(host->h_addr_list[i])) == 1)
			)
			{
				return 1;
			}
			if ( (host->h_addrtype == AF_INET6)
				&& (__lhip_check_ipv6_value ((struct in6_addr *)(host->h_addr_list[i])) == 1)
			)
			{
				return 1;
			}
			i++;
		}
	}

	return 0;
}

/* =============================================================== */

/**
 * Gets addrinfo data for the given host.
 * @param host the host to get addrinfo data for.
 */
static void
__lhip_get_address_info (
#ifdef LHIP_ANSIC
	const char host[])
#else
	host)
	const char host[];
#endif
{
	struct addrinfo ai_hints;
	struct addrinfo * __lhip_ai_all_tmp;
	struct addrinfo * tmp;
	int ai_res;

	if ( (host == NULL) || (__lhip_real_getaddrinfo_location () == NULL) )
	{
		return;
	}
	if ( host[0] == '\0' )
	{
		return;
	}

	LHIP_MEMSET (&ai_hints, 0, sizeof (struct addrinfo));

	ai_hints.ai_flags = /*AI_NUMERICHOST |*/ AI_CANONNAME;
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = 0;
	ai_hints.ai_protocol = 0;
	ai_hints.ai_addr = NULL;
	ai_hints.ai_canonname = NULL;
	ai_hints.ai_next = NULL;
	ai_res = (*__lhip_real_getaddrinfo_location ()) (host,
		NULL /* service */, &ai_hints, &__lhip_ai_all_tmp);
	if ( (ai_res == 0) && (__lhip_ai_all_tmp != NULL) )
	{
		if ( __lhip_ai_all == NULL )
		{
			__lhip_ai_all = __lhip_ai_all_tmp;
		}
		else
		{
			/* join the lists: */
			tmp = __lhip_ai_all;
			while ( tmp->ai_next != NULL )
			{
				tmp = tmp->ai_next;
			}
			tmp->ai_next = __lhip_ai_all_tmp;
		}
	}
}

/* =============================================================== */

/**
 * Changes the given IPv4 address contents so that it contains only
 *  generic data ("127.0.0.1")
 * @param addr4 the address to change
 */
void
__lhip_set_ipv4_value (
#ifdef LHIP_ANSIC
	struct in_addr * const addr4)
#else
	addr4)
	struct in_addr * const addr4;
#endif
{
	if ( addr4 == NULL )
	{
		return;
	}
	LHIP_MEMCOPY ( addr4,
		__lhip_localhost_ipv4,
		sizeof (__lhip_localhost_ipv4) );
}

/* =============================================================== */

/**
 * Changes the given IPv4 address mask contents so that it contains only
 *  generic data ("255.255.255.255")
 * @param mask4 the address mask to change
 */
void
__lhip_set_ipv4_mask_value (
#ifdef LHIP_ANSIC
	struct in_addr * const mask4)
#else
	mask4)
	struct in_addr * const mask4;
#endif
{
	if ( mask4 == NULL )
	{
		return;
	}
	LHIP_MEMCOPY ( mask4,
		__lhip_netmask_ipv4,
		sizeof (__lhip_netmask_ipv4) );
}

/* =============================================================== */

/**
 * Changes the given IPv6 address contents so that it contains only
 *  generic data ("::1")
 * @param addr6 the address to change
 */
void
__lhip_set_ipv6_value (
#ifdef LHIP_ANSIC
	struct in6_addr * const addr6)
#else
	addr6)
	struct in6_addr * const addr6;
#endif
{
	if ( addr6 == NULL )
	{
		return;
	}
	LHIP_MEMCOPY ( addr6,
		__lhip_localhost_ipv6,
		sizeof (__lhip_localhost_ipv6) );
}

/* =============================================================== */

/**
 * Changes the given IPv6 address mask contents so that it contains only
 *  generic data ("::1")
 * @param mask6 the address mask to change
 */
void
__lhip_set_ipv6_mask_value (
#ifdef LHIP_ANSIC
	struct in6_addr * const mask6)
#else
	mask6)
	struct in6_addr * const mask6;
#endif
{
	if ( mask6 == NULL )
	{
		return;
	}
	LHIP_MEMCOPY ( mask6,
		__lhip_netmask_ipv6,
		sizeof (__lhip_netmask_ipv6) );
}

/* =============================================================== */

/**
 * Changes the given MAC address contents so that it contains only
 *  generic data ("01:02:03:04:05:06")
 * @param macaddr the address to change
 */
void
__lhip_set_mac_value (
#ifdef LHIP_ANSIC
	void * const macaddr)
#else
	macaddr)
	void * const macaddr;
#endif
{
	if ( macaddr == NULL )
	{
		return;
	}
	LHIP_MEMCOPY ( macaddr,
		__lhip_fake_mac,
		sizeof (__lhip_fake_mac) );
}

/* =============================================================== */

/**
 * Checks the given IPv4 address contents if it contains only
 *  generic data ("127.0.0.1")
 * @param addr4 the address to check
 * @return 1 if the address is OK
 */
int
__lhip_check_ipv4_value (
#ifdef LHIP_ANSIC
	const struct in_addr * const addr4)
#else
	addr4)
	const struct in_addr * const addr4;
#endif
{
	if ( addr4 == NULL )
	{
		return 0;
	}
	if (memcmp (addr4,
		__lhip_localhost_ipv4,
		sizeof (__lhip_localhost_ipv4) ) == 0)
	{
		return 1;
	}
	return 0;
}

/* =============================================================== */

/**
 * Checks the given IPv6 address contents if it contains only
 *  generic data ("::1")
 * @param addr6 the address to check
 * @return 1 if the address is OK
 */
int
__lhip_check_ipv6_value (
#ifdef LHIP_ANSIC
	const struct in6_addr * const addr6)
#else
	addr6)
	const struct in6_addr * const addr6;
#endif
{
	if ( addr6 == NULL )
	{
		return 0;
	}
	if (memcmp (addr6,
		__lhip_localhost_ipv6,
		sizeof (__lhip_localhost_ipv6) ) == 0)
	{
		return 1;
	}
	return 0;
}
