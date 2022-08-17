/*
 * A library for hiding local IP address.
 *	-- address resolving functions' replacements.
 *
 * Copyright (C) 2008-2019 Bogdan Drozdowski, bogdandr (at) op.pl
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
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 */

#include "lhip_cfg.h"

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
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

#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#include "lhip_priv.h"

#if (!defined HAVE_RES_NQUERY) && (!defined res_nquery)
# ifdef __cplusplus
extern "C" {
# endif

extern int res_nquery LHIP_PARAMS ((res_state statep,
	const char *dname, int class, int type,
	unsigned char *answer, int anslen));

extern int res_nsearch LHIP_PARAMS ((res_state statep,
	const char *dname, int class, int type,
	unsigned char *answer, int anslen));

extern int res_nquerydomain LHIP_PARAMS ((res_state statep,
	const char *name, const char *domain,
	int class, int type, unsigned char *answer,
	int anslen));

extern int res_nmkquery LHIP_PARAMS ((res_state statep,
	int op, const char *dname, int class,
	int type, const unsigned char *data, int datalen,
	const unsigned char *newrr,
	unsigned char *buf, int buflen));


# ifdef __cplusplus
}
# endif
#endif

static char __lhip_name_copy[LHIP_MAXPATHLEN];

/* =============================================================== */

#ifndef LHIP_ANSIC
static int __lhip_is_forbidden_name LHIP_PARAMS ((const char * const name));
#endif

/**
 * Tells if the given name is forbidden to be resolved.
 * \param name The name to check.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lhip_is_forbidden_name (
#ifdef LHIP_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
	struct hostent h;
	size_t i, j;
	const char * forbidden_names[] =
		{ "127.0.0.1", "::1", "0.0.0.0", "::0",
		"localhost", "localhost6", "localhost.", "localhost6." };
#ifdef HAVE_MALLOC
	char * new_name = NULL;
#endif
	int res;

	if ( name == NULL )
	{
		return 0;
	}

	for ( i = 0; i < sizeof (forbidden_names) / sizeof (forbidden_names[0]); i++ )
	{
		if ( strcmp (name, forbidden_names[i]) == 0 )
		{
			return 1;
		}
		j = strlen (forbidden_names[i]);
		if ( forbidden_names[i][j-1] == '.' )
		{
			if ( strncmp (name, forbidden_names[i], j-1) == 0 )
			{
				return 1;
			}
		}
	}

	j = strlen (name);
#ifdef HAVE_MALLOC
	new_name = (char *) malloc ( j + 1 );
	if ( new_name != NULL )
	{
		strncpy (new_name, name, j);
		new_name[j] = '\0';
		h.h_name = new_name;
	}
	else
	{
		strncpy (__lhip_name_copy, name, LHIP_MIN (j, LHIP_MAXPATHLEN-1));
		__lhip_name_copy[LHIP_MAXPATHLEN-1] = '\0';
		h.h_name = __lhip_name_copy;
	}
#else
	strncpy (__lhip_name_copy, name, LHIP_MIN (j, LHIP_MAXPATHLEN-1));
	__lhip_name_copy[LHIP_MAXPATHLEN-1] = '\0';
	h.h_name = __lhip_name_copy;
#endif
	h.h_aliases = NULL;
	h.h_addrtype = 0;
	h.h_length = 0;
	h.h_addr_list = NULL;
	res = __lhip_is_local_addr (&h);
#ifdef HAVE_MALLOC
	if ( new_name != NULL )
	{
		free (new_name);
	}
#endif
	if ( res != 0 )
	{
		return 1;
	}
	return 0;
}

/* =============================================================== */

int
res_query (
#ifdef LHIP_ANSIC
	const char *dname, int class, int type, unsigned char *answer, int anslen)
#else
	dname, class, type, answer, anslen)
	const char *dname;
	int class;
	int type;
	unsigned char *answer;
	int anslen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_query(%s)\n", (dname != NULL)? dname : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_query_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_query_location ()) (dname, class, type, answer, anslen);
	}

	if ( __lhip_is_forbidden_name (dname) != 0 )
	{
		return -1;
	}
	return (*__lhip_real_res_query_location ()) (dname, class, type, answer, anslen);
}

/* =============================================================== */

int
res_nquery (
#ifdef LHIP_ANSIC
	res_state statep, const char *dname, int class, int type, unsigned char *answer, int anslen)
#else
	statep, dname, class, type, answer, anslen)
	res_state statep;
	const char *dname;
	int class;
	int type;
	unsigned char *answer;
	int anslen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_nquery(%s)\n", (dname != NULL)? dname : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_nquery_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_nquery_location ()) (statep, dname, class, type, answer, anslen);
	}

	if ( __lhip_is_forbidden_name (dname) != 0 )
	{
		return -1;
	}
	return (*__lhip_real_res_nquery_location ()) (statep, dname, class, type, answer, anslen);
}

/* =============================================================== */

int
res_search (
#ifdef LHIP_ANSIC
	const char *dname, int class, int type, unsigned char *answer, int anslen)
#else
	dname, class, type, answer, anslen)
	const char *dname;
	int class;
	int type;
	unsigned char *answer;
	int anslen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_search(%s)\n", (dname != NULL)? dname : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_search_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_search_location ()) (dname, class, type, answer, anslen);
	}

	if ( __lhip_is_forbidden_name (dname) != 0 )
	{
		return -1;
	}

	return (*__lhip_real_res_search_location ()) (dname, class, type, answer, anslen);
}

/* =============================================================== */

int
res_nsearch (
#ifdef LHIP_ANSIC
	res_state statep, const char *dname, int class, int type, unsigned char *answer, int anslen)
#else
	statep, dname, class, type, answer, anslen)
	res_state statep;
	const char *dname;
	int class;
	int type;
	unsigned char *answer;
	int anslen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_nsearch(%s)\n", (dname != NULL)? dname : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_nsearch_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_nsearch_location ()) (statep, dname, class, type, answer, anslen);
	}

	if ( __lhip_is_forbidden_name (dname) != 0 )
	{
		return -1;
	}

	return (*__lhip_real_res_nsearch_location ()) (statep, dname, class, type, answer, anslen);
}

/* =============================================================== */

int
res_querydomain (
#ifdef LHIP_ANSIC
	const char *name, const char *domain, int class, int type, unsigned char *answer, int anslen)
#else
	name, domain, class, type, answer, anslen)
	const char *name;
	const char *domain;
	int class;
	int type;
	unsigned char *answer;
	int anslen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_querydomain(%s, %s)\n", (name != NULL)? name : "null",
		(domain!=NULL)? domain : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_querydomain_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_querydomain_location ()) (name, domain, class, type, answer, anslen);
	}

	if ( __lhip_is_forbidden_name (name) != 0 )
	{
		return -1;
	}

	return (*__lhip_real_res_querydomain_location ()) (name, domain, class, type, answer, anslen);
}

/* =============================================================== */

int
res_nquerydomain (
#ifdef LHIP_ANSIC
	res_state statep, const char *name, const char *domain, int class, int type, unsigned char *answer, int anslen)
#else
	statep, name, domain, class, type, answer, anslen)
	res_state statep;
	const char *name;
	const char *domain;
	int class;
	int type;
	unsigned char *answer;
	int anslen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_nquerydomain(%s, %s)\n", (name != NULL)? name : "null",
		(domain!=NULL)? domain : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_nquerydomain_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_nquerydomain_location ()) (statep, name, domain, class, type, answer, anslen);
	}

	if ( __lhip_is_forbidden_name (name) != 0 )
	{
		return -1;
	}

	return (*__lhip_real_res_nquerydomain_location ()) (statep, name, domain, class, type, answer, anslen);
}

/* =============================================================== */

int
res_mkquery (
#ifdef LHIP_ANSIC
	int op, const char *dname, int class, int type, const unsigned char *data,
		int datalen, const unsigned char *newrr, unsigned char *buf, int buflen)
#else
	op, dname, class, type, data, datalen, newrr, buf, buflen)
	int op;
	const char *dname;
	int class;
	int type;
	const unsigned char *data;
	int datalen;
	const unsigned char *newrr;
	unsigned char *buf;
	int buflen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_mkquery(%s)\n", (dname != NULL)? dname : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_mkquery_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_mkquery_location ())
			(op, dname, class, type, data, datalen, newrr, buf, buflen);
	}

	if ( __lhip_is_forbidden_name (dname) != 0 )
	{
		return -1;
	}

	return (*__lhip_real_res_mkquery_location ())
		(op, dname, class, type, data, datalen, newrr, buf, buflen);
}

/* =============================================================== */

int
res_nmkquery (
#ifdef LHIP_ANSIC
	res_state statep, int op, const char *dname, int class, int type,
	const unsigned char *data, int datalen, const unsigned char *newrr,
	unsigned char *buf, int buflen)
#else
	statep, op, dname, class, type, data, datalen, newrr, buf, buflen)
	res_state statep;
	int op;
	const char *dname;
	int class;
	int type;
	const unsigned char *data;
	int datalen;
	const unsigned char *newrr;
	unsigned char *buf;
	int buflen;
#endif
{
	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: res_nmkquery(%s)\n", (dname != NULL)? dname : "null");
	fflush (stderr);
#endif

	if ( __lhip_real_res_nmkquery_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_res_nmkquery_location ())
			(statep, op, dname, class, type, data, datalen, newrr, buf, buflen);
	}

	if ( __lhip_is_forbidden_name (dname) != 0 )
	{
		return -1;
	}

	return (*__lhip_real_res_nmkquery_location ())
		(statep, op, dname, class, type, data, datalen, newrr, buf, buflen);
}
