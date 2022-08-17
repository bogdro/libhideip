/*
 * A library for hiding local IP address.
 *	-- uname function replacement.
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

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#else
struct utsname
{
	char sysname[];
	char nodename[];
	char release[];
	char version[];
	char machine[];
};
#endif


#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lhip_priv.h"

#define LHIP_MIN(a,b) ( ((a)<(b)) ? (a) : (b) )

/* =============================================================== */

int
uname (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	struct utsname *buf)
#else
	buf)
	struct utsname *buf;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
#ifndef HAVE_MEMSET
	size_t i;
#endif
	int ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: uname()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_uname_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_uname_location ()) (buf);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_uname_location ()) (buf);
	}

	ret = (*__lhip_real_uname_location ()) (buf);
	if ( ret >= 0 )
	{
# ifdef HAVE_MEMSET
		memset (&(buf->nodename), 0, sizeof (buf->nodename));
# else
		for ( i = 0; i < sizeof (buf->nodename); i++ )
		{
			buf->nodename[i] = '\0';
		}
# endif
		strncpy (buf->nodename, "localhost", LHIP_MIN (sizeof (buf->nodename), 9));
	}
	return ret;
}

