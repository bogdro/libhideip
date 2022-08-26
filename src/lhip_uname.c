/*
 * A library for hiding local IP address.
 *	-- uname function replacement.
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

#ifdef TEST_COMPILE
# undef LHIP_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

/* =============================================================== */

int
uname (
#ifdef LHIP_ANSIC
	struct utsname *buf)
#else
	buf)
	struct utsname *buf;
#endif
{
	LHIP_MAKE_ERRNO_VAR(err);
	int ret;

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: uname()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_uname_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( buf == NULL )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_uname_location ()) (buf);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO (err);
		return (*__lhip_real_uname_location ()) (buf);
	}

	ret = (*__lhip_real_uname_location ()) (buf);
	if ( ret >= 0 )
	{
		LHIP_MEMSET (&(buf->nodename), 0, sizeof (buf->nodename));
		strncpy (buf->nodename, "localhost", LHIP_MIN (sizeof (buf->nodename), 9)+1);
	}
	return ret;
}
