/*
 * LibHideIP - A library for hiding local IP address.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2008-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
#include "lhip_paths.h"

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lhip_priv.h"
#include "libhideip.h"

#if (defined LHIP_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
# define LHIP_CAN_USE_BANS 1
# define BANNING_CAN_USE_BANS 1
#else
# undef LHIP_CAN_USE_BANS
# define BANNING_CAN_USE_BANS 0
#endif

#if (defined LHIP_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
# define LHIP_CAN_USE_ENV 1
# define BANNING_ENABLE_ENV 1
#else
# undef LHIP_CAN_USE_ENV
# define BANNING_ENABLE_ENV 0
#endif

#ifdef TEST_COMPILE
# undef LHIP_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

#ifdef LHIP_ANSIC
# define BANNING_ANSIC 1
#else
# define BANNING_ANSIC 0
#endif

#define BANNING_SET_ERRNO(value) LHIP_SET_ERRNO(value)
#define BANNING_GET_ERRNO(value) LHIP_GET_ERRNO(variable)
#define BANNING_MAKE_ERRNO_VAR(x) LHIP_MAKE_ERRNO_VAR(x)
#define BANNING_MAXPATHLEN LHIP_MAXPATHLEN
#define BANNING_PATH_SEP LHIP_PATH_SEP
#define BANNING_PARAMS(x) LHIP_PARAMS(x)

#ifndef HAVE_READLINK
# define HAVE_READLINK 0
#endif
#ifndef HAVE_GETENV
# define HAVE_GETENV 0
#endif

#include <banning-generic.c>

#if HAVE_READLINK == 0
# undef HAVE_READLINK
#endif
#if HAVE_GETENV == 0
# undef HAVE_GETENV
#endif

/* =============================================================== */

int GCC_WARN_UNUSED_RESULT
__lhip_check_prog_ban (LHIP_VOID)
{
	int	ret = 0;	/* DEFAULT: NO, this program is not banned */
	LHIP_MAKE_ERRNO_VAR(err);

	/* Is this process on the list of applications to ignore? */
	__banning_get_exename (__banning_exename, LHIP_MAXPATHLEN);
	__banning_exename[LHIP_MAXPATHLEN-1] = '\0';
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: __lhip_check_prog_ban(): exename='%s'\n",
		__banning_exename);
	fflush (stderr);
#endif

	if ( __banning_exename[0] == '\0' /*strlen (__banning_exename) == 0*/ )
	{
		/* can't find executable name. Assume not banned */
		LHIP_SET_ERRNO (err);
		return 0;
	}

	ret = __banning_is_banned ("libhideip.progban",
		LHIP_BANNING_USERFILE, LHIP_BANNING_ENV,
		__banning_exename, __lhip_real_fopen_location());
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: __lhip_check_prog_ban()=%d\n", ret);
	fflush (stderr);
#endif
	LHIP_SET_ERRNO (err);
	return ret;
}
