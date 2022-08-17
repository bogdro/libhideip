/*
 * A library for secure removing files.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2008-2010 Bogdan Drozdowski, bogdandr (at) op.pl
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
#include "lhip_paths.h"

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "lhip_priv.h"

static char __lhip_exename[LHIP_MAXPATHLEN];	/* 4096 */
static char __lhip_omitfile[LHIP_MAXPATHLEN];

/******************* some of what's below comes from libsafe ***************/

#ifndef LHIP_ANSIC
static char *
__lhip_get_exename PARAMS((char * const exename, const size_t size));
#endif

/**
 * Gets the running program's name and puts in into the given buffer.
 * \param exename The buffer to put into.
 * \param size The size of the buffer.
 * \return The buffer.
 */
static char *
__lhip_get_exename (
#ifdef LHIP_ANSIC
	char * const exename, const size_t size)
#else
	exename, size)
	char * const exename;
	const size_t size;
#endif
{
	size_t i;
#ifdef HAVE_READLINK
	ssize_t res;
#endif
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	for ( i=0; i < size; i++ ) exename[i] = '\0';
	/* get the name of the current executable */
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
#ifdef HAVE_READLINK
	res = readlink ("/proc/self/exe", exename, size - 1);
	if (res == -1)
	{
		exename[0] = '\0';
	}
	else
	{
		exename[res] = '\0';
	}
#else
	exename[0] = '\0';
#endif
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return exename;
}

/* =============================================================== */

int GCC_WARN_UNUSED_RESULT
__lhip_check_prog_ban (
#ifdef LHIP_ANSIC
	void
#endif
)
{
	FILE    *fp;
	int	ret = 0;	/* DEFAULT: NO, this program is not banned */

	/* Is this process on the list of applications to ignore? */
	__lhip_get_exename (__lhip_exename, LHIP_MAXPATHLEN);
	__lhip_exename[LHIP_MAXPATHLEN-1] = '\0';
	if ( strlen (__lhip_exename) == 0 )
	{
		/* can't find executable name. Assume not banned */
		return 0;
	}

	if ( __lhip_real_fopen_location () != NULL )
	{
		fp = (*__lhip_real_fopen_location ()) (SYSCONFDIR LHIP_PATH_SEP "libhideip.progban", "r");
		if (fp != NULL)
		{
			while ( fgets (__lhip_omitfile, sizeof (__lhip_omitfile), fp) != NULL )
			{
				__lhip_omitfile[LHIP_MAXPATHLEN - 1] = '\0';

				if ( (strlen (__lhip_omitfile) > 0) && (__lhip_omitfile[0] != '\n')
					&& (__lhip_omitfile[0] != '\r') )
				{
					/*if (strncmp (omitfile, exename, sizeof (omitfile)) == 0)*/
					/* NOTE the reverse parameters */
					/* char *strstr(const char *haystack, const char *needle); */
					if (strstr (__lhip_exename, __lhip_omitfile) != NULL)
					{
						/* needle found in haystack */
						fclose (fp);
						ret = 1;	/* YES, this program is banned */
					}
				}
			}
			fclose (fp);
		}
	}
	return ret;
}
