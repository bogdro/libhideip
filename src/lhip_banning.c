/*
 * A library for secure removing files.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2008-2012 Bogdan Drozdowski, bogdandr (at) op.pl
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
#include "libhideip.h"

static char __lhip_exename[LHIP_MAXPATHLEN];	/* 4096 */
static char __lhip_omitfile[LHIP_MAXPATHLEN];
static const char __lhip_banfilename[] = LHIP_BANNING_USERFILE;

/******************* some of what's below comes from libsafe ***************/

#ifndef LHIP_ANSIC
static char *
__lhip_get_exename LHIP_PARAMS((char * const exename, const size_t size));
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
	for ( i = 0; i < size; i++ )
	{
		exename[i] = '\0';
	}
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

#ifndef LHIP_ANSIC
static int
__lhip_is_banned_in_file LHIP_PARAMS((const char * const exename, const char * const ban_file_name));
#endif

/**
 * Checks if the given program is banned (listed) in the given file.
 * \param exename The program name to check.
 * \param ban_file_name The name of the banning file to check.
 * \return The buffer.
 */
static int GCC_WARN_UNUSED_RESULT
__lhip_is_banned_in_file (
#ifdef LHIP_ANSIC
	const char * const exename, const char * const ban_file_name)
#else
	exename, ban_file_name)
	const char * const exename;
	const char * const ban_file_name;
#endif
{
	FILE *fp;
	int ret = 0;	/* DEFAULT: NO, this program is not banned */
	size_t line_len;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	if ( (exename == NULL) || (ban_file_name == NULL) )
	{
		return ret;
	}

#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	fp = (*__lhip_real_fopen_location ()) (ban_file_name, "r");
	if ( fp != NULL )
	{
		while ( fgets (__lhip_omitfile, sizeof (__lhip_omitfile), fp) != NULL )
		{
			__lhip_omitfile[LHIP_MAXPATHLEN - 1] = '\0';

			if ( (__lhip_omitfile[0] != '\0') /*(strlen (__lhip_omitfile) > 0)*/
				&& (__lhip_omitfile[0] != '\n')
				&& (__lhip_omitfile[0] != '\r') )
			{
				do
				{
					line_len = strlen (__lhip_omitfile);
					if ( line_len == 0 )
					{
						break;
					}
					if ( (__lhip_omitfile[line_len-1] == '\r')
						|| (__lhip_omitfile[line_len-1] == '\n') )
					{
						__lhip_omitfile[line_len-1] = '\0';
					}
					else
					{
						break;
					}
				}
				while ( line_len != 0 );
				if ( line_len == 0 )
				{
					/* empty line in file - shouldn't happen here */
					continue;
				}
				/*if (strncmp (omitfile, exename, sizeof (omitfile)) == 0)*/
				/* NOTE the reverse parameters */
				/* char *strstr(const char *haystack, const char *needle); */
				if (strstr (exename, __lhip_omitfile) != NULL)
				{
					/* needle found in haystack */
					ret = 1;	/* YES, this program is banned */
					break;
				}
			}
		}
		fclose (fp);
	}
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return ret;
}


/* =============================================================== */

int GCC_WARN_UNUSED_RESULT
__lhip_check_prog_ban (
#ifdef LHIP_ANSIC
	void
#endif
)
{
	int	ret = 0;	/* DEFAULT: NO, this program is not banned */
#if (defined LHIP_ENABLE_USERBANS) && (defined HAVE_GETENV) && (defined HAVE_MALLOC)
	char *path = NULL;
	char * full_path = NULL;
	size_t path_len;
	static size_t filename_len = 0;
	static size_t filesep_len = 0;
#endif

	/* Is this process on the list of applications to ignore? */
	__lhip_get_exename (__lhip_exename, LHIP_MAXPATHLEN);
	__lhip_exename[LHIP_MAXPATHLEN-1] = '\0';
	if ( __lhip_exename[0] == '\0' /*strlen (__lhip_exename) == 0*/ )
	{
		/* can't find executable name. Assume not banned */
		return 0;
	}

	if ( __lhip_real_fopen_location () != NULL )
	{
		ret = __lhip_is_banned_in_file (__lhip_exename, SYSCONFDIR LHIP_PATH_SEP "libhideip.progban");
#if (defined LHIP_ENABLE_ENV) && (defined HAVE_GETENV)
		if ( ret == 0 )
		{
			ret = __lhip_is_banned_in_file (__lhip_exename, getenv (LHIP_BANNING_ENV));
		}
#endif
#if (defined LHIP_ENABLE_USERBANS) && (defined HAVE_GETENV) && (defined HAVE_MALLOC)
		if ( ret == 0 )
		{
			path = getenv ("HOME");
			if ( path != NULL )
			{
				path_len = strlen (path);
				if ( filename_len == 0 )
				{
					filename_len = strlen (__lhip_banfilename);
				}
				if ( filesep_len == 0 )
				{
					filesep_len = strlen (LHIP_PATH_SEP);
				}
				full_path = (char *) malloc (path_len + 1 + filesep_len + 1 + filename_len + 1);
				if ( full_path != NULL )
				{
					strncpy (full_path, path, path_len+1);
					strncat (full_path, LHIP_PATH_SEP, filesep_len+1);
					strncat (full_path, __lhip_banfilename, filename_len+1);
					ret = __lhip_is_banned_in_file (__lhip_exename, full_path);
					free (full_path);
				}
			}
		}
#endif
	}
	return ret;
}
