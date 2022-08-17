/*
 * A library for hiding local IP address.
 *	-- execution functions' replacements.
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

#define _BSD_SOURCE 1
#define _XOPEN_SOURCE 500
#define _POSIX_C_SOURCE 200112L

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* execve(), readlink() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#include <stdio.h>	/* stdlib.h */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* system(), getenv() */
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_SYS_STAT_H
# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
# endif
# include <sys/stat.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lhip_priv.h"

/* The programs LibHideIP forbids to execute. */
static const char *programs[] =
{
	"ping",
	"traceroute",
	"tracert",
	"dig",
	"nmap",
	"nessus",
	"ifconfig",
	"ifcfg",
	"nc",
	"netcat",
	"ftp",
	"links",
	"lynx",
	"wget",
	"host",
	"hostname",
	"uname"
};

/* The programs LibHideIP conditionally forbids to execute (when they're used to get
   the contents of important files). */
static const char *viewing_programs[] =
{
	/* plain viewers: */
	"cat",
	"type",
	"tac",
	"less",
	"more",

	/* editors: */
	"vi",	/* also mathes "vim" */
	"emacs",
	"joe",
	"jed",
	"lpe",
	"pico",
	"hexedit",

	/* textutils: */
	"nl",
	"od",
	"fmt",
	"pr",
	"fold",
	"head",
	"tail",
	"split",	/* also mathes "csplit" */
	"sort",
	"uniq",
	"comm",
	"cut",
	"paste",
	"join",
	"tr",
	"expand",	/* also mathes "unexpand" */

	/* diff tools: */
	"diff",		/* also mathes "diff3" and "sdiff" */

	/* text programming/manipulation tools: */
	"ed",		/* matches "sed", too */
	"awk",		/* matches "nawk" and "gawk", too */
	"perl",
	"python",
};

static const char * __lhip_valuable_files[] =
{
	VALUABLE_FILES
};

#define  LHIP_MAXPATHLEN 4097

/* =============================================================== */

int
execve (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *filename, char *const argv[], char *const envp[])
#else
	filename, argv, envp)
	const char *filename;
	char *const argv[];
	char *const envp[];
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	unsigned int i, j, k;
	char linkpath[LHIP_MAXPATHLEN];
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
	struct stat st;
	char newlinkpath[LHIP_MAXPATHLEN];
#endif

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: execve(%s)\n", (filename==NULL)? "null" : filename);
	fflush (stderr);
#endif

	if ( __lhip_real_execve_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( filename == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_execve_location ()) (filename, argv, envp);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_execve_location ()) (filename, argv, envp);
	}

	strncpy (linkpath, filename, strlen (filename));
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	res = stat (linkpath, &st);
	while ( res >= 0 )
	{
		if ( S_ISLNK (st.st_mode) )
		{
			res = readlink (linkpath, newlinkpath, sizeof (newlinkpath) );
			if ( res < 0 ) break;
			newlinkpath[res] = '\0';
			strncpy (linkpath, newlinkpath, (size_t)res);
		}
		else break;
		res = stat (linkpath, &st);
	}
#endif
	for ( i=0; i < sizeof (programs)/sizeof (programs[0]); i++)
	{
		if ( strstr (filename, programs[i]) != NULL )
		{
#ifdef HAVE_ERRNO_H
			errno = -EPERM;
#endif
			return -1;
		}
	}
	if ( argv != NULL )
	{
		/*
		 now check if the viewing programs aren't used to get the contents
		 of valuable files like /etc/hosts
		 */
		for ( i=0; i < sizeof (viewing_programs)/sizeof (viewing_programs[0]); i++)
		{
			if ( strstr (linkpath, viewing_programs[i]) != NULL )
			{
				for ( j=0;
					j < sizeof (__lhip_valuable_files)/sizeof (__lhip_valuable_files[0]);
					j++)
				{
					k = 0;
					while ( argv[k] != NULL )
					{
						if ( strstr (argv[k], __lhip_valuable_files[j]) != NULL )
						{
#ifdef HAVE_ERRNO_H
							errno = -EPERM;
#endif
							return -1;
						}
					}
				}
			}
		}
	}
	return (*__lhip_real_execve_location ()) (filename, argv, envp);
}

/* =============================================================== */

int
system (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char *command)
#else
	command)
	const char *command;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	unsigned int i, j;
	char linkpath[LHIP_MAXPATHLEN];
	char *first_char;
#if (defined HAVE_GETENV) && (defined HAVE_MALLOC)
	char *path;
	char *path_dir;
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
	struct stat st;
#endif
#if ((defined HAVE_GETENV) && (defined HAVE_MALLOC)) ||	\
	 ((defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK))
	char newlinkpath[LHIP_MAXPATHLEN];
#endif

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: system(%s)\n", (command==NULL)? "null" : command);
	fflush (stderr);
#endif

	if ( __lhip_real_system_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( command == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_system_location ()) (command);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < 2) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_system_location ()) (command);
	}

	first_char = strchr (command, ' ');
	if ( first_char != NULL )
	{
		strncpy (linkpath, command, (size_t)(first_char - command));
	}
	else
	{
		i = strlen (command);
#define LHIP_MIN(a,b) ( ((a)<(b)) ? (a) : (b) )
		strncpy (linkpath, command, LHIP_MIN(i, LHIP_MAXPATHLEN));
	}
	/* add path, so we have the full path to the oject and can check its type. */
#if (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H)
	path = getenv ("PATH");
	first_char = strchr (path, ':');
	if ( first_char != NULL )
	{
# if (defined HAVE_MALLOC)
		path_dir = (char *) malloc (strlen (path) + 1);
		if ( path_dir != NULL )
		{
			do
			{
				strncpy (path_dir, path, (size_t)(first_char - path));
				strncat (path_dir, linkpath, LHIP_MAXPATHLEN-strlen (path_dir));
				strncat (path_dir, PATH_SEP, LHIP_MIN(LHIP_MAXPATHLEN-strlen (path_dir), 1));
				res = stat (path_dir, &st);
				if ( res >= 0 ) break;	/* object was found */
				path = &first_char[1];
				first_char = strchr (path, ':');

			} while (first_char != NULL);
		}
# endif
	}
	else
	{
# if (defined HAVE_MALLOC)
		path_dir = (char *) malloc (strlen (path) + 1);
		if ( path_dir != NULL ) strncpy (path_dir, path, strlen (path) + 1);
# endif
	}
# if (defined HAVE_MALLOC)
	strncpy (newlinkpath, path_dir, LHIP_MAXPATHLEN);
	if ( path_dir != NULL ) free (path_dir);
# else
	if ( first_char != NULL ) strncpy (newlinkpath, path, (size_t)(first_char - path));
	else strncpy (newlinkpath, path, strlen (path) + 1);
# endif
	strncat (newlinkpath, linkpath, LHIP_MAXPATHLEN-strlen (newlinkpath));
	strncpy (linkpath, newlinkpath, LHIP_MAXPATHLEN);
#endif


#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	res = stat (linkpath, &st);
	while ( res >= 0 )
	{
		if ( S_ISLNK (st.st_mode) )
		{
			res = readlink (linkpath, newlinkpath, sizeof (newlinkpath) );
			if ( res < 0 ) break;
			newlinkpath[res] = '\0';
			strncpy (linkpath, newlinkpath, (size_t)res);
		}
		else break;
		res = stat (linkpath, &st);
	}
#endif
	for ( i=0; i < sizeof (programs)/sizeof (programs[0]); i++)
	{
		if ( strstr (command, programs[i]) != NULL )
		{
#ifdef HAVE_ERRNO_H
			errno = -EPERM;
#endif
			return -1;
		}
	}
	/*
	 now check if the viewing programs aren't used to get the contents
	 of valuable files like /etc/hosts
	*/
	for ( i=0; i < sizeof (viewing_programs)/sizeof (viewing_programs[0]); i++)
	{
		if ( strstr (linkpath, viewing_programs[i]) != NULL )
		{
			for ( j=0;
				j < sizeof (__lhip_valuable_files)/sizeof (__lhip_valuable_files[0]);
				j++)
			{
				if ( strstr (command, __lhip_valuable_files[j]) != NULL )
				{
#ifdef HAVE_ERRNO_H
					errno = -EPERM;
#endif
					return -1;
				}
			}
		}
	}
	return (*__lhip_real_system_location ()) (command);
}
