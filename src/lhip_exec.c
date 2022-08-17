/*
 * A library for hiding local IP address.
 *	-- execution functions' replacements.
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
	"uname",
	"arp",
	"netstat",
	"domainname",
	"ipmaddr",
	"mii",
	"route",
	"ifdown",
	"ifup",
	"iftop",
	"tcp",
	"ppp",
	"isdn",
	"ssh",
	"telnet",
	"rsh",
	"ntop",
	"sniff",
	"shark"
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

	/* text programming/manipulation tools and interpreters: */
	"ed",		/* matches "sed", too */
	"awk",		/* matches "nawk" and "gawk", too */
	"perl",
	"python",
	"ruby",
	"lua",
	"php",
	"tcl",
	"gcl",
	"sbcl",
	"lisp",

	/* shells (blocking "sh" can catch too many programs): */
	"bash",
	"zsh",
	"csh",
	"ksh"
};

static const char * __lhip_valuable_files[] =
{
	"if_inet6",
	"ipv6_route",
	"hosts",
	"ifcfg-",
	"hostname",
	"mactab",
	"/dev/net",
	"/dev/udp",
	"/dev/tcp"
};

#ifndef HAVE_MALLOC
static char __lhip_linkpath[LHIP_MAXPATHLEN];
static char __lhip_newlinkpath[LHIP_MAXPATHLEN];
#endif

/* ======================================================= */

/**
 * Tells if the file with the given name is forbidden to be opened.
 * \param name The name of the file to check.
 * \return 1 if forbidden, 0 otherwise.
 */
int __lhip_is_forbidden_file (
#ifdef LHIP_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#ifdef HAVE_MALLOC
	char * __lhip_linkpath;
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
	struct stat st;
# ifdef HAVE_MALLOC
	char * __lhip_newlinkpath;
# endif
#endif
#ifndef HAVE_MEMSET
	size_t i;
#endif
	unsigned int j;
	int ret = 0;

	if ( name == NULL )
	{
		return 0;
	}
	j = strlen (name) + 1;
#ifdef HAVE_MALLOC
	__lhip_linkpath = (char *) malloc ( j );
	__lhip_newlinkpath = (char *) malloc ( j );
	if ( (__lhip_linkpath != NULL) && (__lhip_newlinkpath != NULL) )
#endif
	{
#ifdef HAVE_MALLOC
# ifdef HAVE_MEMSET
		memset (__lhip_linkpath, 0, j);
		memset (__lhip_newlinkpath, 0, j);
# else
		for ( i = 0; i < j; i++ )
		{
			__lhip_linkpath[i] = '\0';
			__lhip_newlinkpath[i] = '\0';
		}
# endif
		strncpy (__lhip_linkpath, name, strlen (name));
#else
# ifdef HAVE_MEMSET
		memset (__lhip_linkpath, 0, sizeof (__lhip_linkpath));
		memset (__lhip_newlinkpath, 0, sizeof (__lhip_newlinkpath));
# else
		for ( i = 0; i < sizeof (__lhip_linkpath); i++ )
		{
			__lhip_linkpath[i] = '\0';
		}
		for ( i = 0; i < sizeof (__lhip_newlinkpath); i++ )
		{
			__lhip_newlinkpath[i] = '\0';
		}
# endif
		strncpy (__lhip_linkpath, name, sizeof (__lhip_linkpath) - 1);
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
# ifdef HAVE_MALLOC
		j = strlen (name) + 1;
# else
		j = sizeof (__lhip_newlinkpath);
# endif
		res = stat (name, &st);
		while ( res >= 0 )
		{
			if ( S_ISLNK (st.st_mode) )
			{
				res = readlink (__lhip_linkpath, __lhip_newlinkpath, j - 1 );
				if ( res < 0 )
				{
					break;
				}
				__lhip_newlinkpath[res] = '\0';
				strncpy (__lhip_linkpath, __lhip_newlinkpath, (size_t)res);
				__lhip_linkpath[res] = '\0';
			}
			else
			{
				break;
			}
			res = stat (__lhip_linkpath, &st);
		}
#endif
		for ( j=0; j < sizeof (__lhip_valuable_files)/sizeof (__lhip_valuable_files[0]); j++)
		{
			if ( strstr (__lhip_linkpath, __lhip_valuable_files[j]) != NULL )
			{
				ret = 1;
				break;
			}
		}
	}
#ifdef HAVE_MALLOC
	if ( __lhip_newlinkpath != NULL )
	{
		free (__lhip_newlinkpath);
	}
	if ( __lhip_linkpath != NULL )
	{
		free (__lhip_linkpath);
	}
#endif
	return ret;
}

/* =============================================================== */

#ifndef LHIP_ANSIC
static int __lhip_is_forbidden_program
	LHIP_PARAMS((const char * const name, char *const argv[], const int is_system));
#endif

/**
 * Tells if the program with the given name is forbidden to run.
 * \param name The name of the program to check.
 * \param argv The command-line arguments of the program (in case of exec*()).
 * \param is_system Non-zero in case of a check for the system() function.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lhip_is_forbidden_program (
#ifdef LHIP_ANSIC
	const char * const name, char *const argv[], const int is_system)
#else
	name, argv, is_system)
	const char * const name;
	char *const argv[];
	const int is_system;
#endif
{
#ifdef HAVE_MALLOC
	char * __lhip_linkpath = NULL;
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
	struct stat st;
	char *first_char = NULL;
# ifdef HAVE_MALLOC
	char * __lhip_newlinkpath = NULL;
# endif
#endif
#ifndef HAVE_MEMSET
	size_t l;
#endif
#if (defined HAVE_GETENV) && (defined HAVE_MALLOC)
	char *path = NULL;
	char *path_dir = NULL;
#endif
	unsigned int i, j, k;
	int ret = 0;
	size_t linksize = sizeof (__lhip_linkpath);
	size_t newlinksize = sizeof (__lhip_newlinkpath);

	if ( name == NULL )
	{
		return 0;
	}
	j = strlen (name) + 1;
#ifdef HAVE_MALLOC
	__lhip_linkpath = (char *) malloc ( j );
	__lhip_newlinkpath = (char *) malloc ( j );
	if ( (__lhip_linkpath != NULL) && (__lhip_newlinkpath != NULL) )
#endif
	{
#ifdef HAVE_MALLOC
		linksize = j;
		newlinksize = j;
# ifdef HAVE_MEMSET
		memset (__lhip_linkpath, 0, j);
		memset (__lhip_newlinkpath, 0, j);
# else
		for ( l = 0; l < j; l++ )
		{
			__lhip_linkpath[l] = '\0';
			__lhip_newlinkpath[l] = '\0';
		}
# endif
		strncpy (__lhip_linkpath, name, strlen (name));
#else
# ifdef HAVE_MEMSET
		memset (__lhip_linkpath, 0, linksize);
		memset (__lhip_newlinkpath, 0, newlinksize);
# else
		for ( l = 0; l < linksize; l++ )
		{
			__lhip_linkpath[l] = '\0';
		}
		for ( l = 0; l < newlinksize; l++ )
		{
			__lhip_newlinkpath[l] = '\0';
		}
# endif
		strncpy (__lhip_linkpath, name, linksize - 1);
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
		if ( is_system )
		{
			/* system() call - find the full path of the program to run */
			first_char = strchr (name, ' ');
			if ( first_char != NULL )
			{
				strncpy (__lhip_linkpath, name,
					LHIP_MIN ((size_t)(first_char - name), linksize - 1));
			}
			else
			{
				i = strlen (name);
				strncpy (__lhip_linkpath, name, LHIP_MIN (i, linksize));
			}
			if ( strncmp (__lhip_linkpath, LHIP_PATH_SEP, 1) != 0 )
			{
				/* add path, so we have the full path to the oject and can check its type. */
# if (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H)
				path = getenv ("PATH");
				if ( path != NULL )
				{
					first_char = strchr (path, LHIP_FILE_SEP);
					if ( first_char != NULL )
					{
#  if (defined HAVE_MALLOC)
						path_dir = (char *) malloc (LHIP_MAXPATHLEN + 1);
						if ( path_dir != NULL )
						{
							do
							{
								strncpy (path_dir, path,
									LHIP_MIN ((size_t)(first_char - path), LHIP_MAXPATHLEN));
								strncat (path_dir, __lhip_linkpath,
									LHIP_MAXPATHLEN-strlen (path_dir));
								strncat (path_dir, LHIP_PATH_SEP,
									LHIP_MIN (LHIP_MAXPATHLEN-strlen (path_dir), 1));
								res = stat (path_dir, &st);
								if ( res >= 0 )
								{
									break;	/* object was found */
								}
								path = &first_char[1];
								first_char = strchr (path, LHIP_FILE_SEP);

							} while (first_char != NULL);
						}
#  endif
					}
					else
					{
#  if (defined HAVE_MALLOC)
						path_dir = (char *) malloc (strlen (path) + 1);
						if ( path_dir != NULL )
						{
							strncpy (path_dir, path, strlen (path) + 1);
						}
#  endif
					}
#  if (defined HAVE_MALLOC)
					if ( path_dir != NULL )
					{
						strncpy (__lhip_newlinkpath, path_dir, newlinksize-1);
						free (path_dir);
					}
#  else
					if ( first_char != NULL )
					{
						strncpy (__lhip_newlinkpath, path,
							LHIP_MIN ((size_t)(first_char - path), newlinksize - 1));
					}
					else
					{
						strncpy (__lhip_newlinkpath, path,
							LHIP_MIN (strlen (path) + 1, newlinksize - 1));
					}
#  endif
				}
				strncat (__lhip_newlinkpath, __lhip_linkpath, newlinksize-strlen (__lhip_newlinkpath));
				strncpy (__lhip_linkpath, __lhip_newlinkpath, linksize);
			}
# endif
		}
# ifdef HAVE_MALLOC
		j = strlen (__lhip_linkpath) + 1;
# else
		j = sizeof (__lhip_newlinkpath);
# endif
		res = stat (__lhip_linkpath, &st);
		while ( res >= 0 )
		{
			if ( S_ISLNK (st.st_mode) )
			{
				res = readlink (__lhip_linkpath, __lhip_newlinkpath, j - 1 );
				if ( res < 0 )
				{
					break;
				}
				__lhip_newlinkpath[res] = '\0';
				strncpy (__lhip_linkpath, __lhip_newlinkpath, (size_t)res);
				__lhip_linkpath[res] = '\0';
			}
			else break;
			res = stat (__lhip_linkpath, &st);
		}
#endif
		for ( j = 0; j < sizeof (programs)/sizeof (programs[0]); j++)
		{
			if ( strstr (name, programs[j]) != NULL )
			{
				ret = 1;
				break;
			}
			if ( strstr (__lhip_linkpath, programs[j]) != NULL )
			{
				ret = 1;
				break;
			}
		}
		if ( (argv != NULL) && (ret == 0) )
		{
			/*
			now check if the viewing programs aren't used to get the contents
			of valuable files like /etc/hosts
			*/
			for ( i = 0; (ret == 0)
				&& (i < sizeof (viewing_programs)/sizeof (viewing_programs[0])); i++)
			{
				if ( strstr (__lhip_linkpath, viewing_programs[i]) != NULL )
				{
					k = 0;
					while ( (argv[k] != NULL) && (ret == 0) )
					{
						if ( __lhip_is_forbidden_file (argv[k]) != 0 )
						{
							ret = 1;
							break;
						}
					}
				}
			}
		}
		if ( __lhip_is_forbidden_file (__lhip_linkpath) != 0 )
		{
			ret = 1;
		}
	} /* if ( __lhip_linkpath != NULL && __lhip_newlinkpath != NULL ) */
#ifdef HAVE_MALLOC
	if ( __lhip_newlinkpath != NULL )
	{
		free (__lhip_newlinkpath);
	}
	if ( __lhip_linkpath != NULL )
	{
		free (__lhip_linkpath);
	}
#endif
	return ret;
}

/* =============================================================== */

int
execve (
#ifdef LHIP_ANSIC
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

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: execve(%s)\n", (filename == NULL)? "null" : filename);
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

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_execve_location ()) (filename, argv, envp);
	}

	if ( __lhip_is_forbidden_program (filename, argv, 0) != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return -1;
	}
	return (*__lhip_real_execve_location ()) (filename, argv, envp);
}

/* =============================================================== */

int
system (
#ifdef LHIP_ANSIC
	const char *command)
#else
	command)
	const char *command;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: system(%s)\n", (command == NULL)? "null" : command);
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

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_system_location ()) (command);
	}

	if ( __lhip_is_forbidden_program (command, NULL, 1) != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return -1;
	}
	return (*__lhip_real_system_location ()) (command);
}
