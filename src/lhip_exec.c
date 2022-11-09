/*
 * LibHideIP - A library for hiding local IP address.
 *	-- execution functions' replacements.
 *
 * Copyright (C) 2008-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#ifdef HAVE_LIBGEN_H
# include <libgen.h>
#endif

#ifdef HAVE_LINUX_FCNTL_H
# include <linux/fcntl.h>
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
	"hostid",
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

/* The programs LibHideIP conditionally forbids to execute (when they're
   used to get the contents of important files). */
static const char *viewing_programs[] =
{
	/* plain viewers: */
	"cat",
	"type",
	"tac",
	"less",
	"more",
	"coreutils",

	/* editors: */
	"vi",	/* also matches "vim" */
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
	"split",	/* also matches "csplit" */
	"sort",
	"uniq",
	"comm",
	"cut",
	"paste",
	"join",
	"tr",
	"expand",	/* also matches "unexpand" */

	/* diff tools: */
	"diff",		/* also matches "diff3" and "sdiff" */

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
	"/dev/tcp",
	"/proc/net/fib_trie"
};

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_EXECVEAT
extern int execveat LHIP_PARAMS ((int dirfd, const char *pathname,
	char *const argv[], char *const envp[], int flags));
#endif
#ifndef HAVE_FEXECVE
extern int fexecve LHIP_PARAMS ((int fd, char *const argv[], char *const envp[]));
#endif

#ifdef __cplusplus
}
#endif

#ifdef TEST_COMPILE
# undef LHIP_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

#ifndef HAVE_MALLOC
static char __lhip_linkpath[LHIP_MAXPATHLEN + 1];
static char __lhip_newlinkpath[LHIP_MAXPATHLEN + 1];
static char __lhip_newlinkdir[LHIP_MAXPATHLEN + 1];
#endif

/* ======================================================= */

#ifndef LHIP_ANSIC
static char * __lhip_get_target_link_path
	LHIP_PARAMS ((char * const name));
#endif

/**
 * Gets the final target object name of the given link (the name of the
 *  first object being pointed to, which is not a link).
 * \param name The name of the link to traverser.
 * \return The real target's name.
 */
static char * __lhip_get_target_link_path (
#ifdef LHIP_ANSIC
	char * const name)
#else
	name)
	char * const name;
#endif
{
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
	ssize_t lnk_res;
	char * current_name;
	off_t lsize;
# ifdef HAVE_LSTAT64
	struct stat64 st;
# else
#  ifdef HAVE_LSTAT
	struct stat st;
#  endif
# endif
# ifdef HAVE_MALLOC
	char * __lhip_newlinkpath;
	char * __lhip_newlinkdir;
# endif
	char * last_slash;
	size_t dirname_len;

	if ( name == NULL )
	{
		return NULL;
	}

# ifdef HAVE_CANONICALIZE_FILE_NAME
	current_name = canonicalize_file_name (name);
	if ( current_name != NULL )
	{
		return current_name;
	}
# endif
# ifdef HAVE_REALPATH
	current_name = realpath (name, NULL);
	if ( current_name != NULL )
	{
		return current_name;
	}
# endif

	/* find the real path manually: */
	current_name = LHIP_STRDUP (name);
	if ( current_name != NULL )
	{
# ifdef HAVE_LSTAT64
		res = lstat64 (current_name, &st);
# else
#  ifdef HAVE_LSTAT
		res = lstat (current_name, &st);
#  else
		res = -1;
#  endif
# endif
		while ( res >= 0 )
		{
			if ( ! S_ISLNK (st.st_mode) )
			{
				break;
			}
			lsize = st.st_size;
			if ( lsize <= 0 )
			{
				break;
			}
			/* in case the link's target is a relative path,
			prepare to prepend the link's directory name */
			/*
			 * BUG in glibc (2.30?) or gcc - when not run with
			 * -Os, rindex/strrchr reaches outside of the buffer.
			 * glibc-X/sysdeps/x86_64/multiarch/strchr-sse2-no-bsf.S?
			 */
			/*last_slash = rindex (current_name, '/');*/
			last_slash = strrchr (current_name, '/');
			if ( last_slash != NULL )
			{
				dirname_len = (size_t)(last_slash - current_name);
			}
			else
			{
				dirname_len = 0;
			}
# ifdef HAVE_MALLOC
			__lhip_newlinkpath = (char *) malloc ((size_t)(
				dirname_len + 1
				+ (size_t)lsize + 1));
			if ( __lhip_newlinkpath == NULL )
			{
				break;
			}
# else /* ! HAVE_MALLOC */
			lsize = sizeof (__lhip_newlinkpath);
# endif /* HAVE_MALLOC */
			LHIP_MEMSET (__lhip_newlinkpath, 0, (size_t)lsize);
			lnk_res = readlink (current_name, __lhip_newlinkpath, (size_t)lsize);
			if ( (lnk_res < 0) || (lnk_res > lsize) )
			{
# ifdef HAVE_MALLOC
				free (__lhip_newlinkpath);
# endif /* HAVE_MALLOC */
				break;
			}
			__lhip_newlinkpath[lnk_res] = '\0';
			if ( (__lhip_newlinkpath[0] != '/') && (dirname_len > 0) )
			{
				/* The link's target is a relative path (no slash) in a
				different directory (there was a slash in the original path)
				- append the link's directory name */
# ifdef HAVE_MALLOC
				__lhip_newlinkdir = (char *) malloc ((size_t)(
					dirname_len + 1
					+ (size_t)lsize + 1));
				if ( __lhip_newlinkdir == NULL )
				{
					free (__lhip_newlinkpath);
					break;
				}
# endif /* HAVE_MALLOC */
				strncpy (__lhip_newlinkdir, current_name, dirname_len);
				__lhip_newlinkdir[dirname_len] = '/';
				__lhip_newlinkdir[dirname_len + 1] = '\0';
				strncat (__lhip_newlinkdir, __lhip_newlinkpath,
					(size_t)lsize + 1);
				__lhip_newlinkdir[dirname_len + 1
					+ (size_t)lsize] = '\0';
				strncpy (__lhip_newlinkpath, __lhip_newlinkdir,
					dirname_len + 1 + (size_t)lsize + 1);
				__lhip_newlinkpath[dirname_len + 1 +
					(size_t)lsize] = '\0';
# ifdef HAVE_MALLOC
				free (__lhip_newlinkdir);
# endif /* HAVE_MALLOC */
			}
			res = strcmp (current_name, __lhip_newlinkpath);
# ifdef HAVE_MALLOC
			free (current_name);
# endif /* HAVE_MALLOC */
			current_name = __lhip_newlinkpath;

			if ( res == 0 )
			{
				/* the old and new names are the same - a link pointing to itself */
				break;
			}
# ifdef HAVE_LSTAT64
			res = lstat64 (current_name, &st);
# else
#  ifdef HAVE_LSTAT
			res = lstat (current_name, &st);
#  else
			res = -1;
#  endif
# endif
		} /* while ( res >= 0 ) */
		return current_name;
	}
	else
	{
		/* NOTE: memory not allocated - return NULL to avoid returning
		 * a local variable from __lhip_get_target_link_path_fd()
	 	 */
		return NULL /*name*/;
	}
#else
	/* NOTE: return a copy to avoid returning a local variable
	 * from __lhip_get_target_link_path_fd()
	 */
	return LHIP_STRDUP (name) /*name*/;
#endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) && (defined HAVE_LSTAT) */
}

/* ======================================================= */

#ifndef LHIP_ANSIC
static char * __lhip_get_target_link_path_fd
	LHIP_PARAMS ((const int fd));
#endif

/**
 * Gets the final target object name of the given link (the name of the
 *  first object being pointed to, which is not a link).
 * \param name The name of the link to traverser.
 * \return The real target's name.
 */
static char * __lhip_get_target_link_path_fd (
#ifdef LHIP_ANSIC
	const int fd)
#else
	fd)
	const int fd;
#endif
{
	/* strlen(/proc) + strlen(/self) + strlen(/fd/) + strlen(maxint) + '\0' */
	char linkpath[5 + 5 + 4 + 10 + 1];

	if ( fd < 0 )
	{
		return NULL;
	}
#ifdef HAVE_SNPRINTF
	snprintf (linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
#else
	sprintf (linkpath, "/proc/self/fd/%d", fd);
#endif
	linkpath[sizeof(linkpath) - 1] = '\0';
	return __lhip_get_target_link_path (linkpath);
}

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
	char * name_copy;
#endif
	unsigned int j;
	int ret = 0;

	if ( name == NULL )
	{
		return 0;
	}
#ifdef HAVE_MALLOC
	name_copy = LHIP_STRDUP (name);
	if ( name_copy == NULL )
	{
		return 0;
	}
	__lhip_linkpath = __lhip_get_target_link_path (name_copy);
#else
	strncpy (__lhip_linkpath, name, sizeof (__lhip_linkpath)-1);
	strncpy (__lhip_linkpath, __lhip_get_target_link_path (__lhip_linkpath), sizeof (__lhip_linkpath)-1);
	__lhip_linkpath[sizeof (__lhip_linkpath) - 1] = '\0';
#endif
	for ( j = 0; j < sizeof (__lhip_valuable_files)/sizeof (__lhip_valuable_files[0]); j++)
	{
		if ( strstr (__lhip_linkpath, __lhip_valuable_files[j]) != NULL )
		{
			ret = 1;
			break;
		}
	}
#ifdef HAVE_MALLOC
	free (name_copy);
	if ( (__lhip_linkpath != NULL) /*&& (__lhip_linkpath != name_copy)*/ )
	{
		free ((void *)__lhip_linkpath);
	}
#endif
	return ret;
}

/* =============================================================== */

#ifndef LHIP_ANSIC
static void __lhip_append_path
	LHIP_PARAMS ((char * const path, const char * const name, const size_t path_size));
#endif

/**
 * Appends the given element to the given path.
 * \param path The path to append to.
 * \param name The element to append.
 * \param path_size the size of the "path" array/pointer
 */
static void __lhip_append_path (
#ifdef LHIP_ANSIC
	char * const path, const char * const name, const size_t path_size)
#else
	path, name, path_size)
	char * const path;
	const char * const name;
	const size_t path_size;
#endif
{
	size_t path_len;
	size_t sep_len;
	size_t name_len;

	if ( (path == NULL) || (name == NULL) || (path_size == 0) )
	{
		return;
	}

	path_len = strlen (path);
	sep_len = strlen (LHIP_PATH_SEP);
	name_len = strlen (name);

	strncat (path, LHIP_PATH_SEP,
		LHIP_MIN (path_size - path_len - 1, sep_len));
	strncat (path, name,
		LHIP_MIN (path_size - path_len - 1, name_len));
	path[path_size - 1] = '\0';
}

/* =============================================================== */

#ifndef LHIP_ANSIC
static int __lhip_is_forbidden_program
	LHIP_PARAMS ((const char * const name, char *const argv[], const int is_system));
#endif

#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
# define LHIP_ONLY_WITH_STAT_AND_READLINK
#else
# define LHIP_ONLY_WITH_STAT_AND_READLINK LHIP_ATTR ((unused))
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
	const char * const name, char *const argv[],
	const int is_system LHIP_ONLY_WITH_STAT_AND_READLINK
	)
#else
	name, argv, is_system)
	const char * const name;
	char *const argv[];
	const int is_system LHIP_ONLY_WITH_STAT_AND_READLINK;
#endif
{
#ifdef HAVE_MALLOC
	char * __lhip_linkpath = NULL;
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
# ifdef HAVE_STAT64
	struct stat64 st;
# else
#  ifdef HAVE_STAT
	struct stat st;
#  endif
# endif
	char *first_char = NULL;
# if (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H)
	char *path = NULL;
#  ifdef HAVE_MALLOC
	char *path_dir = NULL;
#  endif
# endif
#endif
	size_t i, j;
	unsigned int k;
	int ret = 0;

	if ( name == NULL )
	{
		return 0;
	}

#ifdef HAVE_MALLOC
	j = strlen (name);
	j = LHIP_MAX (LHIP_MAXPATHLEN, j);
	__lhip_linkpath = (char *) malloc (j + 1);
	if ( __lhip_linkpath != NULL )
#else
	j = LHIP_MAXPATHLEN;
#endif
	{
		LHIP_MEMSET (__lhip_linkpath, 0, j + 1);

		strncpy (__lhip_linkpath, name, j + 1);
		__lhip_linkpath[j] = '\0';
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
		if ( is_system )
		{
			/* system() call - find the full path of the program to run.
			   If space is not found, then 'name' is the full program
			   name and it's already copied to '__lhip_linkpath' */
			first_char = strchr (name, ' ');
			if ( first_char != NULL )
			{
				/* space found - copy everything before it as the program name */
				strncpy (__lhip_linkpath, name,
					LHIP_MIN ((size_t)(first_char - name), j));
				__lhip_linkpath[first_char - name] = '\0';
			}
			__lhip_linkpath[j] = '\0';
			if ( strncmp (__lhip_linkpath, LHIP_PATH_SEP, strlen(LHIP_PATH_SEP)) != 0 )
			{
				/* add path, so we have the full path to the object and can check its type. */
# if (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H)
				path = getenv ("PATH");
				if ( path != NULL )
				{
					first_char = strchr (path, LHIP_FILE_SEP);
#  if (defined HAVE_MALLOC)
					if ( first_char != NULL )
					{
						path_dir = (char *) malloc (j + 1);
						if ( path_dir != NULL )
						{
							LHIP_MEMSET (path_dir, 0, j + 1);

							do
							{
								strncpy (path_dir, path,
									LHIP_MIN ((size_t)(first_char - path), j));
								path_dir[LHIP_MIN ((size_t)(first_char - path), j)]
									= '\0';
								__lhip_append_path (path_dir, __lhip_linkpath, j);
								path_dir[j] = '\0';
#   ifdef HAVE_STAT64
								res = stat64 (path_dir, &st);
#   else
#    ifdef HAVE_STAT
								res = stat (path_dir, &st);
#    else
								res = -1;
#    endif
#   endif
								if ( res >= 0 )
								{
									break;	/* object was found */
								}
								path = &first_char[1];
								first_char = strchr (path, LHIP_FILE_SEP);

							} while ( first_char != NULL );
						}
					}
					else
					{
						path_dir = (char *) malloc (
							strlen (path) + 1 + strlen (__lhip_linkpath) + 1);
						if ( path_dir != NULL )
						{
							strncpy (path_dir, path, strlen (path) + 1);
							path_dir[strlen (path) + 1] = '\0';
							__lhip_append_path (path_dir, __lhip_linkpath, j);
							path_dir[strlen (path) + 1 + strlen (__lhip_linkpath)] = '\0';
						}
					}
					/* path_dir, if not NULL, contains "PATH/name" */
					if ( path_dir != NULL )
					{
						strncpy (__lhip_linkpath, path_dir, j);
						__lhip_linkpath[j] = '\0';
						free (path_dir);
					}
#  else /* ! HAVE_MALLOC */
					if ( first_char != NULL )
					{
						strncpy (__lhip_newlinkpath, path,
							LHIP_MIN ((size_t)(first_char - path),
							sizeof (__lhip_newlinkpath) - 1));
						__lhip_newlinkpath[LHIP_MIN ((size_t)(first_char - path),
							sizeof (__lhip_newlinkpath) - 1)] = '\0';
					}
					else
					{
						strncpy (__lhip_newlinkpath, path,
							sizeof (__lhip_newlinkpath) - 1);
						__lhip_newlinkpath[sizeof (__lhip_newlinkpath) - 1] = '\0';
					}
					__lhip_append_path (__lhip_newlinkpath,
						__lhip_linkpath, sizeof (__lhip_newlinkpath));
					__lhip_newlinkpath[sizeof (__lhip_newlinkpath) - 1] = '\0';
					strncpy (__lhip_linkpath, __lhip_newlinkpath,
						sizeof (__lhip_newlinkpath) - 1);
					__lhip_linkpath[sizeof (__lhip_linkpath) - 1] = '\0';
#  endif /* HAVE_MALLOC */
				}
# endif /* (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H) */
			} /* if (path is not absolute) */
		} /* if is_system */
# ifdef HAVE_MALLOC
		first_char = __lhip_get_target_link_path (__lhip_linkpath);
		free ((void *)__lhip_linkpath);
		__lhip_linkpath = first_char;
# else
		strncpy (__lhip_linkpath, __lhip_get_target_link_path (__lhip_linkpath),
			sizeof (__lhip_linkpath)-1);
		__lhip_linkpath[sizeof (__lhip_linkpath) - 1] = '\0';
# endif
#endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) */
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
						k++;
					}
				}
			}
		}
		if ( (ret == 0) && (__lhip_is_forbidden_file (__lhip_linkpath) != 0) )
		{
			ret = 1;
		}
	} /* if ( __lhip_linkpath != NULL && __lhip_newlinkpath != NULL ) */
#ifdef HAVE_MALLOC
	if ( (__lhip_linkpath != NULL) && (__lhip_linkpath != name) )
	{
		free ((void *)__lhip_linkpath);
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
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: execve(%s)\n", (filename == NULL)? "null" : filename);
	fflush (stderr);
#endif

	if ( __lhip_real_execve_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( filename == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_execve_location ()) (filename, argv, envp);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_execve_location ()) (filename, argv, envp);
	}

	if ( __lhip_is_forbidden_program (filename, argv, 0) != 0 )
	{
		LHIP_SET_ERRNO_PERM();
		return -1;
	}
	if ( argv != NULL )
	{
		if ( __lhip_is_forbidden_program (argv[0], argv, 0) != 0 )
		{
			LHIP_SET_ERRNO_PERM();
			return -1;
		}
	}
	return (*__lhip_real_execve_location ()) (filename, argv, envp);
}

/* =============================================================== */

int
fexecve (
#ifdef LHIP_ANSIC
	int fd, char *const argv[], char *const envp[])
#else
	fd, argv, envp)
	int fd;
	char *const argv[];
	char *const envp[];
#endif
{
	char * real_name;
	int res;
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: fexecve(%d)\n", fd);
	fflush (stderr);
#endif

	if ( __lhip_real_fexecve_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_fexecve_location ()) (fd, argv, envp);
	}

	real_name = __lhip_get_target_link_path_fd (fd);
	if ( real_name != NULL )
	{
		res = __lhip_is_forbidden_program (real_name, argv, 0);
#ifdef HAVE_MALLOC
		free ((void *)real_name);
#endif
		if ( res != 0 )
		{
			LHIP_SET_ERRNO_PERM();
			return -1;
		}
		if ( argv != NULL )
		{
			if ( __lhip_is_forbidden_program (argv[0], argv, 0) != 0 )
			{
				LHIP_SET_ERRNO_PERM();
				return -1;
			}
		}
	}
	return (*__lhip_real_fexecve_location ()) (fd, argv, envp);
}

/* =============================================================== */

int
execveat (
#ifdef LHIP_ANSIC
	int dirfd, const char *filename, char *const argv[], char *const envp[], int flags)
#else
	dirfd, filename, argv, envp, flags)
	int dirfd;
	const char *filename;
	char *const argv[];
	char *const envp[];
	int flags;
#endif
{
#if (defined AT_EMPTY_PATH) && (defined HAVE_LINUX_FCNTL_H)
	char * real_name;
	int res;
#endif
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: execveat(%d, %s)\n", dirfd,
		(filename == NULL)? "null" : filename);
	fflush (stderr);
#endif

	if ( __lhip_real_execveat_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( filename == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_execveat_location ()) (dirfd, filename, argv, envp, flags);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_execveat_location ()) (dirfd, filename, argv, envp, flags);
	}

	if ( __lhip_is_forbidden_program (filename, argv, 0) != 0 )
	{
		LHIP_SET_ERRNO_PERM();
		return -1;
	}
	if ( argv != NULL )
	{
		if ( __lhip_is_forbidden_program (argv[0], argv, 0) != 0 )
		{
			LHIP_SET_ERRNO_PERM();
			return -1;
		}
	}
#if (defined AT_EMPTY_PATH) && (defined HAVE_LINUX_FCNTL_H)
	if ( ((filename == NULL) || (filename[0] == '\0'))
		&& ((flags & AT_EMPTY_PATH) == AT_EMPTY_PATH))
	{
		/* the dirfd is the actual file to execute */
		real_name = __lhip_get_target_link_path_fd (dirfd);
		if ( real_name != NULL )
		{
			res = __lhip_is_forbidden_program (real_name, argv, 0);
# ifdef HAVE_MALLOC
			free ((void *)real_name);
# endif
			if ( res != 0 )
			{
				LHIP_SET_ERRNO_PERM();
				return -1;
			}
			if ( argv != NULL )
			{
				if ( __lhip_is_forbidden_program (argv[0], argv, 0) != 0 )
				{
					LHIP_SET_ERRNO_PERM();
					return -1;
				}
			}
		}
	}
#endif
	return (*__lhip_real_execveat_location ()) (dirfd, filename, argv, envp, flags);
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
	LHIP_MAKE_ERRNO_VAR(err);

	__lhip_main ();
#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: system(%s)\n", (command == NULL)? "null" : command);
	fflush (stderr);
#endif

	if ( __lhip_real_system_location () == NULL )
	{
		LHIP_SET_ERRNO_MISSING();
		return -1;
	}

	if ( command == NULL )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_system_location ()) (command);
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LHIP_SET_ERRNO(err);
		return (*__lhip_real_system_location ()) (command);
	}

	if ( __lhip_is_forbidden_program (command, NULL, 1) != 0 )
	{
		LHIP_SET_ERRNO_PERM();
		return -1;
	}
	return (*__lhip_real_system_location ()) (command);
}
