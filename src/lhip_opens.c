/*
 * A library for hiding local IP address.
 *	-- file opening functions' replacements.
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

# define _LARGEFILE64_SOURCE 1
/*# define _FILE_OFFSET_BITS 64*/
#define _ATFILE_SOURCE 1

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# ifdef HAVE_VARARGS_H
#  include <varargs.h>
# endif
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* readlink() */
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

#ifdef HAVE_SYS_STAT_H
# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
# endif
# include <sys/stat.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#else
# ifdef HAVE_MALLOC_H
#  include <malloc.h>
# endif
#endif

#include <stdio.h>

#include "lhip_priv.h"

#ifdef HAVE_FCNTL_H
# include <fcntl.h>	/* open*() */
#else
extern int open LHIP_PARAMS ((const char * const path, const int flags, ... ));
extern int open64 LHIP_PARAMS ((const char * const path, const int flags, ... ));
#endif
#ifndef HAVE_OPENAT
extern int openat LHIP_PARAMS ((const int dirfd, const char * const pathname, const int flags, ...));
#endif
#ifndef HAVE_OPENAT64
extern int openat64 LHIP_PARAMS ((const int dirfd, const char * const pathname, const int flags, ...));
#endif

/*
#ifndef HAVE_FOPEN64
extern FILE* fopen64 LHIP_PARAMS((const char * const name, const char * const mode));
#endif
#ifndef HAVE_FREOPEN64
extern FILE* freopen64 LHIP_PARAMS((const char * const path, const char * const mode, FILE * stream));
#endif
#ifndef HAVE_OPEN64
extern int open64 LHIP_PARAMS((const char * const path, const int flags, ... ));
#endif
*/

/* ======================================================= */

#ifdef fopen64
# undef fopen64
#endif

FILE*
fopen64 (
#ifdef LHIP_ANSIC
	const char * const name, const char * const mode)
#else
	name, mode)
	const char * const name;
	const char * const mode;
#endif
{
#if (defined __GNUC__) && (!defined fopen64)
# pragma GCC poison fopen64
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: fopen64(%s, %s)\n", (name == NULL)? "null" : name,
		(mode == NULL)? "null" : mode);
	fflush (stderr);
#endif

	if ( __lhip_real_fopen64_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_fopen64_location ()) (name, mode);
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_fopen64_location ()) (name, mode);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_fopen64_location ()) (name, mode);
	}

	if ( __lhip_is_forbidden_file (name) != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return NULL;
	}
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lhip_real_fopen64_location ()) (name, mode);
}

/* ======================================================= */

#ifdef fopen
# undef fopen
#endif

FILE*
fopen (
#ifdef LHIP_ANSIC
	const char * const name, const char * const mode)
#else
	name, mode)
	const char * const name;
	const char * const mode;
#endif
{
#if (defined __GNUC__) && (!defined fopen)
# pragma GCC poison fopen
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: fopen(%s, %s)\n", (name == NULL)? "null" : name,
		(mode == NULL)? "null" : mode);
	fflush (stderr);
#endif

	if ( __lhip_real_fopen_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_fopen_location ()) (name, mode);
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_fopen_location ()) (name, mode);
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_fopen_location ()) (name, mode);
	}

	if ( __lhip_is_forbidden_file (name) != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return NULL;
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lhip_real_fopen_location ()) (name, mode);
}
/* ======================================================= */

#ifdef freopen64
# undef freopen64
#endif

FILE*
freopen64 (
#ifdef LHIP_ANSIC
	const char * const path, const char * const mode, FILE * stream)
#else
	path, mode, stream)
	const char * const path;
	const char * const mode;
	FILE * stream;
#endif
{
#if (defined __GNUC__) && (!defined freopen64)
# pragma GCC poison freopen64
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: freopen64(%s, %s, %ld)\n",
		(path == NULL)? "null" : path, (mode == NULL)? "null" : mode, (long int)stream);
	fflush (stderr);
#endif

	if ( __lhip_real_freopen64_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( path == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_freopen64_location ()) ( path, mode, stream );
	}

	if ( (path[0] == '\0') /*(strlen (path) == 0)*/ || (stream == stdin)
		|| (stream == stdout) || (stream == stderr)
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_freopen64_location ()) ( path, mode, stream );
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_freopen64_location ()) ( path, mode, stream );
	}

	if ( __lhip_is_forbidden_file (path) != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return NULL;
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lhip_real_freopen64_location ()) ( path, mode, stream );
}

/* ======================================================= */

#ifdef freopen
# undef freopen
#endif

FILE*
freopen (
#ifdef LHIP_ANSIC
	const char * const name, const char * const mode, FILE* stream)
#else
	name, mode, stream)
	const char * const name;
	const char * const mode;
	FILE* stream;
#endif
{
#if (defined __GNUC__) && (!defined freopen)
# pragma GCC poison freopen
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: freopen(%s, %s, %ld)\n",
		(name == NULL)? "null" : name, (mode == NULL)? "null" : mode, (long int)stream);
	fflush (stderr);
#endif

	if ( __lhip_real_freopen_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_freopen_location ()) ( name, mode, stream );
	}

	if ( (name[0] == '\0') /*(strlen (name) == 0)*/ || (stream == stdin)
		|| (stream == stdout) || (stream == stderr)
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_freopen_location ()) ( name, mode, stream );
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lhip_real_freopen_location ()) ( name, mode, stream );
	}

	if ( __lhip_is_forbidden_file (name) != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return NULL;
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lhip_real_freopen_location ()) ( name, mode, stream );
}

/* ======================================================= */

/* 'man 2 open' gives:
    int open(const char *pathname, int flags);
    int open(const char *pathname, int flags, mode_t mode);
   'man 3p open' (POSIX) & /usr/include/fcntl.h give:
    int open(const char *path, int oflag, ...  );
 */

#ifdef open64
# undef open64
#endif

int
open64 (
#ifdef LHIP_ANSIC
	const char * const path, const int flags, ... )
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	path, flags )
	const char * const path;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined open64)
# pragma GCC poison open64
#endif

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LHIP_ANSIC
	char * const path;
	int flags;
# endif
#endif
	int ret_fd;
	mode_t mode = 0666;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: open64(%s, 0%o, ...)\n", (path == NULL)? "null" : path, flags);
	fflush (stderr);
#endif

	if ( __lhip_real_open64_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LHIP_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	path = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif

	if ( path == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_open64_location ()) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( path[0] == '\0' /*strlen (path) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_open64_location ()) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_open64_location ()) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( __lhip_is_forbidden_file (path) != 0 )
	{
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return -1;
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lhip_real_open64_location ()) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_end (args);
#endif
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}

/* ======================================================= */

#ifdef open
# undef open
#endif

int
open (
#ifdef LHIP_ANSIC
	const char * const name, const int flags, ... )
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	name, flags )
	const char * const name;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined open)
# pragma GCC poison open
#endif

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LHIP_ANSIC
	char * const name;
	int flags;
# endif
#endif
	int ret_fd;
	mode_t mode = 0666;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: open(%s, 0%o, ...)\n", (name == NULL)? "null" : name, flags);
	fflush (stderr);
#endif

	if ( __lhip_real_open_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LHIP_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	name = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_open_location ()) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_open_location ()) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_open_location ()) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( __lhip_is_forbidden_file (name) != 0 )
	{
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return -1;
	}


#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lhip_real_open_location ()) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_end (args);
#endif
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}

/* ======================================================= */

#ifdef openat64
# undef openat64
#endif

int
openat64 (
#ifdef LHIP_ANSIC
	const int dirfd, const char * const pathname, const int flags, ...)
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	dirfd, pathname, flags )
	const int dirfd;
	const char * const pathname;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined openat64)
# pragma GCC poison openat64
#endif

	int ret_fd;
	mode_t mode = 0666;
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LHIP_ANSIC
	int dirfd;
	char * const pathname;
	int flags;
# endif
#endif
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: openat64(%d, %s, 0%o, ...)\n",
		dirfd, (pathname == NULL)? "null" : pathname, flags);
	fflush (stderr);
#endif

	if ( __lhip_real_openat64_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LHIP_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	dirfd = va_arg (args, int);
	pathname = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif

	if ( pathname == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_openat64_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( pathname[0] == '\0' /*strlen (pathname) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_openat64_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_openat64_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( __lhip_is_forbidden_file (pathname) != 0 )
	{
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return -1;
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lhip_real_openat64_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_end (args);
#endif
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}


/* ======================================================= */

/*/
int openat(int dirfd, const char *pathname, int flags);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 */

#ifdef openat
# undef openat
#endif

int
openat (
#ifdef LHIP_ANSIC
	const int dirfd, const char * const pathname, const int flags, ...)
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	dirfd, pathname, flags )
	const int dirfd;
	const char * const pathname;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined openat)
# pragma GCC poison openat
#endif

	int ret_fd;
	mode_t mode = 0666;
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LHIP_ANSIC
	int dirfd;
	char * const pathname;
	int flags;
# endif
#endif
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: openat(%d, %s, 0%o, ...)\n", dirfd,
		(pathname == NULL)? "null" : pathname, flags);
	fflush (stderr);
#endif

	if ( __lhip_real_openat_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LHIP_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	dirfd = va_arg (args, int);
	pathname = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif

	if ( pathname == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_openat_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( pathname[0] == '\0' /*strlen (pathname) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_openat_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lhip_check_prog_ban () != 0) || (__lhip_get_init_stage () < LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lhip_real_openat_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( __lhip_is_forbidden_file (pathname) != 0 )
	{
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
		va_end (args);
#endif
#ifdef HAVE_ERRNO_H
		errno = -EPERM;
#endif
		return -1;
	}


#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lhip_real_openat_location ()) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_end (args);
#endif
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}
