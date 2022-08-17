/*
 * A library for secure removing files.
 *	-- unit test common functions - header file.
 *
 * Copyright (C) 2015-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#ifndef LHIPTEST_COMMON_HEADER
# define LHIPTEST_COMMON_HEADER 1

# include <check.h>

/* compatibility with older check versions */
# ifndef ck_abort
#  define ck_abort() ck_abort_msg(NULL)
#  define ck_abort_msg fail
#  define ck_assert(C) ck_assert_msg(C, NULL)
#  define ck_assert_msg fail_unless
# endif

# ifndef _ck_assert_int
#  define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
#  define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
#  define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
# endif

# ifndef _ck_assert_str
#  define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
#  define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
#  define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
# endif

# define LHIP_MAXHOSTLEN 16384
# if defined(__GNUC__) && __GNUC__ >= 3
#  define LHIP_ALIGN(x) __attribute__((aligned(x)))
# else
#  define LHIP_ALIGN(x)
# endif

/* LHIP_PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# undef LHIP_PARAMS
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
#  define LHIP_PARAMS(protos) protos
#  define LHIP_ANSIC
# else
#  define LHIP_PARAMS(protos) ()
#  undef LHIP_ANSIC
# endif

# if (defined LHIP_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
#  define LHIP_CAN_USE_BANS 1
# else
#  undef LHIP_CAN_USE_BANS
# endif

# if (defined LHIP_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
#  define LHIP_CAN_USE_ENV 1
# else
#  undef LHIP_CAN_USE_ENV
# endif

# define LHIP_TEST_FILENAME "zz1"
# define LHIP_TEST_FILE_LENGTH 3
# define LHIP_LINK_FILENAME "zz1link"
# define LHIP_TEST_BANNED_FILENAME "/etc/hosts"
# define LHIP_TEST_BANNED_FILENAME_SHORT "hosts"
# define LHIP_TEST_BANNED_LINKNAME "banlink"
# define LHIP_EXIT_VALUE (-222)

# define LHIP_PROLOG_FOR_TEST() \
	puts(__func__)

# ifdef __cplusplus
extern "C" {
# endif

extern void verify_ipv4 LHIP_PARAMS((void * addr4));
extern void verify_ipv6 LHIP_PARAMS((void * addr_ip6));
extern void lhiptest_prepare_banned_file LHIP_PARAMS((void));
extern TCase * lhiptest_add_fixtures LHIP_PARAMS((TCase * tests));

# ifdef __cplusplus
}
# endif

#endif /* LHIPTEST_COMMON_HEADER */
