# ==================================================================================
#  https://www.gnu.org/software/autoconf-archive/ax_func_which_gethostbyaddr_r.html
# ==================================================================================
#
# SYNOPSIS
#
#   AX_FUNC_WHICH_GETHOSTBYADDR_R
#
# DESCRIPTION
#
#   Determines which historical variant of the gethostbyaddr_r() call
#   (taking five, seven or eight arguments) is available on the system and
#   defines one of the following macros accordingly:
#
#     HAVE_FUNC_GETHOSTBYADDR_R_8
#     HAVE_FUNC_GETHOSTBYADDR_R_7
#     HAVE_FUNC_GETHOSTBYADDR_R_5
#
#   as well as
#
#     HAVE_GETHOSTBYADDR_R
#
# LICENSE
#
#   Copyright (c) 2023 Bogdan Drozdowski <bogdro /at/ users.sourceforge.net>
#   Based on AX_FUNC_WHICH_GETHOSTBYNAME_R:
#    Copyright (c) 2008 Caolan McNamara <caolan@skynet.ie>
#    Copyright (c) 2008 Daniel Richard G. <skunk@iskunk.org>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <https://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 1

AC_DEFUN([AX_FUNC_WHICH_GETHOSTBYADDR_R], [

    AC_LANG_PUSH([C])
    AC_MSG_CHECKING([how many arguments gethostbyaddr_r() takes])

    AC_CACHE_VAL([ac_cv_func_which_gethostbyaddr_r], [

################################################################

ac_cv_func_which_gethostbyaddr_r=unknown

#
# ONE ARGUMENT (sanity check)
#

# This should fail, as there is no variant of gethostbyaddr_r() that takes
# a single argument. If it actually compiles, then we can assume that
# netdb.h is not declaring the function, and the compiler is thereby
# assuming an implicit prototype. In which case, we're out of luck.
#
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <netdb.h>],
        [
            char *name = "www.gnu.org";
            (void)gethostbyaddr_r(name) /* ; */
        ])],
    [ac_cv_func_which_gethostbyaddr_r=no])

#
# EIGHT ARGUMENTS
# (e.g. Linux)
#

if test "$ac_cv_func_which_gethostbyaddr_r" = "unknown"; then

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <netdb.h>],
        [
            char *name = "www.gnu.org";
            struct hostent ret, *retp;
            char buf@<:@1024@:>@;
            int buflen = 1024;
            int my_h_errno;
            socklen_t len = 11;
            int addr_type = 1;
            (void)gethostbyaddr_r(name, len, addr_type, &ret, buf, buflen, &retp, &my_h_errno) /* ; */
        ])],
    [ac_cv_func_which_gethostbyaddr_r=eight])

fi

#
# SEVEN ARGUMENTS
# (e.g. Solaris)
#

if test "$ac_cv_func_which_gethostbyaddr_r" = "unknown"; then

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <netdb.h>],
        [
            char *name = "www.gnu.org";
            struct hostent ret;
            char buf@<:@1024@:>@;
            int buflen = 1024;
            int my_h_errno;
            int len = 11;
            int addr_type = 1;
            (void)gethostbyaddr_r(name, len, addr_type, &ret, buf, buflen, &my_h_errno) /* ; */
        ])],
    [ac_cv_func_which_gethostbyaddr_r=seven])

fi

#
# FIVE ARGUMENTS
# (e.g. AIX)
#

if test "$ac_cv_func_which_gethostbyaddr_r" = "unknown"; then

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <netdb.h>],
        [
            char *name = "www.gnu.org";
            struct hostent ret;
            int len = 11;
            int addr_type = 1;
            struct hostent_data data;
            (void)gethostbyaddr_r(name, len, addr_type, &ret, &data) /* ; */
        ])],
    [ac_cv_func_which_gethostbyaddr_r=five])

fi

################################################################

]) dnl end AC_CACHE_VAL

case "$ac_cv_func_which_gethostbyaddr_r" in
    eight|seven|five)
    AC_DEFINE([HAVE_GETHOSTBYADDR_R], [1],
              [Define to 1 if you have some form of gethostbyaddr_r().])
    ;;
esac

case "$ac_cv_func_which_gethostbyaddr_r" in
    eight)
    AC_MSG_RESULT([eight])
    AC_DEFINE([HAVE_FUNC_GETHOSTBYADDR_R_8], [1],
              [Define to 1 if you have the eight-argument form of gethostbyaddr_r().])
    ;;

    seven)
    AC_MSG_RESULT([seven])
    AC_DEFINE([HAVE_FUNC_GETHOSTBYADDR_R_7], [1],
              [Define to 1 if you have the seven-argument form of gethostbyaddr_r().])
    ;;

    five)
    AC_MSG_RESULT([five])
    AC_DEFINE([HAVE_FUNC_GETHOSTBYADDR_R_5], [1],
              [Define to 1 if you have the five-argument form of gethostbyaddr_r().])
    ;;

    no)
    AC_MSG_RESULT([cannot find function declaration in netdb.h])
    ;;

    unknown)
    AC_MSG_RESULT([unknown])
    ;;

    *)
    AC_MSG_ERROR([internal error])
    ;;
esac

AC_LANG_POP

]) dnl end AC_DEFUN
