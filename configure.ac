#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libhideip, 0.9, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile doc/libhideip.texi
	libhideip.spec src/lhip_cfg.h src/libhideip.h src/lhip_public.c
	libhideip.pc test/Makefile])
AC_CONFIG_SRCDIR([src/lhip_net.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])


# ==================== configure arguments

AC_ARG_ENABLE([public-interface],
	AS_HELP_STRING([--enable-public-interface],
		[Enable the library's public interface @<:@default=no@:>@.]),
        [if (test "x$enableval" = "xyes"); then
                public_if=yes
         else
                public_if=no
         fi
        ]
        ,[public_if=no])

AM_CONDITIONAL(PUBLIC_INTERFACE, test "x$public_if" = "xyes")

AC_ARG_ENABLE([environment],
	AS_HELP_STRING([--enable-environment],
		[Enable additional ban files pointed to by environment variables @<:@default=yes@:>@.]),
        [if (test "x$enableval" = "xyes"); then
                environment=yes
         else
                environment=no
         fi
        ]
        ,[environment=yes])

if (test "x$environment" = "xyes"); then

	AC_DEFINE([LHIP_ENABLE_ENV], [1],
		[Whether or not to enable additional ban files pointed to by environment variables.])
fi

AC_ARG_ENABLE([user-files],
	AS_HELP_STRING([--enable-user-files],
		[Enable additional ban files located in users' home directories @<:@default=yes@:>@.]),
        [if (test "x$enableval" = "xyes"); then
                user_files=yes
         else
                user_files=no
         fi
        ]
        ,[user_files=yes])

if (test "x$user_files" = "xyes"); then

	AC_DEFINE([LHIP_ENABLE_USERBANS], [1],
		[Whether or not to enable additional ban files located in users' home directories.])
fi

AC_ARG_WITH([max-host-names],
	AS_HELP_STRING([--with-max-host-names=n],
		[Maximum number of addreses and aliases of your host @<:@default=100@:>@.]),
        [if (test "x$withval" != "x"); then
		AC_DEFINE_UNQUOTED([LHIP_MAX_HOSTNAMES], [$withval],
			[Maximum number of addreses and aliases of your host.])
         fi
        ])

# ==================== Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_CONDITIONAL(ISGCC, test "x$GCC" = "xyes")
AC_PROG_LIBTOOL

# ==================== Checks for libraries.
libdl=yes
AC_CHECK_LIB([dl],[dlsym],,[libdl=no])
if (test "x$libdl" = "xyes"); then
	AC_DEFINE([HAVE_LIBDL], [1], [Whether you have the libdl library])
	AC_DEFINE([HAVE_LIBDL_DLSYM], [1], [Whether you have the dlsym() function in the libdl library])
	AC_CHECK_LIB([dl],[dlvsym],[AC_DEFINE([HAVE_LIBDL_DLVSYM], [1],
		[Whether you have the dlvsym() function in the libdl library])])

fi

dlsym=yes
AC_CHECK_FUNC([dlsym],
	[AC_DEFINE([HAVE_DLSYM], [1], [Whether you have the dlsym function])],[dlsym=no])
dlvsym=yes
AC_CHECK_FUNC([dlvsym],
	[AC_DEFINE([HAVE_DLVSYM], [1], [Whether you have the dlvsym function])],[dlvsym=no])

if (test "x$libdl" != "xyes"); then

#	AC_CHECK_FUNCS([dlsym dlvsym])
	if (test "x$dlsym" != "xyes" && test "x$dlvsym" != "xyes"); then

		AC_MSG_ERROR([[I need the dlsym() and optionally dlvsym() function to work.]])
	fi
fi

# Adding additional libraries actually makes LibHideIP "see" the functions
# contained in them, via dlsym/dlvsym, so the original functions can be called.
# This adds a runtime dependency, but otherwise it could make the program
# bypass LibHideIP or make normally-working functions not available anymore.

AC_CHECK_LIB([pcap],[pcap_lookupdev])

AC_CHECK_LIB([resolv],[res_query])

# ==================== Checks for header files.
AC_CHECK_HEADER([dlfcn.h],[AC_DEFINE([HAVE_DLFCN_H], [1], [Whether you have the dlfcn.h header])],
	AC_MSG_ERROR([[I need the dlfcn.h file to work.]]), [])

AC_CHECK_DECL([RTLD_NEXT],[AC_DEFINE([HAVE_DECL_RTLD_NEXT], [1], [Whether RTLD_NEXT is defined])],
	[echo "**************************************"
	AC_MSG_ERROR([[RTLD_NEXT not defined. Use the GNU C library. Sorry.]])],
	[
	#ifndef _GNU_SOURCE
	#define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_DLFCN_H
	#include <dlfcn.h>
	#endif
	])

AC_HEADER_STDC

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h\
	sys/types.h netdb.h sys/socket.h ifaddrs.h arpa/inet.h\
	netinet/in.h sys/ioctl.h fcntl.h sys/utsname.h asm/types.h\
	arpa/nameser.h stdint.h inttypes.h])

AC_CHECK_HEADER([net/if.h],AC_DEFINE([HAVE_NET_IF_H],[1],
	[Whether you have the net/if.h header.]),[],
	[
	#ifdef HAVE_SYS_TYPES_H
	#include <sys/types.h>
	#endif
	/* need AF_MAX on OpenBSD */
	#ifdef HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
	#else
	typedef unsigned short int sa_family_t;
	#endif
	#ifdef HAVE_ASM_TYPES_H
	#include <asm/types.h>
	#else
	typedef unsigned int __u32;
	typedef unsigned short __u16;
	#endif
	])

AC_CHECK_HEADER([linux/netlink.h],AC_DEFINE([HAVE_LINUX_NETLINK_H],[1],
	[Whether you have the linux/netlink.h header.]),[],
	[
	#ifdef HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
	#else
	typedef unsigned short int sa_family_t;
	#endif
	#ifdef HAVE_ASM_TYPES_H
	#include <asm/types.h>
	#else
	typedef unsigned int __u32;
	typedef unsigned short __u16;
	#endif
	])

AC_CHECK_HEADER([resolv.h],AC_DEFINE([HAVE_RESOLV_H],[1],
	[Whether you have the resolv.h header.]),[],
	[
	#ifdef HAVE_SYS_TYPES_H
	#include <sys/types.h>
	#endif
	#ifdef HAVE_NETINET_IN_H
	#include <netinet/in.h>
	#endif
	#ifdef HAVE_ARPA_NAMESER_H
	#include <arpa/nameser.h>
	#endif
	#ifdef HAVE_NETDB_H
	#include <netdb.h>
	#endif
	])

has_sys_stat_h=yes
AC_CHECK_HEADER([sys/stat.h],AC_DEFINE([HAVE_SYS_STAT_H],[1],
	[Whether you have the sys/stat.h header.]),[has_sys_stat_h=no])

AC_HEADER_STAT

AC_CHECK_HEADER([stdarg.h],AC_DEFINE([HAVE_STDARG_H],[1],
	[Whether you have the stdarg.h header.]),
	[
	AC_CHECK_HEADER([varargs.h],AC_DEFINE([HAVE_VARARGS_H],[1],
		[Whether you have the varargs.h header.]))
	])

AC_CHECK_HEADER(pcap.h,AC_DEFINE([HAVE_PCAP_H],[1],
	[Whether you have the pcap.h header.]),
	[
	AC_CHECK_HEADER([pcap/pcap.h],AC_DEFINE([HAVE_PCAP_PCAP_H],[1],
		[Whether you have the pcap/pcap.h header.]))
	])

# ==================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

AC_CHECK_TYPES([size_t, mode_t, socklen_t, ssize_t],,,
	[
	#ifdef HAVE_SYS_TYPES_H
	#include <sys/types.h>
	#endif
	#ifdef HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
	#endif
	])

AC_DEFINE_PATH_STYLE()

# ==================== Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNC([malloc],
	AC_DEFINE([HAVE_MALLOC],[1],[Whether you have the malloc function.]))

AC_CHECK_FUNCS([memcpy memset readlink getipnodebyname \
	getipnodebyaddr getenv gethostbyaddr_r gethostbyname_r gethostbyname2_r\
	gethostent_r openat openat64 realloc symlink lstat])

AH_TEMPLATE([GETNAMEINFO_ARG4TYPE])
AH_TEMPLATE([GETNAMEINFO_ARG6TYPE])
AH_TEMPLATE([GETNAMEINFO_ARG7TYPE])
AC_CHECK_FUNC([getnameinfo], [AC_DEFINE(HAVE_GETNAMEINFO, [1], [Whether you have the getnameinfo function])
	AC_PROTOTYPE(getnameinfo,
	[
		#ifdef HAVE_SYS_TYPES_H
		#include <sys/types.h>
		#endif
		#ifdef HAVE_SYS_SOCKET_H
		#include <sys/socket.h>
		#endif
		#ifdef HAVE_NETDB_H
		#include <netdb.h>
		#endif
	],
	[
		int (*test) (const struct sockaddr *sa, socklen_t salen,
                       char *host, ARG4TYPE hostlen,
                       char *serv, ARG6TYPE servlen, ARG7TYPE flags) = &getnameinfo;
	],
	ARG4TYPE, [socklen_t, size_t],
	ARG6TYPE, [socklen_t, size_t],
	ARG7TYPE, [unsigned int, int])
	])

have_check=no
#ACTION-IF-NOT-FOUND is required, otherwise 'configure' fails
PKG_CHECK_MODULES([CHECK], [check >= 0.9.8], [have_check=yes], [have_check=no])
#AM_PATH_CHECK([], [have_check=yes])

AM_CONDITIONAL([LHIP_TESTS_ENABLED], [test "x$have_check" = "xyes"])

# ==================== Checks for compiler options.

if (test "x$GCC" = "xyes" ); then

	AX_GCC_WARN_UNUSED_RESULT()

	AX_C_CHECK_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-W], [CFLAGS="$CFLAGS -W"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wbad-function-cast], [CFLAGS="$CFLAGS -Wbad-function-cast"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wsign-compare], [CFLAGS="$CFLAGS -Wsign-compare"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wunreachable-code], [CFLAGS="$CFLAGS -Wunreachable-code"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-qual], [CFLAGS="$CFLAGS -Wcast-qual"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-security], [CFLAGS="$CFLAGS -Wformat -Wformat-security"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-nonliteral], [CFLAGS="$CFLAGS -Wformat -Wformat-nonliteral"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wconversion], [CFLAGS="$CFLAGS -Wconversion"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpadded], [CFLAGS="$CFLAGS -Wpadded"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wredundant-decls], [CFLAGS="$CFLAGS -Wredundant-decls"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfatal-errors], [CFLAGS="$CFLAGS -Wfatal-errors"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-pedantic], [CFLAGS="$CFLAGS -pedantic"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wno-strict-aliasing], [CFLAGS="$CFLAGS -Wno-strict-aliasing"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-declarations], [CFLAGS="$CFLAGS -Wmissing-declarations"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O1 -Wuninitialized], [CFLAGS="$CFLAGS -O1 -Wuninitialized"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Winit-self], [CFLAGS="$CFLAGS -Winit-self"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wlogical-op], [CFLAGS="$CFLAGS -Wlogical-op"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O2], [CFLAGS="$CFLAGS -O2"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O3], [CFLAGS="$CFLAGS -O3"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Waggregate-return], [CFLAGS="$CFLAGS -Waggregate-return"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"], [CFLAGS="$CFLAGS"])
	# required for the compiler, which is used by libtool instead of the linker
	AX_C_CHECK_FLAG([-Wl,-z -Wl,noexecstack], [CFLAGS="$CFLAGS -Wl,-z -Wl,noexecstack"], [CFLAGS="$CFLAGS"])
	# and just in case the linker was used
	AX_CHECK_LINK_FLAG([-z noexecstack])

fi

# this doubles the CFLAGS on compile:
#AC_SUBST([AM_CFLAGS],[$CFLAGS])

AC_OUTPUT

# ===================== Print summary

echo "***********************************"

if (test "x$public_if" = "xyes"); then

	echo " *	Public interface: yes"

else

	echo " *	Public interface: no (disabled by command line)"

fi

if (test "x$environment" = "xyes"); then

	echo " *	Additional ban files pointed to by environment variables: yes"

else

	echo " *	Additional ban files pointed to by environment variables: no (disabled by command line)"

fi

if (test "x$user_files" = "xyes"); then

	echo " *	Additional ban files located in users' home directories: yes"

else

	echo " *	Additional ban files located in users' home directories: no (disabled by command line)"

fi

echo "***********************************"
