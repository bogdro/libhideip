/*
 * A library for hiding local IP address.
 *
 * Copyright (C) 2008-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
 * Parts of this file are Copyright (C) Free Software Foundation, Inc.
 * License: GNU General Public License, v3+
 *
 * Syntax example: export LD_PRELOAD=/usr/local/lib/libhideip.so
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

#if (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL))
	/* need RTLD_NEXT and dlvsym(), so define _GNU_SOURCE */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE	1
# endif
# include <dlfcn.h>
# ifndef RTLD_NEXT
#  define RTLD_NEXT ((void *) -1l)
# endif
#else
# ifdef LHIP_ANSIC
#  error Dynamic loading functions missing.
# endif
#endif

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif

#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif

#include "lhip_priv.h"

static int	__lhip_is_initialized		= LHIP_INIT_STAGE_NOT_INITIALIZED;
static void *	__lhip_handle_resolv		= NULL;
static void *	__lhip_handle_anl		= NULL;

/* --- Pointers to original functions. */
/* network-related functions: */
static shp_vp_sl_i			__lhip_real_gethostbyaddr	= NULL;
static i_vp_sl_i_shp_cp_s_shpp_ip	__lhip_real_gethostbyaddr_r	= NULL;
static shp_cp				__lhip_real_gethostbyname	= NULL;
static i_cp_shp_cp_s_shpp_ip		__lhip_real_gethostbyname_r	= NULL;
static shp_cp_i				__lhip_real_gethostbyname2	= NULL;
static i_cp_i_shp_cp_s_shpp_i		__lhip_real_gethostbyname2_r	= NULL;
static shp_v				__lhip_real_gethostent		= NULL;
static i_shp_cp_s_shpp_ip		__lhip_real_gethostent_r	= NULL;
static shp_cp_s_i_ip			__lhip_real_getipnodebyaddr	= NULL;
static shp_cp_i_i_ip			__lhip_real_getipnodebyname	= NULL;
static i_sipp				__lhip_real_getifaddrs		= NULL;
static i_ssp_sl_cp_s_cp_s_i		__lhip_real_getnameinfo		= NULL;
static i_cp_cp_sap_sapp			__lhip_real_getaddrinfo		= NULL;
static i_cp_cpp_cpp			__lhip_real_execve		= NULL;
static i_i_cpp_cpp			__lhip_real_fexecve		= NULL;
static i_i_cp_cpp_cpp_i			__lhip_real_execveat		= NULL;
static i_cp				__lhip_real_system		= NULL;
static i_i_i_va				__lhip_real_ioctl		= NULL;
static i_i_i_i				__lhip_real_socket		= NULL;
static ss_i_smp_i			__lhip_real_recvmsg		= NULL;
static ss_i_csmp_i			__lhip_real_sendmsg		= NULL;
static i_cp_s				__lhip_real_gethostname		= NULL;
static i_sup				__lhip_real_uname		= NULL;
static i_i_i_vp_slp			__lhip_real_getsockopt		= NULL;
static i_i_i_cvp_sl			__lhip_real_setsockopt		= NULL;
static i_ssp_slp			__lhip_real_getsockname		= NULL;
static i_cssp_sl			__lhip_real_bind		= NULL;
static i_i_ia2				__lhip_real_socketpair		= NULL;
#if (defined HAVE_GETADDRINFO_A) || (defined HAVE_LIBANL)
static i_i_sgpp_i_ssp			__lhip_real_getaddrinfo_a	= NULL;
#endif

/* file-related functions: */
static fp_cp_cp				__lhip_real_fopen64		= NULL;
static fp_cp_cp_fp			__lhip_real_freopen64		= NULL;
static i_cp_i_				__lhip_real_open64		= NULL;
static i_i_cp_i_			__lhip_real_openat64		= NULL;
static fp_cp_cp				__lhip_real_fopen		= NULL;
static fp_cp_cp_fp			__lhip_real_freopen		= NULL;
static i_cp_i_				__lhip_real_open		= NULL;
static i_i_cp_i_			__lhip_real_openat		= NULL;

/* name resolving functions: */
static ccp_i_ucp_i			__lhip_real_res_query		= NULL;
static r_ccp_i_ucp_i			__lhip_real_res_nquery		= NULL;
static ccp_i_ucp_i			__lhip_real_res_search		= NULL;
static r_ccp_i_ucp_i			__lhip_real_res_nsearch		= NULL;
static ccp_cpp_i_ucp_i			__lhip_real_res_querydomain	= NULL;
static r_ccp_cpp_i_ucp_i		__lhip_real_res_nquerydomain	= NULL;
static i_ccp_i_i_cucp_i_cucp_ucp_i	__lhip_real_res_mkquery		= NULL;
static r_i_ccp_i_i_cucp_i_cucp_ucp_i	__lhip_real_res_nmkquery	= NULL;

/* libpcap functions: */
static cp_cp				__lhip_real_pcap_lookupdev		= NULL;
static i_ccp_uip_uip_cp			__lhip_real_pcap_lookupnet		= NULL;
static pp_ccp_cp			__lhip_real_pcap_create			= NULL;
static pp_i_i				__lhip_real_pcap_open_dead		= NULL;
static pp_i_i_ui			__lhip_real_pcap_open_dead_ts		= NULL;
static pp_ccp_i_i_i_cp			__lhip_real_pcap_open_live		= NULL;
static pp_ccp_cp			__lhip_real_pcap_open_offline		= NULL;
static pp_ccp_ui_cp			__lhip_real_pcap_open_offline_ts	= NULL;
static pp_Fp_cp				__lhip_real_pcap_fopen_offline		= NULL;
static pp_Fp_ui_cp			__lhip_real_pcap_fopen_offline_ts	= NULL;
static pp_ipt_cp			__lhip_real_pcap_hopen_offline		= NULL;
static pp_ipt_ui_cp			__lhip_real_pcap_hopen_offline_ts	= NULL;
static i_ifpp_cp			__lhip_real_pcap_findalldevs		= NULL;
static i_cp_rmtp_ifpp_cp		__lhip_real_pcap_findalldevs_ex		= NULL;

#if ((defined HAVE_DLSYM) || (defined HAVE_LIBDL_DLSYM))		\
	&& (!defined HAVE_DLVSYM) && (!defined HAVE_LIBDL_DLVSYM)	\
	|| (defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1)))
# define LHIP_CANT_USE_VERSIONED_FOPEN 1
/*# warning Versioned fopen is unavailable, so LibHideIP may crash on some glibc versions.*/
#else
# undef LHIP_CANT_USE_VERSIONED_FOPEN
#endif

#ifdef TEST_COMPILE
# undef LHIP_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

/* =============================================================== */

#ifndef HAVE_STRDUP
char * __lhip_duplicate_string (
# ifdef LHIP_ANSIC
	const char src[])
# else
	src)
	const char src[];
# endif
{
	size_t len;
	char * dest;

	if ( src == NULL )
	{
		return NULL;
	}
	len = strlen (src);
	if ( len == 0 )
	{
		return NULL;
	}
	dest = (char *) malloc (len + 1);
	if ( dest == NULL )
	{
		return NULL;
	}
# ifdef HAVE_STRING_H
	strncpy (dest, src, len);
# else
	LHIP_MEMCOPY (dest, src, len);
# endif
	dest[len] = '\0';
	return dest;
}
#endif /* ! HAVE_STRDUP */

/* =============================================================== */

#ifndef HAVE_MEMCPY
void __lhip_memcopy (
# ifdef LHIP_ANSIC
	void * const dest, const void * const src, const size_t len)
# else
	dest, src, len)
	void * const dest;
	const void * const src;
	const size_t len;
# endif
{
	size_t i;
	char * const d = (char *)dest;
	const char * const s = (const char *)src;

	for ( i = 0; i < len; i++ )
	{
		d[i] = s[i];
	}
}
#endif

/* =============================================================== */

#ifndef HAVE_MEMSET
void __lhip_mem_set (
# ifdef LHIP_ANSIC
	void * const dest, const char value, const size_t len)
# else
	dest, value, len)
	void * const dest;
	const char value;
	const size_t len;
# endif
{
	size_t i;
	for ( i = 0; i < len; i++ )
	{
		((char *)dest)[i] = value;
	}
}
#endif

/* =============================================================== */

#ifndef LHIP_ANSIC
static void * __lhip_resolve_func LHIP_PARAMS ((void * const lib_handle,
	const char func_name1[], const char func_name2[]));
#endif

static void * __lhip_resolve_func (
#ifdef LHIP_ANSIC
	void * const lib_handle, const char func_name1[], const char func_name2[])
#else
	lib_handle, func_name1, func_name2)
	void * const lib_handle;
	const char func_name1[];
	const char func_name2[];
#endif
{
	void * ret = NULL;
	ret = dlsym (RTLD_NEXT, func_name1);
	if ( ret == NULL )
	{
		ret = dlsym (RTLD_NEXT, func_name2);
	}
	if ( (ret == NULL) && (lib_handle != NULL) )
	{
		ret = dlsym (lib_handle, func_name1);
		if ( ret == NULL )
		{
			ret = dlsym (lib_handle, func_name2);
		}
	}
	return ret;
}

/* =============================================================== */

int LHIP_ATTR ((constructor))
__lhip_main (LHIP_VOID)
{
	if ( __lhip_is_initialized == LHIP_INIT_STAGE_NOT_INITIALIZED )
	{
		/* Get pointers to the original functions: */

		*(void **) (&__lhip_real_gethostbyaddr)    = dlsym (RTLD_NEXT, "gethostbyaddr");
		*(void **) (&__lhip_real_gethostbyaddr_r)  = dlsym (RTLD_NEXT, "gethostbyaddr_r");
		*(void **) (&__lhip_real_gethostbyname)    = dlsym (RTLD_NEXT, "gethostbyname");
		*(void **) (&__lhip_real_gethostbyname_r)  = dlsym (RTLD_NEXT, "gethostbyname_r");
		*(void **) (&__lhip_real_gethostbyname2)   = dlsym (RTLD_NEXT, "gethostbyname2");
		*(void **) (&__lhip_real_gethostbyname2_r) = dlsym (RTLD_NEXT, "gethostbyname2_r");
		*(void **) (&__lhip_real_gethostent)       = dlsym (RTLD_NEXT, "gethostent");
		*(void **) (&__lhip_real_gethostent_r)     = dlsym (RTLD_NEXT, "gethostent_r");
		*(void **) (&__lhip_real_getipnodebyaddr)  = dlsym (RTLD_NEXT, "getipnodebyaddr");
		*(void **) (&__lhip_real_getipnodebyname)  = dlsym (RTLD_NEXT, "getipnodebyname");
		*(void **) (&__lhip_real_getifaddrs)       = dlsym (RTLD_NEXT, "getifaddrs");
		*(void **) (&__lhip_real_getnameinfo)      = dlsym (RTLD_NEXT, "getnameinfo");
		*(void **) (&__lhip_real_getaddrinfo)      = dlsym (RTLD_NEXT, "getaddrinfo");
		*(void **) (&__lhip_real_execve)           = dlsym (RTLD_NEXT, "execve");
		*(void **) (&__lhip_real_fexecve)          = dlsym (RTLD_NEXT, "fexecve");
		*(void **) (&__lhip_real_execveat)         = dlsym (RTLD_NEXT, "execveat");
		*(void **) (&__lhip_real_system)           = dlsym (RTLD_NEXT, "system");
		*(void **) (&__lhip_real_ioctl)            = dlsym (RTLD_NEXT, "ioctl");
		*(void **) (&__lhip_real_socket)           = dlsym (RTLD_NEXT, "socket");
		*(void **) (&__lhip_real_recvmsg)          = dlsym (RTLD_NEXT, "recvmsg");
		*(void **) (&__lhip_real_sendmsg)          = dlsym (RTLD_NEXT, "sendmsg");
		*(void **) (&__lhip_real_gethostname)      = dlsym (RTLD_NEXT, "gethostname");
		*(void **) (&__lhip_real_uname)            = dlsym (RTLD_NEXT, "uname");
		*(void **) (&__lhip_real_getsockopt)       = dlsym (RTLD_NEXT, "getsockopt");
		*(void **) (&__lhip_real_setsockopt)       = dlsym (RTLD_NEXT, "setsockopt");
		*(void **) (&__lhip_real_getsockname)      = dlsym (RTLD_NEXT, "getsockname");
		*(void **) (&__lhip_real_bind)             = dlsym (RTLD_NEXT, "bind");
		*(void **) (&__lhip_real_socketpair)       = dlsym (RTLD_NEXT, "socketpair");
		/* file-related functions: */
#ifdef LHIP_CANT_USE_VERSIONED_FOPEN
		*(void **) (&__lhip_real_fopen64)          = dlsym  (RTLD_NEXT, "fopen64");
#else
		*(void **) (&__lhip_real_fopen64)          = dlvsym (RTLD_NEXT, "fopen64", "GLIBC_2.1");
		if ( __lhip_real_fopen64 == NULL )
		{
			*(void **) (&__lhip_real_fopen64)  = dlsym (RTLD_NEXT, "fopen64");
		}
#endif
		*(void **) (&__lhip_real_freopen64)        = dlsym  (RTLD_NEXT, "freopen64");
		*(void **) (&__lhip_real_open64)           = dlsym  (RTLD_NEXT, "open64");
		*(void **) (&__lhip_real_openat64)         = dlsym  (RTLD_NEXT, "openat64");

#ifdef LHIP_CANT_USE_VERSIONED_FOPEN
		*(void **) (&__lhip_real_fopen)            = dlsym  (RTLD_NEXT, "fopen");
#else
		*(void **) (&__lhip_real_fopen)            = dlvsym (RTLD_NEXT, "fopen", "GLIBC_2.1");
		if ( __lhip_real_fopen == NULL )
		{
			*(void **) (&__lhip_real_fopen)    = dlsym  (RTLD_NEXT, "fopen");
		}
#endif
		*(void **) (&__lhip_real_freopen)          = dlsym  (RTLD_NEXT, "freopen");
		*(void **) (&__lhip_real_open)             = dlsym  (RTLD_NEXT, "open");
		*(void **) (&__lhip_real_openat)           = dlsym  (RTLD_NEXT, "openat");

		/* name resolving functions: */
		__lhip_handle_resolv = dlopen("libresolv.so", RTLD_NOW);
		/* CAUTION: some glibc version actually define the name resolver
		 * as macros, so a standard symbol search will always fail.
		 */
#define LHIP_RES_FUNC(x) #x /* doesn't substitute the parameter, so level 2 needed */
#define LHIP_RES_FUNC2(x) LHIP_RES_FUNC(x) /* substitute the real function's symbol and pass it to LHIP_RES_FUNC() */

		*(void **) (&__lhip_real_res_query)        = __lhip_resolve_func (
						__lhip_handle_resolv, "res_query", LHIP_RES_FUNC2(res_query));
		*(void **) (&__lhip_real_res_nquery)       = __lhip_resolve_func (
						__lhip_handle_resolv, "res_nquery", LHIP_RES_FUNC2(res_nquery));
		*(void **) (&__lhip_real_res_search)       = __lhip_resolve_func (
						__lhip_handle_resolv, "res_search", LHIP_RES_FUNC2(res_search));
		*(void **) (&__lhip_real_res_nsearch)      = __lhip_resolve_func (
						__lhip_handle_resolv, "res_nsearch", LHIP_RES_FUNC2(res_nsearch));
		*(void **) (&__lhip_real_res_querydomain)  = __lhip_resolve_func (
						__lhip_handle_resolv, "res_querydomain", LHIP_RES_FUNC2(res_querydomain));
		*(void **) (&__lhip_real_res_nquerydomain) = __lhip_resolve_func (
						__lhip_handle_resolv, "res_nquerydomain", LHIP_RES_FUNC2(res_nquerydomain));
		*(void **) (&__lhip_real_res_mkquery)      = __lhip_resolve_func (
						__lhip_handle_resolv, "res_mkquery", LHIP_RES_FUNC2(res_mkquery));
		*(void **) (&__lhip_real_res_nmkquery)     = __lhip_resolve_func (
						__lhip_handle_resolv, "res_nmkquery", LHIP_RES_FUNC2(res_nmkquery));

		/* libpcap functions: */
		*(void **) (&__lhip_real_pcap_lookupdev)        = dlsym  (RTLD_NEXT, "pcap_lookupdev");
		*(void **) (&__lhip_real_pcap_lookupnet)        = dlsym  (RTLD_NEXT, "pcap_lookupnet");
		*(void **) (&__lhip_real_pcap_create)           = dlsym  (RTLD_NEXT, "pcap_create");
		*(void **) (&__lhip_real_pcap_open_dead)        = dlsym  (RTLD_NEXT, "pcap_open_dead");
		*(void **) (&__lhip_real_pcap_open_dead_ts)     = dlsym  (RTLD_NEXT, "pcap_open_dead_with_tstamp_precision");
		*(void **) (&__lhip_real_pcap_open_live)        = dlsym  (RTLD_NEXT, "pcap_open_live");
		*(void **) (&__lhip_real_pcap_open_offline)     = dlsym  (RTLD_NEXT, "pcap_open_offline");
		*(void **) (&__lhip_real_pcap_open_offline_ts)  = dlsym  (RTLD_NEXT, "pcap_open_offline_with_tstamp_precision");
		*(void **) (&__lhip_real_pcap_fopen_offline)    = dlsym  (RTLD_NEXT, "pcap_fopen_offline");
		*(void **) (&__lhip_real_pcap_fopen_offline_ts) = dlsym  (RTLD_NEXT, "pcap_fopen_offline_with_tstamp_precision");
		*(void **) (&__lhip_real_pcap_hopen_offline)    = dlsym  (RTLD_NEXT, "pcap_hopen_offline");
		*(void **) (&__lhip_real_pcap_hopen_offline_ts) = dlsym  (RTLD_NEXT, "pcap_hopen_offline_with_tstamp_precision");
		*(void **) (&__lhip_real_pcap_findalldevs)      = dlsym  (RTLD_NEXT, "pcap_findalldevs");
		*(void **) (&__lhip_real_pcap_findalldevs_ex)   = dlsym  (RTLD_NEXT, "pcap_findalldevs_ex");

		*(void **) (&__lhip_real_getaddrinfo_a)         = dlsym  (RTLD_NEXT, "getaddrinfo_a");
		if ( __lhip_real_getaddrinfo_a == NULL )
		{
			__lhip_handle_anl = dlopen("libanl.so", RTLD_NOW);
#if (defined HAVE_GETADDRINFO_A) || (defined HAVE_LIBANL)
			*(void **) (&__lhip_real_getaddrinfo_a) = dlsym  (__lhip_handle_anl, "getaddrinfo_a");
#endif
		}

		__lhip_is_initialized = LHIP_INIT_STAGE_AFTER_DLSYM;

		__lhip_read_local_addresses ();

		__lhip_is_initialized = LHIP_INIT_STAGE_FULLY_INITIALIZED;

	}	/* is_initialized == 0 */
	return 0;
}

/* =============================================================== */

void LHIP_ATTR ((destructor))
__lhip_end (LHIP_VOID)
{
	if ( __lhip_handle_resolv != NULL )
	{
		dlclose (__lhip_handle_resolv);
		__lhip_handle_resolv = NULL;
	}
	if ( __lhip_handle_anl != NULL )
	{
		dlclose (__lhip_handle_anl);
		__lhip_handle_anl = NULL;
	}
	__lhip_free_local_addresses ();
	endhostent();
}

/* =============================================================== */

int __lhip_get_init_stage (LHIP_VOID)
{
	return __lhip_is_initialized;
}

/* =============================================================== */

shp_vp_sl_i __lhip_real_gethostbyaddr_location (LHIP_VOID)
{
	return __lhip_real_gethostbyaddr;
}

/* =============================================================== */

i_vp_sl_i_shp_cp_s_shpp_ip __lhip_real_gethostbyaddr_r_location (LHIP_VOID)
{
	return __lhip_real_gethostbyaddr_r;
}

/* =============================================================== */

shp_cp __lhip_real_gethostbyname_location (LHIP_VOID)
{
	return __lhip_real_gethostbyname;
}

/* =============================================================== */

i_cp_shp_cp_s_shpp_ip __lhip_real_gethostbyname_r_location (LHIP_VOID)
{
	return __lhip_real_gethostbyname_r;
}

/* =============================================================== */

shp_cp_i __lhip_real_gethostbyname2_location (LHIP_VOID)
{
	return __lhip_real_gethostbyname2;
}

/* =============================================================== */

i_cp_i_shp_cp_s_shpp_i __lhip_real_gethostbyname2_r_location (LHIP_VOID)
{
	return __lhip_real_gethostbyname2_r;
}

/* =============================================================== */

shp_v __lhip_real_gethostent_location (LHIP_VOID)
{
	return __lhip_real_gethostent;
}

/* =============================================================== */

i_shp_cp_s_shpp_ip __lhip_real_gethostent_r_location (LHIP_VOID)
{
	return __lhip_real_gethostent_r;
}

/* =============================================================== */

shp_cp_s_i_ip __lhip_real_getipnodebyaddr_location (LHIP_VOID)
{
	return __lhip_real_getipnodebyaddr;
}

/* =============================================================== */

shp_cp_i_i_ip __lhip_real_getipnodebyname_location (LHIP_VOID)
{
	return __lhip_real_getipnodebyname;
}

/* =============================================================== */

i_sipp __lhip_real_getifaddrs_location (LHIP_VOID)
{
	return __lhip_real_getifaddrs;
}

/* =============================================================== */

i_ssp_sl_cp_s_cp_s_i __lhip_real_getnameinfo_location (LHIP_VOID)
{
	return __lhip_real_getnameinfo;
}

/* =============================================================== */

i_cp_cp_sap_sapp __lhip_real_getaddrinfo_location (LHIP_VOID)
{
	return __lhip_real_getaddrinfo;
}

/* =============================================================== */

i_cp_cpp_cpp __lhip_real_execve_location (LHIP_VOID)
{
	return __lhip_real_execve;
}

/* =============================================================== */

i_i_cpp_cpp __lhip_real_fexecve_location (LHIP_VOID)
{
	return __lhip_real_fexecve;
}

/* =============================================================== */

i_i_cp_cpp_cpp_i __lhip_real_execveat_location (LHIP_VOID)
{
	return __lhip_real_execveat;
}

/* =============================================================== */

i_cp __lhip_real_system_location (LHIP_VOID)
{
	return __lhip_real_system;
}

/* =============================================================== */

i_i_i_va __lhip_real_ioctl_location (LHIP_VOID)
{
	return __lhip_real_ioctl;
}

/* =============================================================== */

i_i_i_i __lhip_real_socket_location (LHIP_VOID)
{
	return __lhip_real_socket;
}

/* =============================================================== */

ss_i_smp_i __lhip_real_recvmsg_location (LHIP_VOID)
{
	return __lhip_real_recvmsg;
}

/* =============================================================== */

ss_i_csmp_i __lhip_real_sendmsg_location (LHIP_VOID)
{
	return __lhip_real_sendmsg;
}

/* =============================================================== */

i_cp_s __lhip_real_gethostname_location (LHIP_VOID)
{
	return __lhip_real_gethostname;
}

/* =============================================================== */

i_sup __lhip_real_uname_location (LHIP_VOID)
{
	return __lhip_real_uname;
}

/* =============================================================== */

fp_cp_cp __lhip_real_fopen64_location (LHIP_VOID)
{
	return __lhip_real_fopen64;
}

/* =============================================================== */

fp_cp_cp_fp __lhip_real_freopen64_location (LHIP_VOID)
{
	return __lhip_real_freopen64;
}

/* =============================================================== */

i_cp_i_ __lhip_real_open64_location (LHIP_VOID)
{
	return __lhip_real_open64;
}

/* =============================================================== */

i_i_cp_i_ __lhip_real_openat64_location (LHIP_VOID)
{
	return __lhip_real_openat64;
}

/* =============================================================== */

fp_cp_cp __lhip_real_fopen_location (LHIP_VOID)
{
	return __lhip_real_fopen;
}

/* =============================================================== */

fp_cp_cp_fp __lhip_real_freopen_location (LHIP_VOID)
{
	return __lhip_real_freopen;
}

/* =============================================================== */

i_cp_i_ __lhip_real_open_location (LHIP_VOID)
{
	return __lhip_real_open;
}

/* =============================================================== */

i_i_cp_i_ __lhip_real_openat_location (LHIP_VOID)
{
	return __lhip_real_openat;
}

/* =============================================================== */

i_i_i_vp_slp __lhip_real_getsockopt_location (LHIP_VOID)
{
	return __lhip_real_getsockopt;
}

/* =============================================================== */

i_i_i_cvp_sl __lhip_real_setsockopt_location (LHIP_VOID)
{
	return __lhip_real_setsockopt;
}

/* =============================================================== */

i_ssp_slp __lhip_real_getsockname_location (LHIP_VOID)
{
	return __lhip_real_getsockname;
}

/* =============================================================== */

i_cssp_sl __lhip_real_bind_location (LHIP_VOID)
{
	return __lhip_real_bind;
}

/* =============================================================== */

i_i_ia2 __lhip_real_socketpair_location (LHIP_VOID)
{
	return __lhip_real_socketpair;
}

/* =============================================================== */

ccp_i_ucp_i __lhip_real_res_query_location (LHIP_VOID)
{
	return __lhip_real_res_query;
}

/* =============================================================== */

r_ccp_i_ucp_i __lhip_real_res_nquery_location (LHIP_VOID)
{
	return __lhip_real_res_nquery;
}

/* =============================================================== */

ccp_i_ucp_i __lhip_real_res_search_location (LHIP_VOID)
{
	return __lhip_real_res_search;
}

/* =============================================================== */

r_ccp_i_ucp_i __lhip_real_res_nsearch_location (LHIP_VOID)
{
	return __lhip_real_res_nsearch;
}

/* =============================================================== */

ccp_cpp_i_ucp_i __lhip_real_res_querydomain_location (LHIP_VOID)
{
	return __lhip_real_res_querydomain;
}

/* =============================================================== */

r_ccp_cpp_i_ucp_i __lhip_real_res_nquerydomain_location (LHIP_VOID)
{
	return __lhip_real_res_nquerydomain;
}

/* =============================================================== */

i_ccp_i_i_cucp_i_cucp_ucp_i __lhip_real_res_mkquery_location (LHIP_VOID)
{
	return __lhip_real_res_mkquery;
}

/* =============================================================== */

r_i_ccp_i_i_cucp_i_cucp_ucp_i __lhip_real_res_nmkquery_location (LHIP_VOID)
{
	return __lhip_real_res_nmkquery;
}

/* =============================================================== */

cp_cp __lhip_real_pcap_lookupdev_location (LHIP_VOID)
{
	return __lhip_real_pcap_lookupdev;
}

/* =============================================================== */

i_ccp_uip_uip_cp __lhip_real_pcap_lookupnet_location (LHIP_VOID)
{
	return __lhip_real_pcap_lookupnet;
}

/* =============================================================== */

pp_ccp_cp __lhip_real_pcap_create_location (LHIP_VOID)
{
	return __lhip_real_pcap_create;
}

/* =============================================================== */

pp_i_i __lhip_real_pcap_open_dead_location (LHIP_VOID)
{
	return __lhip_real_pcap_open_dead;
}

/* =============================================================== */

pp_i_i_ui __lhip_real_pcap_o_d_tstamp_location (LHIP_VOID)
{
	return __lhip_real_pcap_open_dead_ts;
}

/* =============================================================== */

pp_ccp_i_i_i_cp __lhip_real_pcap_open_live_location (LHIP_VOID)
{
	return __lhip_real_pcap_open_live;
}

/* =============================================================== */

pp_ccp_cp __lhip_real_pcap_open_offline_location (LHIP_VOID)
{
	return __lhip_real_pcap_open_offline;
}

/* =============================================================== */

pp_ccp_ui_cp __lhip_real_pcap_open_offline_ts_location (LHIP_VOID)
{
	return __lhip_real_pcap_open_offline_ts;
}

/* =============================================================== */

pp_Fp_cp __lhip_real_pcap_fopen_offline_location (LHIP_VOID)
{
	return __lhip_real_pcap_fopen_offline;
}

/* =============================================================== */

pp_Fp_ui_cp __lhip_real_pcap_fopen_offline_ts_location (LHIP_VOID)
{
	return __lhip_real_pcap_fopen_offline_ts;
}

/* =============================================================== */

pp_ipt_cp __lhip_real_pcap_hopen_offline_location (LHIP_VOID)
{
	return __lhip_real_pcap_hopen_offline;
}

/* =============================================================== */

pp_ipt_ui_cp __lhip_real_pcap_hopen_offline_ts_location (LHIP_VOID)
{
	return __lhip_real_pcap_hopen_offline_ts;
}

/* =============================================================== */

i_ifpp_cp __lhip_real_pcap_findalldevs_location (LHIP_VOID)
{
	return __lhip_real_pcap_findalldevs;
}

/* =============================================================== */

i_cp_rmtp_ifpp_cp __lhip_real_pcap_findalldevs_ex_location (LHIP_VOID)
{
	return __lhip_real_pcap_findalldevs_ex;
}

/* =============================================================== */

#if (defined HAVE_GETADDRINFO_A) || (defined HAVE_LIBANL)
i_i_sgpp_i_ssp __lhip_real_getaddrinfo_a_location (LHIP_VOID)
{
	return __lhip_real_getaddrinfo_a;
}
#endif
