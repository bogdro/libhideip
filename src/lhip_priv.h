/*
 * A library for hiding local IP address.
 *	-- private header file.
 *
 * Copyright (C) 2008-2012 Bogdan Drozdowski, bogdandr (at) op.pl
 * Parts of this file are Copyright (C) Free Software Foundation, Inc.
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

#ifndef _LHIP_HEADER
# define _LHIP_HEADER 1

# include "lhip_cfg.h"

# undef LHIP_ATTR
# ifdef __GNUC__
#  define LHIP_ATTR(x)	__attribute__(x)
# else
#  define LHIP_ATTR(x)
# endif

# ifndef GCC_WARN_UNUSED_RESULT
/*
 if the compiler doesn't support this, define this to an empty string,
 so that everything compiles (just in case)
 */
#  define GCC_WARN_UNUSED_RESULT /*LHIP_ATTR((warn_unused_result))*/
# endif

# ifndef LHIP_MAX_HOSTNAMES
#  define LHIP_MAX_HOSTNAMES 100
# endif
# if LHIP_MAX_HOSTNAMES < 10
#  undef LHIP_MAX_HOSTNAMES
#  define LHIP_MAX_HOSTNAMES 100
# endif

/* PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# undef PARAMS
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
#  define PARAMS(protos) protos
#  define LHIP_ANSIC
# else
#  define PARAMS(protos) ()
#  undef LHIP_ANSIC
# endif

# ifdef __GNUC__
#  ifndef strcat
#   pragma GCC poison strcat
#  endif
#  ifndef strcpy
#   pragma GCC poison strcpy
#  endif
# endif

# include <stdio.h>		/* FILE */

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>	/* size_t */
# endif

# ifndef HAVE_SSIZE_T
typedef int ssize_t;
# endif

# ifdef HAVE_NETDB_H
#  include <netdb.h>
# else
struct hostent
{
	char  *h_name;            /* official name of host */
	char **h_aliases;         /* alias list */
	int    h_addrtype;        /* host address type */
	int    h_length;          /* length of address */
	char **h_addr_list;       /* list of addresses */
};

struct addrinfo
{
	int ai_flags;			/* Input flags.  */
	int ai_family;		/* Protocol family for socket.  */
	int ai_socktype;		/* Socket type.  */
	int ai_protocol;		/* Protocol for socket.  */
	socklen_t ai_addrlen;		/* Length of socket address.  */
	struct sockaddr *ai_addr;	/* Socket address for socket.  */
	char *ai_canonname;		/* Canonical name for service location.  */
	struct addrinfo *ai_next;	/* Pointer to next in list.  */
};
# endif

# ifdef HAVE_STDLIB_H
#  include <stdlib.h>		/* sys/socket.h */
# endif

# ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# else
#  ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#  endif
# endif

# ifdef HAVE_IFADDRS_H
#  include <ifaddrs.h>
# else
struct ifaddrs
{
	struct ifaddrs *ifa_next;	/* Pointer to the next structure.  */

	char *ifa_name;		/* Name of this network interface.  */
	unsigned int ifa_flags;	/* Flags as from SIOCGIFFLAGS ioctl.  */

	struct sockaddr *ifa_addr;	/* Network address of this interface.  */
	struct sockaddr *ifa_netmask; /* Netmask of this interface.  */
	union
	{
		/* At most one of the following two is valid.  If the IFF_BROADCAST
		   bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
		   IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
		   It is never the case that both these bits are set at once.  */
		struct sockaddr *ifu_broadaddr; /* Broadcast address of this interface. */
		struct sockaddr *ifu_dstaddr; /* Point-to-point destination address.  */
	} ifa_ifu;
	/* These very same macros are defined by <net/if.h> for `struct ifaddr'.
	   So if they are defined already, the existing definitions will be fine.  */
#  ifndef ifa_broadaddr
#   define ifa_broadaddr	ifa_ifu.ifu_broadaddr
#  endif
#  ifndef ifa_dstaddr
#   define ifa_dstaddr		ifa_ifu.ifu_dstaddr
#  endif

	void *ifa_data;		/* Address-specific data (may be unused).  */
};

#  if (defined __solaris__) && (defined AF_INET6)
struct lifaddrs
{
	struct ifaddrs *lifa_next;	/* Pointer to the next structure.  */

	char *lifa_name;		/* Name of this network interface.  */
	unsigned int lifa_flags;	/* Flags as from SIOCGIFFLAGS ioctl.  */

	struct sockaddr *lifa_addr;	/* Network address of this interface.  */
	struct sockaddr *lifa_netmask; /* Netmask of this interface.  */
	union
	{
		/* At most one of the following two is valid.  If the IFF_BROADCAST
		   bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
		   IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
		   It is never the case that both these bits are set at once.  */
		struct sockaddr *lifu_broadaddr; /* Broadcast address of this interface. */
		struct sockaddr *lifu_dstaddr; /* Point-to-point destination address.  */
	} lifa_ifu;
	/* These very same macros are defined by <net/if.h> for `struct ifaddr'.
	   So if they are defined already, the existing definitions will be fine.  */
#   ifndef lifa_broadaddr
#    define lifa_broadaddr	lifa_ifu.lifu_broadaddr
#   endif
#   ifndef lifa_dstaddr
#    define lifa_dstaddr	lifa_ifu.lifu_dstaddr
#   endif

	void *ifa_data;		/* Address-specific data (may be unused).  */
};
#  endif
# endif

# ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
# else
struct utsname
{
	char sysname[];
	char nodename[];
	char release[];
	char version[];
	char machine[];
};
# endif

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>	/* intptr_t */
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>	/* intptr_t */
#endif

# ifdef HAVE_PCAP_H
#  include <pcap.h>
# else
#  ifdef HAVE_PCAP_PCAP_H
#   include <pcap/pcap.h>
#  else
/* can't find neither pcap.h nor pcap/pcap.h - make up our own declarations: */
typedef void pcap_t;
typedef void pcap_if_t;
typedef unsigned int bpf_u_int32;
/*typedef unsigned int intptr_t;*/
#  endif
# endif

/* --- Function typedefs. */
/* network-related functions: */
typedef struct hostent * (*shp_vp_sl_i)		PARAMS ((const void * addr, socklen_t len, int type));
typedef int (*i_vp_sl_i_shp_cp_s_shpp_ip)	PARAMS ((const void *addr, socklen_t len, int type,
							struct hostent *ret, char *buf, size_t buflen,
							struct hostent **result, int *h_errnop));
typedef struct hostent * (*shp_cp)		PARAMS ((const char *name));
typedef int (*i_cp_shp_cp_s_shpp_ip)		PARAMS ((const char *name,
							struct hostent *ret, char *buf, size_t buflen,
							struct hostent **result, int *h_errnop));
typedef struct hostent * (*shp_cp_i)		PARAMS ((const char *name, int af));
typedef int (*i_cp_i_shp_cp_s_shpp_i)		PARAMS ((const char *name, int af,
							struct hostent *ret, char *buf, size_t buflen,
							struct hostent **result, int *h_errnop));
typedef struct hostent * (*shp_v)		PARAMS ((void));
typedef int (*i_shp_cp_s_shpp_ip)		PARAMS ((struct hostent *ret, char *buf, size_t buflen,
							struct hostent **result, int *h_errnop));
typedef struct hostent * (*shp_cp_s_i_ip)	PARAMS ((const void *addr,
							size_t len, int af, int *error_num));
typedef struct hostent * (*shp_cp_i_i_ip)	PARAMS ((const char *name,
							int af, int flags, int *error_num));
typedef int (*i_sipp)				PARAMS ((struct ifaddrs **__ifap));
typedef int (*i_ssp_sl_cp_s_cp_s_i)		PARAMS ((const struct sockaddr *sa, socklen_t salen,
							char *host, GETNAMEINFO_ARG4TYPE hostlen,
							char *serv, GETNAMEINFO_ARG6TYPE servlen,
							GETNAMEINFO_ARG7TYPE flags));
typedef int (*i_cp_cp_sap_sapp)			PARAMS ((const char *node, const char *service,
							const struct addrinfo *hints,
							struct addrinfo **res));
typedef int (*i_cp_cpp_cpp)			PARAMS ((const char *filename, char *const argv[],
							char *const envp[]));
typedef int (*i_cp)				PARAMS ((const char *command));
typedef int (*i_i_i_va)				PARAMS ((int d, unsigned long int request, ...));
typedef int (*i_i_i_i)				PARAMS ((int domain, int type, int protocol));
typedef ssize_t (*ss_i_smp_i)			PARAMS ((int s, struct msghdr *msg, int flags));
typedef ssize_t (*ss_i_csmp_i)			PARAMS ((int s, const struct msghdr *msg, int flags));
typedef int (*i_cp_s)				PARAMS ((char *name, size_t len));
typedef int (*i_sup)				PARAMS ((struct utsname *buf));
typedef int (*i_i_i_vp_slp)			PARAMS ((int s, int level, int optname,
							void * optval, socklen_t * optlen));
typedef int (*i_i_i_cvp_sl)			PARAMS ((int s, int level, int optname,
							const void * optval, socklen_t optlen));
typedef int (*i_ssp_slp)			PARAMS ((int s, struct sockaddr *name, socklen_t *namelen));
typedef int (*i_cssp_sl)			PARAMS ((int sockfd, const struct sockaddr *my_addr,
							socklen_t addrlen));
typedef int (*i_i_ia2)				PARAMS ((int d, int type, int protocol, int sv[2]));

/* file-related functions: */
typedef FILE*	(*fp_cp_cp)			PARAMS ((const char * const name, const char * const mode));
typedef FILE*	(*fp_cp_cp_fp)			PARAMS ((const char * const name, const char * const mode,
							FILE* stream));
typedef int	(*i_cp_i_)			PARAMS ((const char * const name, const int flags, ...));
typedef int	(*i_i_cp_i_)			PARAMS ((const int dir_fd, const char * const pathname,
							const int flags, ...));

/* name resolving functions: */
typedef int (*ccp_i_ucp_i)			PARAMS ((const char *dname, int class, int type,
							unsigned char *answer, int anslen));
typedef int (*ccp_cpp_i_ucp_i)			PARAMS ((const char *name, const char *domain, int class,
							int type, unsigned char *answer, int anslen));
typedef int (*i_ccp_i_i_cucp_i_cucp_ucp_i)	PARAMS ((int op, const char *dname, int class, int type,
							const unsigned char *data, int datalen,
							const unsigned char *newrr, unsigned char *buf,
							int buflen));
/* libpcap functions: */
typedef char * (*cp_cp)				PARAMS ((char *errbuf));
typedef int (*i_ccp_uip_uip_cp)			PARAMS ((const char * device, bpf_u_int32 * netp,
							bpf_u_int32 * maskp, char * errbuf));

typedef pcap_t * (*pp_ccp_cp)			PARAMS ((const char * source, char * errbuf));
typedef pcap_t * (*pp_i_i)			PARAMS ((int linktype, int snaplen));
typedef pcap_t * (*pp_ccp_i_i_i_cp)		PARAMS ((const char * device, int snaplen,
							int promisc, int to_ms, char * errbuf));
typedef pcap_t * (*pp_Fp_cp)			PARAMS ((FILE * fp, char * errbuf));
typedef pcap_t * (*pp_ipt_cp)			PARAMS ((intptr_t a, char * errbuf));
typedef int (*i_ifpp_cp)			PARAMS ((pcap_if_t ** devs, char * errbuf));

# ifdef __cplusplus
extern "C" {
# endif

/* network-related functions: */
extern GCC_WARN_UNUSED_RESULT shp_vp_sl_i			__lhip_real_gethostbyaddr_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_vp_sl_i_shp_cp_s_shpp_ip	__lhip_real_gethostbyaddr_r_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT shp_cp				__lhip_real_gethostbyname_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_shp_cp_s_shpp_ip		__lhip_real_gethostbyname_r_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT shp_cp_i				__lhip_real_gethostbyname2_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_i_shp_cp_s_shpp_i		__lhip_real_gethostbyname2_r_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT shp_v				__lhip_real_gethostent_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_shp_cp_s_shpp_ip		__lhip_real_gethostent_r_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT shp_cp_s_i_ip			__lhip_real_getipnodebyaddr_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT shp_cp_i_i_ip			__lhip_real_getipnodebyname_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_sipp				__lhip_real_getifaddrs_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_ssp_sl_cp_s_cp_s_i		__lhip_real_getnameinfo_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_cp_sap_sapp			__lhip_real_getaddrinfo_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_cpp_cpp			__lhip_real_execve_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp				__lhip_real_system_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_i_va				__lhip_real_ioctl_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_i_i				__lhip_real_socket_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT ss_i_smp_i			__lhip_real_recvmsg_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT ss_i_csmp_i			__lhip_real_sendmsg_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_s				__lhip_real_gethostname_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_sup				__lhip_real_uname_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_i_vp_slp			__lhip_real_getsockopt_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_i_cvp_sl			__lhip_real_setsockopt_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_ssp_slp				__lhip_real_getsockname_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cssp_sl				__lhip_real_bind_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_ia2				__lhip_real_socketpair_location PARAMS ((void));

/* file-related functions: */
extern GCC_WARN_UNUSED_RESULT fp_cp_cp				__lhip_real_fopen64_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT fp_cp_cp_fp			__lhip_real_freopen64_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_i_				__lhip_real_open64_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_cp_i_				__lhip_real_openat64_location PARAMS ((void));

extern GCC_WARN_UNUSED_RESULT fp_cp_cp				__lhip_real_fopen_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT fp_cp_cp_fp			__lhip_real_freopen_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_i_				__lhip_real_open_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_cp_i_				__lhip_real_openat_location PARAMS ((void));

/* name resolving functions: */
extern GCC_WARN_UNUSED_RESULT ccp_i_ucp_i			__lhip_real_res_query_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT ccp_i_ucp_i			__lhip_real_res_search_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT ccp_cpp_i_ucp_i			__lhip_real_res_querydomain_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_ccp_i_i_cucp_i_cucp_ucp_i	__lhip_real_res_mkquery_location PARAMS ((void));

/* libpcap functions: */
extern GCC_WARN_UNUSED_RESULT cp_cp				__lhip_real_pcap_lookupdev_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_ccp_uip_uip_cp			__lhip_real_pcap_lookupnet_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT pp_ccp_cp				__lhip_real_pcap_create_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT pp_i_i				__lhip_real_pcap_open_dead_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT pp_ccp_i_i_i_cp			__lhip_real_pcap_open_live_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT pp_ccp_cp				__lhip_real_pcap_open_offline_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT pp_Fp_cp				__lhip_real_pcap_fopen_offline_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT pp_ipt_cp				__lhip_real_pcap_hopen_offline_location PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_ifpp_cp				__lhip_real_pcap_findalldevs_location PARAMS ((void));

/* The library functions: */
extern int							__lhip_main PARAMS ((void));
extern int GCC_WARN_UNUSED_RESULT				__lhip_check_prog_ban PARAMS ((void));
extern int GCC_WARN_UNUSED_RESULT				__lhip_is_local_addr PARAMS ((
									const struct hostent * const h));
extern void							__lhip_change_data PARAMS ((
									struct hostent * const ret));
extern struct hostent * GCC_WARN_UNUSED_RESULT			__lhip_get_our_name_ipv4 PARAMS ((void));
extern struct hostent * GCC_WARN_UNUSED_RESULT			__lhip_get_our_name_ipv6 PARAMS ((void));
extern int GCC_WARN_UNUSED_RESULT				__lhip_get_init_stage PARAMS ((void));
extern void 							__lhip_read_local_addresses PARAMS ((void));
extern void							__lhip_free_local_addresses PARAMS ((void));
extern int GCC_WARN_UNUSED_RESULT				__lhip_is_forbidden_file
									PARAMS ((const char * const name));
extern void							__lhip_end PARAMS ((void));


# ifdef __cplusplus
}
# endif

# define LOCAL_IPV4_ADDR 127, 0, 0, 1
# define LOCAL_IPV4_MASK 255, 255, 255, 255
# define LOCAL_IPV6_ADDR 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
# define LOCAL_IPV6_MASK 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255

# if (PATH_STYLE==32) || (PATH_STYLE==128)	/* unix or mac */
#  define LHIP_PATH_SEP "/"
#  define LHIP_FILE_SEP ':'
# else
#  define LHIP_PATH_SEP "\\"
#  define LHIP_FILE_SEP ';'
# endif

# define LHIP_MAX(a, b) ( ((a) > (b)) ? (a) : (b) )
# define LHIP_MIN(a, b) ( ((a) < (b)) ? (a) : (b) )
# define LHIP_MAXPATHLEN 4097
# define LHIP_INIT_STAGE_NOT_INITIALIZED 0
# define LHIP_INIT_STAGE_AFTER_DLSYM 1
# define LHIP_INIT_STAGE_FULLY_INITIALIZED 2

#endif /* _LHIP_HEADER */

