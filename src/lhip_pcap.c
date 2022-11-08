/*
 * LibHideIP - A library for hiding local IP address.
 *	-- libpcap functions' replacements.
 *
 * Copyright (C) 2011-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#include "lhip_priv.h"

#include <stddef.h> /* NULL */
#include <stdio.h> /* FILE */

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>	/* intptr_t */
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>	/* intptr_t */
#endif

#ifdef HAVE_PCAP_H
# include <pcap.h>
#else
# ifdef HAVE_PCAP_PCAP_H
#  include <pcap/pcap.h>
# else
/* already included in lhip_priv.h: */
/*
typedef void pcap_t;
typedef void pcap_if_t;
typedef unsigned int bpf_u_int32;
typedef unsigned int intptr_t;
*/
#  ifdef __cplusplus
extern "C" {
#  endif

extern char * pcap_lookupdev LHIP_PARAMS ((char *errbuf));
extern int pcap_lookupnet LHIP_PARAMS ((const char * device, bpf_u_int32 * netp,
	bpf_u_int32 * maskp, char * errbuf));
extern pcap_t * pcap_create LHIP_PARAMS ((const char * source, char * errbuf));
extern pcap_t * pcap_open_dead LHIP_PARAMS ((int linktype, int snaplen));
extern pcap_t * pcap_open_dead_with_tstamp_precision LHIP_PARAMS ((int, int, u_int));
extern pcap_t * pcap_open_live LHIP_PARAMS ((const char * device, int snaplen,
	int promisc, int to_ms, char * errbuf));
extern pcap_t * pcap_open_offline LHIP_PARAMS ((const char * fname, char * errbuf));
extern pcap_t * pcap_open_offline_with_tstamp_precision LHIP_PARAMS ((const char *, u_int, char *));
extern pcap_t * pcap_fopen_offline LHIP_PARAMS ((FILE * fp, char * errbuf));
extern pcap_t * pcap_fopen_offline_with_tstamp_precision LHIP_PARAMS ((FILE *, u_int, char *));
extern int pcap_findalldevs LHIP_PARAMS ((pcap_if_t ** devs, char * errbuf));
#  ifdef HAVE_PCAP_FINDALLDEVS_EX
extern int pcap_findalldevs_ex LHIP_PARAMS ((PCAP_FINDALLDEVS_EX_ARG1TYPE source,
	struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf));
#  endif /* HAVE_PCAP_FINDALLDEVS_EX */

#  ifdef __cplusplus
}
#  endif

# endif
#endif

#if (!defined _WIN32) && (!defined WIN32)
# ifdef __cplusplus
extern "C" {
# endif

extern pcap_t * pcap_hopen_offline LHIP_PARAMS ((intptr_t a, char * errbuf));
extern pcap_t * pcap_hopen_offline_with_tstamp_precision LHIP_PARAMS ((intptr_t, u_int, char *));

# ifdef __cplusplus
}
# endif

#endif

#ifdef TEST_COMPILE
# undef LHIP_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

/* =============================================================== */

char *
pcap_lookupdev (
#ifdef LHIP_ANSIC
	char * errbuf)
#else
	errbuf)
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_lookupdev()\n");
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_lookupdev_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_lookupdev_location ()) (errbuf);
	}

	return NULL;
}

/* =============================================================== */

int
pcap_lookupnet (
#ifdef LHIP_ANSIC
	const char * device, bpf_u_int32 * netp,
	bpf_u_int32 * maskp, char * errbuf)
#else
	device, netp, maskp, errbuf)
	const char * device;
	bpf_u_int32 * netp;
	bpf_u_int32 * maskp;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_lookupnet(%s)\n", (device == NULL)? "null" : device);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_lookupnet_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_lookupnet_location ()) (device, netp, maskp, errbuf);
	}

	return -1;
}

/* =============================================================== */

pcap_t *
pcap_create (
#ifdef LHIP_ANSIC
	const char * source, char * errbuf)
#else
	source, errbuf)
	const char * source;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_create(%s)\n", (source == NULL)? "null" : source);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_create_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_create_location ()) (source, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_open_dead (
#ifdef LHIP_ANSIC
	int linktype, int snaplen)
#else
	linktype, snaplen)
	int linktype;
	int snaplen;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_open_dead(%d, %d)\n", linktype, snaplen);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_open_dead_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_open_dead_location ()) (linktype, snaplen);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_open_dead_with_tstamp_precision (
#ifdef LHIP_ANSIC
	int linktype, int snaplen, u_int t)
#else
	linktype, snaplen, t)
	int linktype;
	int snaplen;
	u_int t;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_open_dead_with_tstamp_precision(%d, %d, %d)\n",
		linktype, snaplen, t);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_o_d_tstamp_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_o_d_tstamp_location ()) (linktype, snaplen ,t);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_open_live (
#ifdef LHIP_ANSIC
	const char * device, int snaplen,
	int promisc, int to_ms, char * errbuf)
#else
	device, snaplen, promisc, to_ms, errbuf)
	const char * device;
	int snaplen;
	int promisc;
	int to_ms;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_open_live(%s)\n", (device == NULL)? "null" : device);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_open_live_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_open_live_location ()) (device, snaplen, promisc, to_ms, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_open_offline (
#ifdef LHIP_ANSIC
	const char * fname, char * errbuf)
#else
	fname, errbuf)
	const char * fname;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_open_offline(%s)\n", (fname == NULL)? "null" : fname);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_open_offline_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_open_offline_location ()) (fname, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_open_offline_with_tstamp_precision (
#ifdef LHIP_ANSIC
	const char * fname, u_int t, char * errbuf)
#else
	fname, t, errbuf)
	const char * fname;
	u_int t;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_open_offline_with_tstamp_precision(%s, %d)\n",
		(fname == NULL)? "null" : fname, t);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_open_offline_ts_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_open_offline_ts_location ()) (fname, t, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_fopen_offline (
#ifdef LHIP_ANSIC
	FILE * fp, char * errbuf)
#else
	fp, errbuf)
	FILE * fp;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_fopen_offline(0x%lx)\n", (unsigned long int)fp);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_fopen_offline_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_fopen_offline_location ()) (fp, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_fopen_offline_with_tstamp_precision (
#ifdef LHIP_ANSIC
	FILE * fp, u_int t, char * errbuf)
#else
	fp, t, errbuf)
	FILE * fp;
	u_int t;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_fopen_offline_with_tstamp_precision(0x%lx, %d)\n",
		(unsigned long int)fp, t);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_fopen_offline_ts_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_fopen_offline_ts_location ()) (fp, t, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_hopen_offline (
#ifdef LHIP_ANSIC
	intptr_t a, char * errbuf)
#else
	a, errbuf)
	intptr_t a;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_hopen_offline(0x%lx)\n", (unsigned long int)a);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_hopen_offline_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_hopen_offline_location ()) (a, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_hopen_offline_with_tstamp_precision (
#ifdef LHIP_ANSIC
	intptr_t a, u_int t, char * errbuf)
#else
	a, t, errbuf)
	intptr_t a;
	u_int t;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_hopen_offline_with_tstamp_precision(0x%lx, %d)\n",
		(unsigned long int)a, t);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_hopen_offline_ts_location () == NULL )
	{
		return NULL;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_hopen_offline_ts_location ()) (a, t, errbuf);
	}

	return NULL;
}

/* =============================================================== */

int
pcap_findalldevs (
#ifdef LHIP_ANSIC
	pcap_if_t ** devs, char * errbuf)
#else
	devs, errbuf)
	pcap_if_t ** devs;
	char * errbuf;
#endif
{
	__lhip_main ();

#ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_findalldevs(0x%lx)\n", (unsigned long int)devs);
	fflush (stderr);
#endif

	if ( __lhip_real_pcap_findalldevs_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_findalldevs_location ()) (devs, errbuf);
	}

	return -1;
}

/* =============================================================== */

#ifdef HAVE_PCAP_FINDALLDEVS_EX
int
pcap_findalldevs_ex (
# ifdef LHIP_ANSIC
	PCAP_FINDALLDEVS_EX_ARG1TYPE source, struct pcap_rmtauth *auth,
		pcap_if_t **alldevs, char *errbuf)
# else
	source, auth, alldevs, errbuf)
	PCAP_FINDALLDEVS_EX_ARG1TYPE source;
	struct pcap_rmtauth *auth;
	pcap_if_t **alldevs;
	char *errbuf;
# endif
{
	__lhip_main ();

# ifdef LHIP_DEBUG
	fprintf (stderr, "libhideip: pcap_findalldevs_ex(0x%x, 0x%x, 0x%x, 0x%x)\n",
		(unsigned int)devs, (unsigned int)auth, (unsigned int)alldevs,
		(unsigned int)errbuf);
	fflush (stderr);
# endif

	if ( __lhip_real_pcap_findalldevs_ex_location () == NULL )
	{
		return -1;
	}

	if ( (__lhip_check_prog_ban () != 0)
		|| (__lhip_get_init_stage() != LHIP_INIT_STAGE_FULLY_INITIALIZED) )
	{
		return (*__lhip_real_pcap_findalldevs_ex_location ()) (source, auth, alldevs, errbuf);
	}

	return -1;
}
#endif /* HAVE_PCAP_FINDALLDEVS_EX */
