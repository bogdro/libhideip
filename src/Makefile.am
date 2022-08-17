lib_LTLIBRARIES = libhideip.la
libhideip_la_SOURCES = lhip_exec.c lhip_main.c lhip_net.c lhip_banning.c \
	lhip_ioctl.c lhip_opens.c lhip_uname.c lhip_resolve.c lhip_priv.h \
	lhip_pcap.c lhip_addr.c
EXTRA_DIST = lhip_cfg.h.in randomize_names_gawk.sh randomize_names_perl.sh \
	libhideip.h.in lhip_public.c.in

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libhideip_la_LDFLAGS = -version-info 4:0:3

#nobase_include_HEADERS = lhip_priv.h

BUILT_SOURCES = lhip_paths.h
nodist_libhideip_la_SOURCES = lhip_paths.h
libhideip_la_DISTCLEANFILES = lhip_paths.h
lhip_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lhip_paths.h

if PUBLIC_INTERFACE
nobase_include_HEADERS = libhideip.h
nodist_libhideip_la_SOURCES += lhip_public.c libhideip.h
libhideip_la_DISTCLEANFILES += lhip_public.c libhideip.h
endif

