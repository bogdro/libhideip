if LHIP_TESTS_ENABLED

TESTS = lhiptest_banning lhiptest_exec lhiptest_ioctl lhiptest_net lhiptest_opens lhiptest_pcap lhiptest_resolve lhiptest_uname
check_PROGRAMS = lhiptest_banning lhiptest_exec lhiptest_ioctl lhiptest_net lhiptest_opens lhiptest_pcap lhiptest_resolve lhiptest_uname

#nobase_nodist_include_HEADERS = lhiptest_common.h
#nobase_include_HEADERS = lhiptest_common.h
#nodist_include_HEADERS = lhiptest_common.h
EXTRA_DIST = lhiptest_common.h

lhiptest_banning_SOURCES = lhiptest_banning.c lhiptest_common.h
lhiptest_banning_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_banning_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

lhiptest_exec_SOURCES = lhiptest_exec.c lhiptest_common.h
lhiptest_exec_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_exec_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

lhiptest_ioctl_SOURCES = lhiptest_ioctl.c lhiptest_common.h
lhiptest_ioctl_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_ioctl_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

lhiptest_net_SOURCES = lhiptest_net.c lhiptest_common.h
lhiptest_net_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_net_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

lhiptest_opens_SOURCES = lhiptest_opens.c lhiptest_common.h
lhiptest_opens_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_opens_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

lhiptest_pcap_SOURCES = lhiptest_pcap.c lhiptest_common.h
lhiptest_pcap_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_pcap_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

lhiptest_resolve_SOURCES = lhiptest_resolve.c lhiptest_common.h
lhiptest_resolve_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_resolve_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

lhiptest_uname_SOURCES = lhiptest_uname.c lhiptest_common.h
lhiptest_uname_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_uname_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

endif
