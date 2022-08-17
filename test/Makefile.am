if LHIP_TESTS_ENABLED

TESTS = lhiptest
check_PROGRAMS = lhiptest
lhiptest_SOURCES = lhiptest.c
lhiptest_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lhiptest_LDADD = $(top_builddir)/src/libhideip.la @CHECK_LIBS@ @LIBS@

endif
