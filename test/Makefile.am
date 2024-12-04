#
# LibHideIP - A library for hiding local IP address.
#	-- Makefile.am, part of the build system.
#
# Copyright (C) 2008-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
# License: GNU General Public License, v3+
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

if LHIP_TESTS_ENABLED

TESTS = lhiptest_banning lhiptest_exec lhiptest_ioctl lhiptest_net \
	lhiptest_opens lhiptest_pcap lhiptest_resolve lhiptest_uname \
	lhiptest_other
check_PROGRAMS = lhiptest_banning lhiptest_exec lhiptest_ioctl lhiptest_net \
	lhiptest_opens lhiptest_pcap lhiptest_resolve lhiptest_uname \
	lhiptest_other

#nobase_nodist_include_HEADERS = lhiptest_common.h
#nobase_include_HEADERS = lhiptest_common.h
#nodist_include_HEADERS = lhiptest_common.h
EXTRA_DIST = lhiptest_common.h
LHIPTEST_COMMON_SRC = lhiptest_common.c lhiptest_common.h
LHIPTEST_COMMON_CFLAGS = @CHECK_CFLAGS@ -DHAVE_CONFIG_H -I $(top_builddir)/src
LHIPTEST_COMMON_LIB = $(top_builddir)/src/lhip_main.o \
	$(top_builddir)/src/lhip_addr.o \
	$(top_builddir)/src/lhip_banning.o \
	@CHECK_LIBS@ @LIBS@

lhiptest_banning_SOURCES = lhiptest_banning.c $(LHIPTEST_COMMON_SRC)
lhiptest_banning_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_banning_LDADD = $(LHIPTEST_COMMON_LIB)

lhiptest_exec_SOURCES = lhiptest_exec.c $(LHIPTEST_COMMON_SRC)
lhiptest_exec_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_exec_LDADD = $(LHIPTEST_COMMON_LIB) \
	$(top_builddir)/src/lhip_exec.o

lhiptest_ioctl_SOURCES = lhiptest_ioctl.c $(LHIPTEST_COMMON_SRC)
lhiptest_ioctl_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_ioctl_LDADD = $(LHIPTEST_COMMON_LIB) \
	$(top_builddir)/src/lhip_ioctl.o

lhiptest_net_SOURCES = lhiptest_net.c $(LHIPTEST_COMMON_SRC)
lhiptest_net_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_net_LDADD = $(LHIPTEST_COMMON_LIB) \
	$(top_builddir)/src/lhip_net.o

lhiptest_opens_SOURCES = lhiptest_opens.c $(LHIPTEST_COMMON_SRC)
lhiptest_opens_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_opens_LDADD = $(LHIPTEST_COMMON_LIB) \
	$(top_builddir)/src/lhip_opens.o \
	$(top_builddir)/src/lhip_exec.o

lhiptest_pcap_SOURCES = lhiptest_pcap.c $(LHIPTEST_COMMON_SRC)
lhiptest_pcap_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_pcap_LDADD = $(LHIPTEST_COMMON_LIB) \
	$(top_builddir)/src/lhip_pcap.o

lhiptest_resolve_SOURCES = lhiptest_resolve.c $(LHIPTEST_COMMON_SRC)
lhiptest_resolve_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_resolve_LDADD = $(LHIPTEST_COMMON_LIB) \
	$(top_builddir)/src/lhip_resolve.o

lhiptest_uname_SOURCES = lhiptest_uname.c $(LHIPTEST_COMMON_SRC)
lhiptest_uname_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_uname_LDADD = $(LHIPTEST_COMMON_LIB) \
	$(top_builddir)/src/lhip_uname.o

lhiptest_other_SOURCES = lhiptest_other.c $(LHIPTEST_COMMON_SRC)
lhiptest_other_CFLAGS = $(LHIPTEST_COMMON_CFLAGS)
lhiptest_other_LDADD = $(LHIPTEST_COMMON_LIB)

x-compile: $(TESTS)
.PHONY: x-compile

endif
