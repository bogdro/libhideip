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

lib_LTLIBRARIES = libhideip.la
libhideip_la_SOURCES = lhip_exec.c lhip_main.c lhip_net.c lhip_banning.c \
	lhip_ioctl.c lhip_opens.c lhip_uname.c lhip_resolve.c lhip_priv.h \
	lhip_pcap.c lhip_addr.c
EXTRA_DIST = lhip_cfg.h.in randomize_names_gawk.sh randomize_names_perl.sh \
	libhideip.h.in lhip_public.c.in banning-generic.c

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libhideip_la_LDFLAGS = -version-info 10:0:0
#libhideip_la_LIBADD = @LIBS@

#nobase_include_HEADERS = lhip_priv.h

nobase_nodist_include_HEADERS = libhideip.h
BUILT_SOURCES = lhip_paths.h libhideip.h
nodist_libhideip_la_SOURCES = lhip_paths.h libhideip.h
libhideip_la_DISTCLEANFILES = lhip_paths.h libhideip.h
lhip_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lhip_paths.h

if PUBLIC_INTERFACE
BUILT_SOURCES += lhip_public.c
nodist_libhideip_la_SOURCES += lhip_public.c
libhideip_la_DISTCLEANFILES += lhip_public.c
endif

x-randomnames: clean
	./randomize_names_gawk.sh

.PHONY: x-randomnames
