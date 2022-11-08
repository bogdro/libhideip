#
# LibHideIP - A library for hiding local IP address.
#	-- Makefile.am, part of the build system.
#
# Copyright (C) 2007-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

SUBDIRS = src doc test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libhideip.spec.in doc/libhideip.3 m4/ax_c_check_flag.m4 \
	m4/ax_gcc_warn_unused_result.m4 m4/ax_prototype.m4 \
	m4/ac_define_path_style.m4 m4/ax_check_link_flag.m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libhideip.pc

x-pack:	doc/libhideip.info dist-gzip
	tar zxf libhideip-@VERSION@.tar.gz
	echo '\input texinfo'			 > libhideip-@VERSION@/doc/libhideip.texi
	echo '@setfilename libhideip.info'	>> libhideip-@VERSION@/doc/libhideip.texi
	echo '@settitle libhideip manual'	>> libhideip-@VERSION@/doc/libhideip.texi
	echo '@bye'				>> libhideip-@VERSION@/doc/libhideip.texi
	tar zcf libhideip-@VERSION@.tar.gz libhideip-@VERSION@
	rm -fr libhideip-@VERSION@

.PHONY: x-pack
