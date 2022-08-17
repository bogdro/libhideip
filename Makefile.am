SUBDIRS = src doc test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libhideip.spec.in doc/libhideip.3 m4/ax_c_check_flag.m4 \
	m4/ax_gcc_warn_unused_result.m4 m4/ac_prototype.m4 \
	m4/ac_define_path_style.m4 m4/ax_check_link_flag.m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libhideip.pc

pack:	doc/libhideip.info
	make dist-gzip
	mkdir -p libhideip-@VERSION@/doc
	echo '\input texinfo'			 > libhideip-@VERSION@/doc/libhideip.texi
	echo '@setfilename libhideip.info'	>> libhideip-@VERSION@/doc/libhideip.texi
	echo '@settitle libhideip manual'	>> libhideip-@VERSION@/doc/libhideip.texi
	echo '@bye'				>> libhideip-@VERSION@/doc/libhideip.texi
	gunzip -f libhideip-@VERSION@.tar.gz
	tar --delete -f libhideip-@VERSION@.tar libhideip-@VERSION@/doc/libhideip.texi
	tar -rf libhideip-@VERSION@.tar libhideip-@VERSION@/doc/libhideip.texi
	gzip -9 -f libhideip-@VERSION@.tar
	rm -fr libhideip-@VERSION@

