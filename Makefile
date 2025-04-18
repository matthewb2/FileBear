# Makefile.in generated by automake 1.16.5 from Makefile.am.
# Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994-2021 Free Software Foundation, Inc.

# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.




am__is_gnu_make = { \
  if test -z '$(MAKELEVEL)'; then \
    false; \
  elif test -n '$(MAKE_HOST)'; then \
    true; \
  elif test -n '$(MAKE_VERSION)' && test -n '$(CURDIR)'; then \
    true; \
  else \
    false; \
  fi; \
}
am__make_running_with_option = \
  case $${target_option-} in \
      ?) ;; \
      *) echo "am__make_running_with_option: internal error: invalid" \
              "target option '$${target_option-}' specified" >&2; \
         exit 1;; \
  esac; \
  has_opt=no; \
  sane_makeflags=$$MAKEFLAGS; \
  if $(am__is_gnu_make); then \
    sane_makeflags=$$MFLAGS; \
  else \
    case $$MAKEFLAGS in \
      *\\[\ \	]*) \
        bs=\\; \
        sane_makeflags=`printf '%s\n' "$$MAKEFLAGS" \
          | sed "s/$$bs$$bs[$$bs $$bs	]*//g"`;; \
    esac; \
  fi; \
  skip_next=no; \
  strip_trailopt () \
  { \
    flg=`printf '%s\n' "$$flg" | sed "s/$$1.*$$//"`; \
  }; \
  for flg in $$sane_makeflags; do \
    test $$skip_next = yes && { skip_next=no; continue; }; \
    case $$flg in \
      *=*|--*) continue;; \
        -*I) strip_trailopt 'I'; skip_next=yes;; \
      -*I?*) strip_trailopt 'I';; \
        -*O) strip_trailopt 'O'; skip_next=yes;; \
      -*O?*) strip_trailopt 'O';; \
        -*l) strip_trailopt 'l'; skip_next=yes;; \
      -*l?*) strip_trailopt 'l';; \
      -[dEDm]) skip_next=yes;; \
      -[JT]) skip_next=yes;; \
    esac; \
    case $$flg in \
      *$$target_option*) has_opt=yes; break;; \
    esac; \
  done; \
  test $$has_opt = yes
am__make_dryrun = (target_option=n; $(am__make_running_with_option))
am__make_keepgoing = (target_option=k; $(am__make_running_with_option))
pkgdatadir = $(datadir)/filezilla
pkgincludedir = $(includedir)/filezilla
pkglibdir = $(libdir)/filezilla
pkglibexecdir = $(libexecdir)/filezilla
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = x86_64-w64-mingw32
host_triplet = x86_64-w64-mingw32
subdir = .
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/m4/ax_append_flag.m4 \
	$(top_srcdir)/m4/ax_check_compile_flag.m4 \
	$(top_srcdir)/m4/ax_check_define.m4 \
	$(top_srcdir)/m4/ax_check_link_flag.m4 \
	$(top_srcdir)/m4/check_atomic.m4 \
	$(top_srcdir)/m4/check_clock_gettime.m4 \
	$(top_srcdir)/m4/check_libc++.m4 \
	$(top_srcdir)/m4/check_steady_clock.m4 \
	$(top_srcdir)/m4/check_thread_local.m4 \
	$(top_srcdir)/m4/check_time.m4 \
	$(top_srcdir)/m4/cxx_compile_stdcxx_14.m4 \
	$(top_srcdir)/m4/fz_check_pugixml.m4 \
	$(top_srcdir)/m4/fz_checkversion.m4 \
	$(top_srcdir)/m4/icopyhookw.m4 $(top_srcdir)/m4/libtool.m4 \
	$(top_srcdir)/m4/ltoptions.m4 $(top_srcdir)/m4/ltsugar.m4 \
	$(top_srcdir)/m4/ltversion.m4 $(top_srcdir)/m4/lt~obsolete.m4 \
	$(top_srcdir)/m4/map_emplace.m4 $(top_srcdir)/m4/pkg.m4 \
	$(top_srcdir)/m4/wxwin.m4 $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
DIST_COMMON = $(srcdir)/Makefile.am $(top_srcdir)/configure \
	$(am__configure_deps) $(dist_docs_DATA) $(dist_noinst_DATA) \
	$(am__DIST_COMMON)
am__CONFIG_DISTCLEAN_FILES = config.status config.cache config.log \
 configure.lineno config.status.lineno
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/src/include/config.h
CONFIG_CLEAN_FILES = src/fzshellext/version.rc
CONFIG_CLEAN_VPATH_FILES =
AM_V_P = $(am__v_P_$(V))
am__v_P_ = $(am__v_P_$(AM_DEFAULT_VERBOSITY))
am__v_P_0 = false
am__v_P_1 = :
AM_V_GEN = $(am__v_GEN_$(V))
am__v_GEN_ = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
am__v_GEN_0 = @echo "  GEN     " $@;
am__v_GEN_1 = 
AM_V_at = $(am__v_at_$(V))
am__v_at_ = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
am__v_at_0 = @
am__v_at_1 = 
SOURCES =
DIST_SOURCES =
RECURSIVE_TARGETS = all-recursive check-recursive cscopelist-recursive \
	ctags-recursive dvi-recursive html-recursive info-recursive \
	install-data-recursive install-dvi-recursive \
	install-exec-recursive install-html-recursive \
	install-info-recursive install-pdf-recursive \
	install-ps-recursive install-recursive installcheck-recursive \
	installdirs-recursive pdf-recursive ps-recursive \
	tags-recursive uninstall-recursive
am__can_run_installinfo = \
  case $$AM_UPDATE_INFO_DIR in \
    n|no|NO) false;; \
    *) (install-info --version) >/dev/null 2>&1;; \
  esac
am__vpath_adj_setup = srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`;
am__vpath_adj = case $$p in \
    $(srcdir)/*) f=`echo "$$p" | sed "s|^$$srcdirstrip/||"`;; \
    *) f=$$p;; \
  esac;
am__strip_dir = f=`echo $$p | sed -e 's|^.*/||'`;
am__install_max = 40
am__nobase_strip_setup = \
  srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*|]/\\\\&/g'`
am__nobase_strip = \
  for p in $$list; do echo "$$p"; done | sed -e "s|$$srcdirstrip/||"
am__nobase_list = $(am__nobase_strip_setup); \
  for p in $$list; do echo "$$p $$p"; done | \
  sed "s| $$srcdirstrip/| |;"' / .*\//!s/ .*/ ./; s,\( .*\)/[^/]*$$,\1,' | \
  $(AWK) 'BEGIN { files["."] = "" } { files[$$2] = files[$$2] " " $$1; \
    if (++n[$$2] == $(am__install_max)) \
      { print $$2, files[$$2]; n[$$2] = 0; files[$$2] = "" } } \
    END { for (dir in files) print dir, files[dir] }'
am__base_list = \
  sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
  sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
am__uninstall_files_from_dir = { \
  test -z "$$files" \
    || { test ! -d "$$dir" && test ! -f "$$dir" && test ! -r "$$dir"; } \
    || { echo " ( cd '$$dir' && rm -f" $$files ")"; \
         $(am__cd) "$$dir" && rm -f $$files; }; \
  }
man1dir = $(mandir)/man1
am__installdirs = "$(DESTDIR)$(man1dir)" "$(DESTDIR)$(man5dir)" \
	"$(DESTDIR)$(docsdir)"
man5dir = $(mandir)/man5
NROFF = nroff
MANS = $(dist_man1_MANS) $(dist_man5_MANS)
DATA = $(dist_docs_DATA) $(dist_noinst_DATA)
RECURSIVE_CLEAN_TARGETS = mostlyclean-recursive clean-recursive	\
  distclean-recursive maintainer-clean-recursive
am__recursive_targets = \
  $(RECURSIVE_TARGETS) \
  $(RECURSIVE_CLEAN_TARGETS) \
  $(am__extra_recursive_targets)
AM_RECURSIVE_TARGETS = $(am__recursive_targets:-recursive=) TAGS CTAGS \
	cscope distdir distdir-am dist dist-all distcheck
am__tagged_files = $(HEADERS) $(SOURCES) $(TAGS_FILES) $(LISP)
# Read a list of newline-separated strings from the standard input,
# and print each of them once, without duplicates.  Input order is
# *not* preserved.
am__uniquify_input = $(AWK) '\
  BEGIN { nonempty = 0; } \
  { items[$$0] = 1; nonempty = 1; } \
  END { if (nonempty) { for (i in items) print i; }; } \
'
# Make sure the list of sources is unique.  This is necessary because,
# e.g., the same source file might be shared among _SOURCES variables
# for different programs/libraries.
am__define_uniq_tagged_files = \
  list='$(am__tagged_files)'; \
  unique=`for i in $$list; do \
    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
  done | $(am__uniquify_input)`
DIST_SUBDIRS = . src locales data tests
am__DIST_COMMON = $(dist_man1_MANS) $(dist_man5_MANS) \
	$(srcdir)/Makefile.in $(top_srcdir)/config/compile \
	$(top_srcdir)/config/config.guess \
	$(top_srcdir)/config/config.sub \
	$(top_srcdir)/config/install-sh $(top_srcdir)/config/ltmain.sh \
	$(top_srcdir)/config/missing \
	$(top_srcdir)/src/fzshellext/version.rc.in AUTHORS COPYING \
	ChangeLog INSTALL NEWS README config/compile \
	config/config.guess config/config.sub config/depcomp \
	config/install-sh config/ltmain.sh config/missing
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
distdir = $(PACKAGE)-$(VERSION)
top_distdir = $(distdir)
am__remove_distdir = \
  if test -d "$(distdir)"; then \
    find "$(distdir)" -type d ! -perm -200 -exec chmod u+w {} ';' \
      && rm -rf "$(distdir)" \
      || { sleep 5 && rm -rf "$(distdir)"; }; \
  else :; fi
am__post_remove_distdir = $(am__remove_distdir)
am__relativize = \
  dir0=`pwd`; \
  sed_first='s,^\([^/]*\)/.*$$,\1,'; \
  sed_rest='s,^[^/]*/*,,'; \
  sed_last='s,^.*/\([^/]*\)$$,\1,'; \
  sed_butlast='s,/*[^/]*$$,,'; \
  while test -n "$$dir1"; do \
    first=`echo "$$dir1" | sed -e "$$sed_first"`; \
    if test "$$first" != "."; then \
      if test "$$first" = ".."; then \
        dir2=`echo "$$dir0" | sed -e "$$sed_last"`/"$$dir2"; \
        dir0=`echo "$$dir0" | sed -e "$$sed_butlast"`; \
      else \
        first2=`echo "$$dir2" | sed -e "$$sed_first"`; \
        if test "$$first2" = "$$first"; then \
          dir2=`echo "$$dir2" | sed -e "$$sed_rest"`; \
        else \
          dir2="../$$dir2"; \
        fi; \
        dir0="$$dir0"/"$$first"; \
      fi; \
    fi; \
    dir1=`echo "$$dir1" | sed -e "$$sed_rest"`; \
  done; \
  reldir="$$dir2"
DIST_ARCHIVES = $(distdir).tar.gz $(distdir).tar.bz2
GZIP_ENV = --best
DIST_TARGETS = dist-bzip2 dist-gzip
# Exists only to be overridden by the user if desired.
AM_DISTCHECK_DVI_TARGET = dvi
distuninstallcheck_listfiles = find . -type f -print
am__distuninstallcheck_listfiles = $(distuninstallcheck_listfiles) \
  | sed 's|^\./|$(prefix)/|' | grep -v '$(infodir)/dir$$'
distcleancheck_listfiles = find . -type f -print
ACLOCAL = ${SHELL} '/home/user/filezilla-3.41/config/missing' aclocal-1.16
AMTAR = $${TAR-tar}
AM_DEFAULT_VERBOSITY = 1
AR = ar
AUTOCONF = ${SHELL} '/home/user/filezilla-3.41/config/missing' autoconf
AUTOHEADER = ${SHELL} '/home/user/filezilla-3.41/config/missing' autoheader
AUTOMAKE = ${SHELL} '/home/user/filezilla-3.41/config/missing' automake-1.16
AWK = gawk
CC = gcc
CCDEPMODE = depmode=gcc3
CFBUNDLEIDSUFFIX = 
CFLAGS = -g -O2 -Wall
CPPFLAGS =  -fpch-preprocess
CPPUNIT_CFLAGS = 
CPPUNIT_LIBS = 
CSCOPE = cscope
CTAGS = ctags
CXX = g++
CXXCPP = g++ -E
CXXDEPMODE = depmode=gcc3
CXXFLAGS = -g -O2 -Wall
CYGPATH_W = cygpath -w
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DLLTOOL = dlltool
DSYMUTIL = 
DUMPBIN = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /usr/bin/grep -E
ETAGS = etags
EXEEXT = .exe
FGREP = /usr/bin/grep -F
FILECMD = file
FILEZILLA_LINGUAS = an ar az bg_BG ca ca_ES@valencia co cs_CZ cy da de el es et eu fa_IR fi_FI fr gl_ES he_IL hr hu_HU hy id_ID is it ja_JP ka kab km_KH ko_KR ku ky lo_LA lt_LT lv_LV mk_MK nb_NO ne nl nn_NO oc pl_PL pt_BR pt_PT ro_RO ru sk_SK sl_SI sr sv th_TH tr uk_UA vi_VN zh_CN zh_TW
FILEZILLA_LINGUAS_MO = an.mo ar.mo az.mo bg_BG.mo ca.mo ca_ES@valencia.mo co.mo cs_CZ.mo cy.mo da.mo de.mo el.mo es.mo et.mo eu.mo fa_IR.mo fi_FI.mo fr.mo gl_ES.mo he_IL.mo hr.mo hu_HU.mo hy.mo id_ID.mo is.mo it.mo ja_JP.mo ka.mo kab.mo km_KH.mo ko_KR.mo ku.mo ky.mo lo_LA.mo lt_LT.mo lv_LV.mo mk_MK.mo nb_NO.mo ne.mo nl.mo nn_NO.mo oc.mo pl_PL.mo pt_BR.mo pt_PT.mo ro_RO.mo ru.mo sk_SK.mo sl_SI.mo sr.mo sv.mo th_TH.mo tr.mo uk_UA.mo vi_VN.mo zh_CN.mo zh_TW.mo
FILEZILLA_LINGUAS_PO = $(srcdir)/an.po $(srcdir)/ar.po $(srcdir)/az.po $(srcdir)/bg_BG.po $(srcdir)/ca.po $(srcdir)/ca_ES@valencia.po $(srcdir)/co.po $(srcdir)/cs_CZ.po $(srcdir)/cy.po $(srcdir)/da.po $(srcdir)/de.po $(srcdir)/el.po $(srcdir)/es.po $(srcdir)/et.po $(srcdir)/eu.po $(srcdir)/fa_IR.po $(srcdir)/fi_FI.po $(srcdir)/fr.po $(srcdir)/gl_ES.po $(srcdir)/he_IL.po $(srcdir)/hr.po $(srcdir)/hu_HU.po $(srcdir)/hy.po $(srcdir)/id_ID.po $(srcdir)/is.po $(srcdir)/it.po $(srcdir)/ja_JP.po $(srcdir)/ka.po $(srcdir)/kab.po $(srcdir)/km_KH.po $(srcdir)/ko_KR.po $(srcdir)/ku.po $(srcdir)/ky.po $(srcdir)/lo_LA.po $(srcdir)/lt_LT.po $(srcdir)/lv_LV.po $(srcdir)/mk_MK.po $(srcdir)/nb_NO.po $(srcdir)/ne.po $(srcdir)/nl.po $(srcdir)/nn_NO.po $(srcdir)/oc.po $(srcdir)/pl_PL.po $(srcdir)/pt_BR.po $(srcdir)/pt_PT.po $(srcdir)/ro_RO.po $(srcdir)/ru.po $(srcdir)/sk_SK.po $(srcdir)/sl_SI.po $(srcdir)/sr.po $(srcdir)/sv.po $(srcdir)/th_TH.po $(srcdir)/tr.po $(srcdir)/uk_UA.po $(srcdir)/vi_VN.po $(srcdir)/zh_CN.po $(srcdir)/zh_TW.po
FILEZILLA_LINGUAS_PO_NEW = an.po.new ar.po.new az.po.new bg_BG.po.new ca.po.new ca_ES@valencia.po.new co.po.new cs_CZ.po.new cy.po.new da.po.new de.po.new el.po.new es.po.new et.po.new eu.po.new fa_IR.po.new fi_FI.po.new fr.po.new gl_ES.po.new he_IL.po.new hr.po.new hu_HU.po.new hy.po.new id_ID.po.new is.po.new it.po.new ja_JP.po.new ka.po.new kab.po.new km_KH.po.new ko_KR.po.new ku.po.new ky.po.new lo_LA.po.new lt_LT.po.new lv_LV.po.new mk_MK.po.new nb_NO.po.new ne.po.new nl.po.new nn_NO.po.new oc.po.new pl_PL.po.new pt_BR.po.new pt_PT.po.new ro_RO.po.new ru.po.new sk_SK.po.new sl_SI.po.new sr.po.new sv.po.new th_TH.po.new tr.po.new uk_UA.po.new vi_VN.po.new zh_CN.po.new zh_TW.po.new
GREP = /usr/bin/grep
HAVE_CXX14 = 
HOGWEED_CFLAGS = -ID:/msys64_231026/home/user/prefix/include
HOGWEED_LIBS = -LD:/msys64_231026/home/user/prefix/lib -lhogweed
IDN_LIB = 
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
LD = D:/msys64_231026/mingw64/x86_64-w64-mingw32/bin/ld.exe
LDFLAGS =  -Wl,--dynamicbase -Wl,--nxcompat -Wl,--major-subsystem-version -Wl,6 -Wl,--minor-subsystem-version -Wl,1 -Wl,--major-os-version -Wl,6 -Wl,--minor-os-version -Wl,1
LIBDBUS_CFLAGS = 
LIBDBUS_LIBS = 
LIBFILEZILLA_CFLAGS = -ID:/msys64_231026/home/user/prefix/include -ID:/msys64_231026/mingw64/bin/../include
LIBFILEZILLA_LIBS = -LD:/msys64_231026/home/user/prefix/lib -lfilezilla -lws2_32 -liphlpapi
LIBGNUTLS_CFLAGS = -ID:/msys64_231026/home/user/prefix/include -ID:/msys64_231026/mingw64/bin/../include
LIBGNUTLS_LIBS = -LD:/msys64_231026/home/user/prefix/lib -lgnutls
LIBGTK_CFLAGS = 
LIBGTK_LIBS = 
LIBOBJS = 
LIBS = 
LIBSQLITE3_CFLAGS = -ID:/msys64_231026/home/user/prefix/include
LIBSQLITE3_LIBS = -LD:/msys64_231026/home/user/prefix/lib -lsqlite3
LIBSTORJ_CFLAGS = 
LIBSTORJ_LIBS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIPO = 
LN_S = cp -pR
LTLIBOBJS = 
LT_SYS_LIBRARY_PATH = 
MAKEINFO = ${SHELL} '/home/user/filezilla-3.41/config/missing' makeinfo
MANIFEST_TOOL = :
MKDIR_P = /usr/bin/mkdir -p
NETTLE_CFLAGS = -ID:/msys64_231026/home/user/prefix/include
NETTLE_LIBS = -LD:/msys64_231026/home/user/prefix/lib -lnettle
NM = /mingw64/bin/nm -B
NMEDIT = 
NSIS_64BIT = 1
OBJC = 
OBJCDEPMODE = depmode=none
OBJCFLAGS = 
OBJDUMP = objdump
OBJEXT = o
OTOOL = 
OTOOL64 = 
PACKAGE = filezilla
PACKAGE_BUGREPORT = tim.kosse@filezilla-project.org
PACKAGE_NAME = FileZilla
PACKAGE_STRING = FileZilla 3.41.2
PACKAGE_TARNAME = filezilla
PACKAGE_URL = https://filezilla-project.org/
PACKAGE_VERSION = 3.41.2
PACKAGE_VERSION_MAJOR = 3
PACKAGE_VERSION_MICRO = 2
PACKAGE_VERSION_MINOR = 41
PACKAGE_VERSION_NANO = 0
PATH_SEPARATOR = :
PKG_CONFIG = /mingw64/bin/pkg-config
PKG_CONFIG_LIBDIR = 
PKG_CONFIG_PATH = /home/user/prefix/lib/pkgconfig
PUGIXML_LIBS = $(top_builddir)/src/pugixml/libpugixml.a
RANLIB = ranlib
SED = /usr/bin/sed
SET_MAKE = 
SHELL = /bin/sh
STRIP = strip
VERSION = 3.41.2
WINDRES = windres
WINDRESFLAGS =  --include-dir=/home/user/prefix/lib/wx/include/msw-unicode-3.0 --include-dir=/home/user/prefix/include/wx-3.0 -D_FILE_OFFSET_BITS=64 -DWXUSINGDLL -D__WXMSW__
WXRC = /home/user/prefix/bin/wxrc
WX_CFLAGS = -I/home/user/prefix/lib/wx/include/msw-unicode-3.0 -I/home/user/prefix/include/wx-3.0 -D_FILE_OFFSET_BITS=64 -DWXUSINGDLL -D__WXMSW__ 
WX_CFLAGS_ONLY = 
WX_CONFIG_PATH = /home/user/prefix/bin/wx-config
WX_CONFIG_WITH_ARGS = /home/user/prefix/bin/wx-config  --unicode=yes --universal=no
WX_CPPFLAGS = -I/home/user/prefix/lib/wx/include/msw-unicode-3.0 -I/home/user/prefix/include/wx-3.0 -D_FILE_OFFSET_BITS=64 -DWXUSINGDLL -D__WXMSW__
WX_CXXFLAGS = -I/home/user/prefix/lib/wx/include/msw-unicode-3.0 -I/home/user/prefix/include/wx-3.0 -D_FILE_OFFSET_BITS=64 -DWXUSINGDLL -D__WXMSW__ 
WX_CXXFLAGS_ONLY = -I/home/user/prefix/lib/wx/include/msw-unicode-3.0 -I/home/user/prefix/include/wx-3.0 -D_FILE_OFFSET_BITS=64 -DWXUSINGDLL -D__WXMSW__
WX_LIBS = -L/home/user/prefix/lib   -Wl,--subsystem,windows -mwindows -lwx_mswu_aui-3.0 -lwx_mswu_xrc-3.0 -lwx_mswu_adv-3.0 -lwx_mswu_core-3.0 -lwx_baseu_xml-3.0 -lwx_baseu-3.0 
WX_LIBS_STATIC = 
WX_RESCOMP = windres --include-dir /home/user/prefix/include/wx-3.0 --define __WIN32__ --define __GNUWIN32__ --define WX_CPU_AMD64
WX_VERSION = 3.0.6
WX_VERSION_MAJOR = 3
WX_VERSION_MICRO = 6
WX_VERSION_MINOR = 0
abs_builddir = /home/user/filezilla-3.41
abs_srcdir = /home/user/filezilla-3.41
abs_top_builddir = /home/user/filezilla-3.41
abs_top_srcdir = /home/user/filezilla-3.41
ac_ct_AR = ar
ac_ct_CC = gcc
ac_ct_CXX = g++
ac_ct_DUMPBIN = 
ac_ct_OBJC = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = $${TAR-tar} chof - "$$tardir"
am__untar = $${TAR-tar} xf -
bindir = ${exec_prefix}/bin
build = x86_64-w64-mingw32
build_alias = x86_64-w64-mingw32
build_cpu = x86_64
build_os = mingw32
build_vendor = w64
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir = ${docdir}
exec_prefix = ${prefix}
host = x86_64-w64-mingw32
host_alias = 
host_cpu = x86_64
host_os = mingw32
host_vendor = w64
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/user/filezilla-3.41/config/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mkdir_p = $(MKDIR_P)
msgfmt = /mingw64/bin/msgfmt
msgmerge = /mingw64/bin/msgmerge
oldincludedir = /usr/include
pdfdir = ${docdir}
prefix = /mingw64
program_transform_name = s,x,x,
psdir = ${docdir}
runstatedir = ${localstatedir}/run
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
subdirs = 
sysconfdir = ${prefix}/etc
target_alias = 
top_build_prefix = 
top_builddir = .
top_srcdir = .
xdgopen = 
xgettext = /mingw64/bin/xgettext
ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = 1.6
MAYBE_SRCDIR = src
MAYBE_DATADIR = data
#MAYBE_TESTS = tests
MAYBE_LOCALES = locales
SUBDIRS = . $(MAYBE_SRCDIR) $(MAYBE_LOCALES) $(MAYBE_DATADIR) $(MAYBE_TESTS)
dist_noinst_DATA = GPL.html docs/iconspecs.htm
docsdir = $(pkgdatadir)/docs
dist_docs_DATA = docs/fzdefaults.xml.example
dist_man1_MANS = docs/filezilla.man \
		 docs/fzputtygen.man \
		 docs/fzsftp.man

dist_man5_MANS = docs/fzdefaults.xml.man
all: all-recursive

.SUFFIXES:
am--refresh: Makefile
	@:
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      echo ' cd $(srcdir) && $(AUTOMAKE) --gnu'; \
	      $(am__cd) $(srcdir) && $(AUTOMAKE) --gnu \
		&& exit 0; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --gnu Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --gnu Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    echo ' $(SHELL) ./config.status'; \
	    $(SHELL) ./config.status;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $@ $(am__maybe_remake_depfiles)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $@ $(am__maybe_remake_depfiles);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	$(SHELL) ./config.status --recheck

$(top_srcdir)/configure:  $(am__configure_deps)
	$(am__cd) $(srcdir) && $(AUTOCONF)
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	$(am__cd) $(srcdir) && $(ACLOCAL) $(ACLOCAL_AMFLAGS)
$(am__aclocal_m4_deps):
src/fzshellext/version.rc: $(top_builddir)/config.status $(top_srcdir)/src/fzshellext/version.rc.in
	cd $(top_builddir) && $(SHELL) ./config.status $@

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

distclean-libtool:
	-rm -f libtool config.lt
install-man1: $(dist_man1_MANS)
	@$(NORMAL_INSTALL)
	@list1='$(dist_man1_MANS)'; \
	list2=''; \
	test -n "$(man1dir)" \
	  && test -n "`echo $$list1$$list2`" \
	  || exit 0; \
	echo " $(MKDIR_P) '$(DESTDIR)$(man1dir)'"; \
	$(MKDIR_P) "$(DESTDIR)$(man1dir)" || exit 1; \
	{ for i in $$list1; do echo "$$i"; done;  \
	if test -n "$$list2"; then \
	  for i in $$list2; do echo "$$i"; done \
	    | sed -n '/\.1[a-z]*$$/p'; \
	fi; \
	} | while read p; do \
	  if test -f $$p; then d=; else d="$(srcdir)/"; fi; \
	  echo "$$d$$p"; echo "$$p"; \
	done | \
	sed -e 'n;s,.*/,,;p;h;s,.*\.,,;s,^[^1][0-9a-z]*$$,1,;x' \
	      -e 's,\.[0-9a-z]*$$,,;$(transform);G;s,\n,.,' | \
	sed 'N;N;s,\n, ,g' | { \
	list=; while read file base inst; do \
	  if test "$$base" = "$$inst"; then list="$$list $$file"; else \
	    echo " $(INSTALL_DATA) '$$file' '$(DESTDIR)$(man1dir)/$$inst'"; \
	    $(INSTALL_DATA) "$$file" "$(DESTDIR)$(man1dir)/$$inst" || exit $$?; \
	  fi; \
	done; \
	for i in $$list; do echo "$$i"; done | $(am__base_list) | \
	while read files; do \
	  test -z "$$files" || { \
	    echo " $(INSTALL_DATA) $$files '$(DESTDIR)$(man1dir)'"; \
	    $(INSTALL_DATA) $$files "$(DESTDIR)$(man1dir)" || exit $$?; }; \
	done; }

uninstall-man1:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_man1_MANS)'; test -n "$(man1dir)" || exit 0; \
	files=`{ for i in $$list; do echo "$$i"; done; \
	} | sed -e 's,.*/,,;h;s,.*\.,,;s,^[^1][0-9a-z]*$$,1,;x' \
	      -e 's,\.[0-9a-z]*$$,,;$(transform);G;s,\n,.,'`; \
	dir='$(DESTDIR)$(man1dir)'; $(am__uninstall_files_from_dir)
install-man5: $(dist_man5_MANS)
	@$(NORMAL_INSTALL)
	@list1='$(dist_man5_MANS)'; \
	list2=''; \
	test -n "$(man5dir)" \
	  && test -n "`echo $$list1$$list2`" \
	  || exit 0; \
	echo " $(MKDIR_P) '$(DESTDIR)$(man5dir)'"; \
	$(MKDIR_P) "$(DESTDIR)$(man5dir)" || exit 1; \
	{ for i in $$list1; do echo "$$i"; done;  \
	if test -n "$$list2"; then \
	  for i in $$list2; do echo "$$i"; done \
	    | sed -n '/\.5[a-z]*$$/p'; \
	fi; \
	} | while read p; do \
	  if test -f $$p; then d=; else d="$(srcdir)/"; fi; \
	  echo "$$d$$p"; echo "$$p"; \
	done | \
	sed -e 'n;s,.*/,,;p;h;s,.*\.,,;s,^[^5][0-9a-z]*$$,5,;x' \
	      -e 's,\.[0-9a-z]*$$,,;$(transform);G;s,\n,.,' | \
	sed 'N;N;s,\n, ,g' | { \
	list=; while read file base inst; do \
	  if test "$$base" = "$$inst"; then list="$$list $$file"; else \
	    echo " $(INSTALL_DATA) '$$file' '$(DESTDIR)$(man5dir)/$$inst'"; \
	    $(INSTALL_DATA) "$$file" "$(DESTDIR)$(man5dir)/$$inst" || exit $$?; \
	  fi; \
	done; \
	for i in $$list; do echo "$$i"; done | $(am__base_list) | \
	while read files; do \
	  test -z "$$files" || { \
	    echo " $(INSTALL_DATA) $$files '$(DESTDIR)$(man5dir)'"; \
	    $(INSTALL_DATA) $$files "$(DESTDIR)$(man5dir)" || exit $$?; }; \
	done; }

uninstall-man5:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_man5_MANS)'; test -n "$(man5dir)" || exit 0; \
	files=`{ for i in $$list; do echo "$$i"; done; \
	} | sed -e 's,.*/,,;h;s,.*\.,,;s,^[^5][0-9a-z]*$$,5,;x' \
	      -e 's,\.[0-9a-z]*$$,,;$(transform);G;s,\n,.,'`; \
	dir='$(DESTDIR)$(man5dir)'; $(am__uninstall_files_from_dir)
install-dist_docsDATA: $(dist_docs_DATA)
	@$(NORMAL_INSTALL)
	@list='$(dist_docs_DATA)'; test -n "$(docsdir)" || list=; \
	if test -n "$$list"; then \
	  echo " $(MKDIR_P) '$(DESTDIR)$(docsdir)'"; \
	  $(MKDIR_P) "$(DESTDIR)$(docsdir)" || exit 1; \
	fi; \
	for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  echo "$$d$$p"; \
	done | $(am__base_list) | \
	while read files; do \
	  echo " $(INSTALL_DATA) $$files '$(DESTDIR)$(docsdir)'"; \
	  $(INSTALL_DATA) $$files "$(DESTDIR)$(docsdir)" || exit $$?; \
	done

uninstall-dist_docsDATA:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_docs_DATA)'; test -n "$(docsdir)" || list=; \
	files=`for p in $$list; do echo $$p; done | sed -e 's|^.*/||'`; \
	dir='$(DESTDIR)$(docsdir)'; $(am__uninstall_files_from_dir)

# This directory's subdirectories are mostly independent; you can cd
# into them and run 'make' without going through this Makefile.
# To change the values of 'make' variables: instead of editing Makefiles,
# (1) if the variable is set in 'config.status', edit 'config.status'
#     (which will cause the Makefiles to be regenerated when you run 'make');
# (2) otherwise, pass the desired values on the 'make' command line.
$(am__recursive_targets):
	@fail=; \
	if $(am__make_keepgoing); then \
	  failcom='fail=yes'; \
	else \
	  failcom='exit 1'; \
	fi; \
	dot_seen=no; \
	target=`echo $@ | sed s/-recursive//`; \
	case "$@" in \
	  distclean-* | maintainer-clean-*) list='$(DIST_SUBDIRS)' ;; \
	  *) list='$(SUBDIRS)' ;; \
	esac; \
	for subdir in $$list; do \
	  echo "Making $$target in $$subdir"; \
	  if test "$$subdir" = "."; then \
	    dot_seen=yes; \
	    local_target="$$target-am"; \
	  else \
	    local_target="$$target"; \
	  fi; \
	  ($(am__cd) $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$local_target) \
	  || eval $$failcom; \
	done; \
	if test "$$dot_seen" = "no"; then \
	  $(MAKE) $(AM_MAKEFLAGS) "$$target-am" || exit 1; \
	fi; test -z "$$fail"

ID: $(am__tagged_files)
	$(am__define_uniq_tagged_files); mkid -fID $$unique
tags: tags-recursive
TAGS: tags

tags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	set x; \
	here=`pwd`; \
	if ($(ETAGS) --etags-include --version) >/dev/null 2>&1; then \
	  include_option=--etags-include; \
	  empty_fix=.; \
	else \
	  include_option=--include; \
	  empty_fix=; \
	fi; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  if test "$$subdir" = .; then :; else \
	    test ! -f $$subdir/TAGS || \
	      set "$$@" "$$include_option=$$here/$$subdir/TAGS"; \
	  fi; \
	done; \
	$(am__define_uniq_tagged_files); \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: ctags-recursive

CTAGS: ctags
ctags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	$(am__define_uniq_tagged_files); \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"
cscope: cscope.files
	test ! -s cscope.files \
	  || $(CSCOPE) -b -q $(AM_CSCOPEFLAGS) $(CSCOPEFLAGS) -i cscope.files $(CSCOPE_ARGS)
clean-cscope:
	-rm -f cscope.files
cscope.files: clean-cscope cscopelist
cscopelist: cscopelist-recursive

cscopelist-am: $(am__tagged_files)
	list='$(am__tagged_files)'; \
	case "$(srcdir)" in \
	  [\\/]* | ?:[\\/]*) sdir="$(srcdir)" ;; \
	  *) sdir=$(subdir)/$(srcdir) ;; \
	esac; \
	for i in $$list; do \
	  if test -f "$$i"; then \
	    echo "$(subdir)/$$i"; \
	  else \
	    echo "$$sdir/$$i"; \
	  fi; \
	done >> $(top_builddir)/cscope.files

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags
	-rm -f cscope.out cscope.in.out cscope.po.out cscope.files
distdir: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) distdir-am

distdir-am: $(DISTFILES)
	$(am__remove_distdir)
	test -d "$(distdir)" || mkdir "$(distdir)"
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
	@list='$(DIST_SUBDIRS)'; for subdir in $$list; do \
	  if test "$$subdir" = .; then :; else \
	    $(am__make_dryrun) \
	      || test -d "$(distdir)/$$subdir" \
	      || $(MKDIR_P) "$(distdir)/$$subdir" \
	      || exit 1; \
	    dir1=$$subdir; dir2="$(distdir)/$$subdir"; \
	    $(am__relativize); \
	    new_distdir=$$reldir; \
	    dir1=$$subdir; dir2="$(top_distdir)"; \
	    $(am__relativize); \
	    new_top_distdir=$$reldir; \
	    echo " (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) top_distdir="$$new_top_distdir" distdir="$$new_distdir" \\"; \
	    echo "     am__remove_distdir=: am__skip_length_check=: am__skip_mode_fix=: distdir)"; \
	    ($(am__cd) $$subdir && \
	      $(MAKE) $(AM_MAKEFLAGS) \
	        top_distdir="$$new_top_distdir" \
	        distdir="$$new_distdir" \
		am__remove_distdir=: \
		am__skip_length_check=: \
		am__skip_mode_fix=: \
	        distdir) \
	      || exit 1; \
	  fi; \
	done
	-test -n "$(am__skip_mode_fix)" \
	|| find "$(distdir)" -type d ! -perm -755 \
		-exec chmod u+rwx,go+rx {} \; -o \
	  ! -type d ! -perm -444 -links 1 -exec chmod a+r {} \; -o \
	  ! -type d ! -perm -400 -exec chmod a+r {} \; -o \
	  ! -type d ! -perm -444 -exec $(install_sh) -c -m a+r {} {} \; \
	|| chmod -R a+r "$(distdir)"
dist-gzip: distdir
	tardir=$(distdir) && $(am__tar) | eval GZIP= gzip $(GZIP_ENV) -c >$(distdir).tar.gz
	$(am__post_remove_distdir)
dist-bzip2: distdir
	tardir=$(distdir) && $(am__tar) | BZIP2=$${BZIP2--9} bzip2 -c >$(distdir).tar.bz2
	$(am__post_remove_distdir)

dist-lzip: distdir
	tardir=$(distdir) && $(am__tar) | lzip -c $${LZIP_OPT--9} >$(distdir).tar.lz
	$(am__post_remove_distdir)

dist-xz: distdir
	tardir=$(distdir) && $(am__tar) | XZ_OPT=$${XZ_OPT--e} xz -c >$(distdir).tar.xz
	$(am__post_remove_distdir)

dist-zstd: distdir
	tardir=$(distdir) && $(am__tar) | zstd -c $${ZSTD_CLEVEL-$${ZSTD_OPT--19}} >$(distdir).tar.zst
	$(am__post_remove_distdir)

dist-tarZ: distdir
	@echo WARNING: "Support for distribution archives compressed with" \
		       "legacy program 'compress' is deprecated." >&2
	@echo WARNING: "It will be removed altogether in Automake 2.0" >&2
	tardir=$(distdir) && $(am__tar) | compress -c >$(distdir).tar.Z
	$(am__post_remove_distdir)

dist-shar: distdir
	@echo WARNING: "Support for shar distribution archives is" \
	               "deprecated." >&2
	@echo WARNING: "It will be removed altogether in Automake 2.0" >&2
	shar $(distdir) | eval GZIP= gzip $(GZIP_ENV) -c >$(distdir).shar.gz
	$(am__post_remove_distdir)

dist-zip: distdir
	-rm -f $(distdir).zip
	zip -rq $(distdir).zip $(distdir)
	$(am__post_remove_distdir)

dist dist-all:
	$(MAKE) $(AM_MAKEFLAGS) $(DIST_TARGETS) am__post_remove_distdir='@:'
	$(am__post_remove_distdir)

# This target untars the dist file and tries a VPATH configuration.  Then
# it guarantees that the distribution is self-contained by making another
# tarfile.
distcheck: dist
	case '$(DIST_ARCHIVES)' in \
	*.tar.gz*) \
	  eval GZIP= gzip $(GZIP_ENV) -dc $(distdir).tar.gz | $(am__untar) ;;\
	*.tar.bz2*) \
	  bzip2 -dc $(distdir).tar.bz2 | $(am__untar) ;;\
	*.tar.lz*) \
	  lzip -dc $(distdir).tar.lz | $(am__untar) ;;\
	*.tar.xz*) \
	  xz -dc $(distdir).tar.xz | $(am__untar) ;;\
	*.tar.Z*) \
	  uncompress -c $(distdir).tar.Z | $(am__untar) ;;\
	*.shar.gz*) \
	  eval GZIP= gzip $(GZIP_ENV) -dc $(distdir).shar.gz | unshar ;;\
	*.zip*) \
	  unzip $(distdir).zip ;;\
	*.tar.zst*) \
	  zstd -dc $(distdir).tar.zst | $(am__untar) ;;\
	esac
	chmod -R a-w $(distdir)
	chmod u+w $(distdir)
	mkdir $(distdir)/_build $(distdir)/_build/sub $(distdir)/_inst
	chmod a-w $(distdir)
	test -d $(distdir)/_build || exit 0; \
	dc_install_base=`$(am__cd) $(distdir)/_inst && pwd | sed -e 's,^[^:\\/]:[\\/],/,'` \
	  && dc_destdir="$${TMPDIR-/tmp}/am-dc-$$$$/" \
	  && am__cwd=`pwd` \
	  && $(am__cd) $(distdir)/_build/sub \
	  && ../../configure \
	    $(AM_DISTCHECK_CONFIGURE_FLAGS) \
	    $(DISTCHECK_CONFIGURE_FLAGS) \
	    --srcdir=../.. --prefix="$$dc_install_base" \
	  && $(MAKE) $(AM_MAKEFLAGS) \
	  && $(MAKE) $(AM_MAKEFLAGS) $(AM_DISTCHECK_DVI_TARGET) \
	  && $(MAKE) $(AM_MAKEFLAGS) check \
	  && $(MAKE) $(AM_MAKEFLAGS) install \
	  && $(MAKE) $(AM_MAKEFLAGS) installcheck \
	  && $(MAKE) $(AM_MAKEFLAGS) uninstall \
	  && $(MAKE) $(AM_MAKEFLAGS) distuninstallcheck_dir="$$dc_install_base" \
	        distuninstallcheck \
	  && chmod -R a-w "$$dc_install_base" \
	  && ({ \
	       (cd ../.. && umask 077 && mkdir "$$dc_destdir") \
	       && $(MAKE) $(AM_MAKEFLAGS) DESTDIR="$$dc_destdir" install \
	       && $(MAKE) $(AM_MAKEFLAGS) DESTDIR="$$dc_destdir" uninstall \
	       && $(MAKE) $(AM_MAKEFLAGS) DESTDIR="$$dc_destdir" \
	            distuninstallcheck_dir="$$dc_destdir" distuninstallcheck; \
	      } || { rm -rf "$$dc_destdir"; exit 1; }) \
	  && rm -rf "$$dc_destdir" \
	  && $(MAKE) $(AM_MAKEFLAGS) dist \
	  && rm -rf $(DIST_ARCHIVES) \
	  && $(MAKE) $(AM_MAKEFLAGS) distcleancheck \
	  && cd "$$am__cwd" \
	  || exit 1
	$(am__post_remove_distdir)
	@(echo "$(distdir) archives ready for distribution: "; \
	  list='$(DIST_ARCHIVES)'; for i in $$list; do echo $$i; done) | \
	  sed -e 1h -e 1s/./=/g -e 1p -e 1x -e '$$p' -e '$$x'
distuninstallcheck:
	@test -n '$(distuninstallcheck_dir)' || { \
	  echo 'ERROR: trying to run $@ with an empty' \
	       '$$(distuninstallcheck_dir)' >&2; \
	  exit 1; \
	}; \
	$(am__cd) '$(distuninstallcheck_dir)' || { \
	  echo 'ERROR: cannot chdir into $(distuninstallcheck_dir)' >&2; \
	  exit 1; \
	}; \
	test `$(am__distuninstallcheck_listfiles) | wc -l` -eq 0 \
	   || { echo "ERROR: files left after uninstall:" ; \
	        if test -n "$(DESTDIR)"; then \
	          echo "  (check DESTDIR support)"; \
	        fi ; \
	        $(distuninstallcheck_listfiles) ; \
	        exit 1; } >&2
distcleancheck: distclean
	@if test '$(srcdir)' = . ; then \
	  echo "ERROR: distcleancheck can only run from a VPATH build" ; \
	  exit 1 ; \
	fi
	@test `$(distcleancheck_listfiles) | wc -l` -eq 0 \
	  || { echo "ERROR: files left in build directory after distclean:" ; \
	       $(distcleancheck_listfiles) ; \
	       exit 1; } >&2
check-am: all-am
check: check-recursive
all-am: Makefile $(MANS) $(DATA)
installdirs: installdirs-recursive
installdirs-am:
	for dir in "$(DESTDIR)$(man1dir)" "$(DESTDIR)$(man5dir)" "$(DESTDIR)$(docsdir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-recursive
install-exec: install-exec-recursive
install-data: install-data-recursive
uninstall: uninstall-recursive

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-recursive
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
#clean-local:
clean-local:
clean: clean-recursive

clean-am: clean-generic clean-libtool clean-local mostlyclean-am

distclean: distclean-recursive
	-rm -f $(am__CONFIG_DISTCLEAN_FILES)
	-rm -f Makefile
distclean-am: clean-am distclean-generic distclean-libtool \
	distclean-tags

dvi: dvi-recursive

dvi-am:

html: html-recursive

html-am:

info: info-recursive

info-am:

install-data-am: install-dist_docsDATA install-man

install-dvi: install-dvi-recursive

install-dvi-am:

install-exec-am:

install-html: install-html-recursive

install-html-am:

install-info: install-info-recursive

install-info-am:

install-man: install-man1 install-man5

install-pdf: install-pdf-recursive

install-pdf-am:

install-ps: install-ps-recursive

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-recursive
	-rm -f $(am__CONFIG_DISTCLEAN_FILES)
	-rm -rf $(top_srcdir)/autom4te.cache
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-recursive

mostlyclean-am: mostlyclean-generic mostlyclean-libtool

pdf: pdf-recursive

pdf-am:

ps: ps-recursive

ps-am:

uninstall-am: uninstall-dist_docsDATA uninstall-man

uninstall-man: uninstall-man1 uninstall-man5

.MAKE: $(am__recursive_targets) install-am install-strip

.PHONY: $(am__recursive_targets) CTAGS GTAGS TAGS all all-am \
	am--refresh check check-am clean clean-cscope clean-generic \
	clean-libtool clean-local cscope cscopelist-am ctags ctags-am \
	dist dist-all dist-bzip2 dist-gzip dist-lzip dist-shar \
	dist-tarZ dist-xz dist-zip dist-zstd distcheck distclean \
	distclean-generic distclean-libtool distclean-tags \
	distcleancheck distdir distuninstallcheck dvi dvi-am html \
	html-am info info-am install install-am install-data \
	install-data-am install-dist_docsDATA install-dvi \
	install-dvi-am install-exec install-exec-am install-html \
	install-html-am install-info install-info-am install-man \
	install-man1 install-man5 install-pdf install-pdf-am \
	install-ps install-ps-am install-strip installcheck \
	installcheck-am installdirs installdirs-am maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-generic \
	mostlyclean-libtool pdf pdf-am ps ps-am tags tags-am uninstall \
	uninstall-am uninstall-dist_docsDATA uninstall-man \
	uninstall-man1 uninstall-man5

.PRECIOUS: Makefile


#clean-local:
#	rm -rf FileZilla.app

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
