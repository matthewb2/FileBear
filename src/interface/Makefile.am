SUBDIRS = resources .
#########################################################################
# APPLICATION SECTION
#########################################################################
# this is the program that gets installed.  it's name is used for all
# of the other Makefile.am variables

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = filezilla

# the application source, library search path, and link libraries
filezilla_SOURCES = aboutdialog.cpp \
		asksavepassworddialog.cpp \
		asyncrequestqueue.cpp \
		aui_notebook_ex.cpp \
		auto_ascii_files.cpp \
		bookmarks_dialog.cpp \
		buildinfo.cpp \
		chmoddialog.cpp \
		clearprivatedata.cpp \
		cmdline.cpp \
		commandqueue.cpp \
		conditionaldialog.cpp \
		context_control.cpp \
		customheightlistctrl.cpp \
		defaultfileexistsdlg.cpp \
		dialogex.cpp \
		dndobjects.cpp \
		dragdropmanager.cpp \
		drop_target_ex.cpp \
		edithandler.cpp \
		encoding_converter.cpp \
		export.cpp \
		fileexistsdlg.cpp \
		filelistctrl.cpp \
		filelist_statusbar.cpp \
		FileZilla.cpp \
		filter.cpp \
		filter_conditions_dialog.cpp \
		filteredit.cpp \
		file_utils.cpp \
		fzputtygen_interface.cpp \
		graphics.cpp \
		import.cpp \
		inputdialog.cpp \
		ipcmutex.cpp \
		led.cpp \
		listctrlex.cpp \
		listingcomparison.cpp \
		list_search_panel.cpp \
		local_recursive_operation.cpp \
		locale_initializer.cpp \
		LocalListView.cpp \
		LocalTreeView.cpp \
		loginmanager.cpp \
		Mainfrm.cpp \
		manual_transfer.cpp \
		menu_bar.cpp \
		msgbox.cpp \
		netconfwizard.cpp \
		Options.cpp \
		power_management.cpp \
		queue.cpp \
		queue_storage.cpp \
		QueueView.cpp \
		queueview_failed.cpp \
		queueview_successful.cpp \
		quickconnectbar.cpp \
		recentserverlist.cpp \
		recursive_operation.cpp \
		recursive_operation_status.cpp \
		remote_recursive_operation.cpp \
		RemoteListView.cpp \
		RemoteTreeView.cpp \
		search.cpp \
		serverdata.cpp \
		settings/optionspage.cpp \
		settings/optionspage_connection.cpp \
		settings/optionspage_connection_active.cpp \
		settings/optionspage_connection_ftp.cpp \
		settings/optionspage_connection_passive.cpp \
		settings/optionspage_connection_sftp.cpp \
		settings/optionspage_dateformatting.cpp \
		settings/optionspage_debug.cpp \
		settings/optionspage_edit.cpp \
		settings/optionspage_edit_associations.cpp \
		settings/optionspage_fileexists.cpp \
		settings/optionspage_filelists.cpp \
		settings/optionspage_filetype.cpp \
		settings/optionspage_ftpproxy.cpp \
		settings/optionspage_interface.cpp \
		settings/optionspage_language.cpp \
		settings/optionspage_logging.cpp \
		settings/optionspage_passwords.cpp \
		settings/optionspage_proxy.cpp \
		settings/optionspage_sizeformatting.cpp \
		settings/optionspage_themes.cpp \
		settings/optionspage_transfer.cpp \
		settings/optionspage_updatecheck.cpp \
		settings/settingsdialog.cpp \
		sftp_crypt_info_dlg.cpp \
		sitemanager.cpp \
		sitemanager_dialog.cpp \
		sitemanager_site.cpp \
		sizeformatting.cpp \
		speedlimits_dialog.cpp \
		splitter.cpp \
		state.cpp \
		statusbar.cpp \
		statuslinectrl.cpp \
		StatusView.cpp \
		systemimagelist.cpp \
		textctrlex.cpp \
		themeprovider.cpp \
		timeformatting.cpp \
		toolbar.cpp \
		treectrlex.cpp \
		updater.cpp \
		update_dialog.cpp \
		verifycertdialog.cpp \
		verifyhostkeydialog.cpp \
		view.cpp \
		viewheader.cpp \
		volume_enumerator.cpp \
		welcome_dialog.cpp \
		window_state_manager.cpp \
		wrapengine.cpp \
		wxfilesystem_blob_handler.cpp \
		xh_text_ex.cpp \
		xmlfunctions.cpp \
		xrc_helper.cpp


noinst_HEADERS = aboutdialog.h \
		 asksavepassworddialog.h \
		 asyncrequestqueue.h \
		 aui_notebook_ex.h \
		 auto_ascii_files.h \
		 bookmarks_dialog.h \
		 buildinfo.h \
		 chmoddialog.h \
		 clearprivatedata.h \
		 cmdline.h \
		 commandqueue.h \
		 conditionaldialog.h \
		 context_control.h \
		 customheightlistctrl.h \
		 defaultfileexistsdlg.h \
		 dialogex.h \
		 dndobjects.h \
		 dragdropmanager.h \
		 drop_target_ex.h \
		 edithandler.h \
		 encoding_converter.h \
		 export.h \
		 fileexistsdlg.h \
		 filelistctrl.h \
		 filelist_statusbar.h \
		 filezilla.h \
		 filezillaapp.h \
		 filter.h \
		 filter_conditions_dialog.h \
		 filteredit.h \
		 file_utils.h \
		 fzputtygen_interface.h \
		 graphics.h \
		 import.h \
		 inputdialog.h \
		 ipcmutex.h \
		 led.h \
		 listctrlex.h \
		 listingcomparison.h \
		 list_search_panel.h \
		 local_recursive_operation.h \
		 locale_initializer.h \
		 LocalListView.h \
		 LocalTreeView.h \
		 loginmanager.h \
		 Mainfrm.h \
		 manual_transfer.h \
		 menu_bar.h \
		 msgbox.h \
		 netconfwizard.h \
		 Options.h \
		 power_management.h \
		 queue.h \
		 queue_storage.h \
		 QueueView.h \
		 queueview_failed.h \
		 queueview_successful.h \
		 quickconnectbar.h \
		 recentserverlist.h \
		 recursive_operation.h \
		 recursive_operation_status.h \
		 remote_recursive_operation.h \
		 RemoteListView.h \
		 RemoteTreeView.h \
		 search.h \
		 serverdata.h \
		 settings/optionspage.h \
		 settings/optionspage_connection.h \
		 settings/optionspage_connection_active.h \
		 settings/optionspage_connection_ftp.h \
		 settings/optionspage_connection_passive.h \
		 settings/optionspage_connection_sftp.h \
		 settings/optionspage_dateformatting.h \
		 settings/optionspage_debug.h \
		 settings/optionspage_edit.h \
		 settings/optionspage_edit_associations.h \
		 settings/optionspage_fileexists.h \
		 settings/optionspage_filelists.h \
		 settings/optionspage_filetype.h \
		 settings/optionspage_ftpproxy.h \
		 settings/optionspage_interface.h \
		 settings/optionspage_language.h \
		 settings/optionspage_logging.h \
		 settings/optionspage_passwords.h \
		 settings/optionspage_proxy.h \
		 settings/optionspage_sizeformatting.h \
		 settings/optionspage_themes.h \
		 settings/optionspage_transfer.h \
		 settings/optionspage_updatecheck.h \
		 settings/settingsdialog.h \
		 sftp_crypt_info_dlg.h \
		 sitemanager.h \
		 sitemanager_dialog.h \
		 sitemanager_site.h \
		 sizeformatting.h \
		 speedlimits_dialog.h \
		 splitter.h \
		 state.h \
		 statuslinectrl.h \
		 statusbar.h \
		 StatusView.h \
		 systemimagelist.h \
		 textctrlex.h \
		 themeprovider.h \
		 timeformatting.h \
		 toolbar.h \
		 treectrlex.h \
		 updater.h \
		 update_dialog.h \
		 verifycertdialog.h \
		 verifyhostkeydialog.h \
		 view.h \
		 viewheader.h \
		 volume_enumerator.h \
		 welcome_dialog.h \
		 window_state_manager.h \
		 wrapengine.h \
		 wxfilesystem_blob_handler.h \
		 xh_text_ex.h \
		 xmlfunctions.h \
		 xrc_helper.h

if ENABLE_STORJ
filezilla_SOURCES += \
		overlay.cpp \
		storj_key_interface.cpp

noinst_HEADERS += \
		 overlay.h \
		 storj_key_interface.h
endif

if USE_RESOURCEFILE
RESOURCEFILE = resources/filezilla.o
endif

filezilla_DEPENDENCIES = ../engine/libengine.a

filezilla_CPPFLAGS = -I$(srcdir)/../include
filezilla_CPPFLAGS += $(LIBFILEZILLA_CFLAGS)
filezilla_CPPFLAGS += $(NETTLE_CFLAGS)
filezilla_CPPFLAGS += $(WX_CPPFLAGS)
filezilla_CXXFLAGS = $(WX_CXXFLAGS_ONLY)
filezilla_CFLAGS = $(WX_CFLAGS_ONLY)

filezilla_LDFLAGS = ../engine/libengine.a $(LIBFILEZILLA_LIBS)
filezilla_LDFLAGS += $(PUGIXML_LIBS)
filezilla_LDFLAGS += $(NETTLE_LIBS) $(HOGWEED_LIBS)
filezilla_LDFLAGS += $(LIBGNUTLS_LIBS)

if HAVE_DBUS
filezilla_DEPENDENCIES += ../dbus/libfzdbus.a
filezilla_LDFLAGS += ../dbus/libfzdbus.a $(LIBDBUS_LIBS)
endif

filezilla_LDFLAGS += $(WX_LIBS)
filezilla_LDFLAGS += $(RESOURCEFILE)
filezilla_LDFLAGS += $(IDN_LIB)

filezilla_CPPFLAGS += $(LIBSQLITE3_CFLAGS)
filezilla_LDFLAGS += $(LIBSQLITE3_LIBS)

if MINGW
filezilla_LDFLAGS += -lnormaliz -lole32 -luuid -lnetapi32 -lmpr -lpowrprof -lws2_32
endif

# GTK+ libs, empty if not using wxGTK
filezilla_CPPFLAGS += $(LIBGTK_CFLAGS)
filezilla_LDFLAGS += $(LIBGTK_LIBS)

if MINGW
filezilla_DEPENDENCIES += resources/filezilla.o
endif

if HAVE_LIBPUGIXML
else
filezilla_DEPENDENCIES += $(PUGIXML_LIBS)
endif

dist_noinst_DATA = interface.vcxproj

if MACAPPBUNDLE
noinst_DATA = $(top_builddir)/FileZilla.app/Contents/MacOS/filezilla$(EXEEXT)

if USE_MAC_SANDBOX
filezilla_SOURCES += osx_sandbox_userdirs.cpp
noinst_HEADERS += osx_sandbox_userdirs.h
endif

filezilla_SOURCES += file_utils_osx.m power_management_osx.m

endif

$(top_builddir)/FileZilla.app/Contents/MacOS/filezilla$(EXEEXT): filezilla
	mkdir -p $(top_builddir)/FileZilla.app/Contents/MacOS
	mkdir -p $(top_builddir)/FileZilla.app/Contents/SharedSupport/resources
	mkdir -p $(top_builddir)/FileZilla.app/Contents/Resources
	$(MAKE) -C resources mac-copy-resources
	cp -f filezilla $(top_builddir)/FileZilla.app/Contents/MacOS/filezilla
	cp -f $(top_srcdir)/COPYING $(top_builddir)/FileZilla.app/Contents/SharedSupport/COPYING
	mkdir -p $(top_builddir)/FileZilla.app/Contents/docs
	cp -f $(top_srcdir)/docs/fzdefaults.xml.example $(top_builddir)/FileZilla.app/Contents/docs/fzdefaults.xml.example
	cp -f $(top_srcdir)/docs/*.man $(top_builddir)/FileZilla.app/Contents/docs

CLEANFILES = filezilla.h.gch
MAINTAINERCLEANFILES = ./$(DEPDIR)/filezilla.Po
if ENABLE_PRECOMP

BUILT_SOURCES = filezilla.h.gch

-include ./$(DEPDIR)/filezilla.Po

filezilla.h.gch: filezilla.h
	if $(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(filezilla_CPPFLAGS) $(CPPFLAGS) $(filezilla_CXXFLAGS) $(CXXFLAGS) -MT $@ -MD -MP -MF "$(DEPDIR)/$*.Tpo" -c -o "$@" $<; \
	then mv -f "$(DEPDIR)/$*.Tpo" "$(DEPDIR)/$*.Po"; else rm -f "$(DEPDIR)/$*.Tpo"; exit 1; fi

endif

