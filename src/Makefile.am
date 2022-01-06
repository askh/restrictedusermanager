bin_PROGRAMS = restrictedusermanager
restrictedusermanager_SOURCES = restrictedusermanager.cpp
restrictedusermanager_CPPFLAGS = $(BOOST_CPPFLAGS) $(YAMLCPP_CPPFLAGS) -pthread -DBOOST_LOG_DYN_LINK
# restrictedusermanager_LDFLAGS = $(BOOST_PROGRAM_OPTIONS_LDFLAGS) $(YAMLCPP_LIBS)
restrictedusermanager_LDADD = $(BOOST_IOSTREAMS_LIBS) $(BOOST_LOG_LIBS) $(BOOST_LOG_SETUP_LIBS) $(BOOST_OPTIONAL_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS) $(BOOST_SYSTEM_LIBS) $(YAMLCPP_LIBS) -lpthread -lstdc++fs

install-exec-hook:
	chmod 4755 $(DESTDIR)$(bindir)/restrictedusermanager
