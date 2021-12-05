bin_PROGRAMS = restrictedusermanager
restrictedusermanager_SOURCES = restrictedusermanager.cpp
restrictedusermanager_CPPFLAGS = $(BOOST_CPPFLAGS)
restrictedusermanager_LDFLAGS = $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
restrictedusermanager_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

install-exec-hook:
	chmod 4755 $(DESTDIR)$(bindir)/restrictedusermanager
