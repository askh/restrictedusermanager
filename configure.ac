#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([restrictedusermanager], [0.0], [askh@askh.ru])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/restrictedusermanager.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AX_CXX_COMPILE_STDCXX([17], [ext], [mandatory])

# AC_PROG_LIBTOOL
LT_INIT

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
BOOST_REQUIRE
BOOST_IOSTREAMS
BOOST_LOG
BOOST_LOG_SETUP
BOOST_OPTIONAL
BOOST_PROGRAM_OPTIONS
AM_GNU_GETTEXT([external])

# Checks for header files.
PKG_CHECK_MODULES([YAMLCPP], [yaml-cpp])
AC_CHECK_HEADER([errno.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# AC_SUBST(LOCALEDIR)
AC_DEFINE_UNQUOTED([LOCALEDIR], ["$localedir"], [Locale directory])
# AC_DEFINE([BOOST_LOG_DYN_LINK], [1], [Option for boost])
# AC_DEFINE([BOOST_ALL_DYN_LINK], [1], [Option for boost])

AC_CONFIG_FILES([Makefile src/Makefile po/Makefile.in])
AC_OUTPUT
