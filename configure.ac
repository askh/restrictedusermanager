#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([restrictedusermanager], [0.0], [askh@askh.ru])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/restrictedusermanager.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# AC_PROG_LIBTOOL
LT_INIT

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
# AX_BOOST_BASE([1.74], [], [AC_MSG_ERROR(Could not find the boost library)])
BOOST_REQUIRE
BOOST_PROGRAM_OPTIONS

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
