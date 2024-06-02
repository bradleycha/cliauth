#------------------------------------------------------------------------------#
#                          Copyright (c) CliAuth 2024                          #
#                    https://github.com/bradleycha/cliauth                     #
#------------------------------------------------------------------------------#
# configure.ac - GNU Autoconf script                                           #
#------------------------------------------------------------------------------#

AC_INIT([cliauth], 0.1.0+setup, [bradleycha@proton.me])

AC_CONFIG_SRCDIR([src/cliauth.c])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_HEADERS([build/config.h])

AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC

AC_ARG_ENABLE([log-ansi],
   [AS_HELP_STRING([Use ANSI escape sequences to color log messages])],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ANSI], [1], [Use ANSI escape sequences to color log messages])],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ANSI], [0], [Use ANSI escape sequences to color log messages])]
)
AC_ARG_ENABLE([log-origin],
   [AS_HELP_STRING(Include the location in source code every log message originates from)],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ORIGIN], [1], [Include the location in source code every log message originates from])],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ORIGIN], [0], [Include the location in source code every log message originates from])]
)

AC_OUTPUT

