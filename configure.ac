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

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC

# TODO: Make these less reduntant - no copy+paste!
# TODO: Figure out how to set some of these to default on
AC_ARG_ENABLE([log-ansi],
   [AS_HELP_STRING([Use ANSI escape sequences to color log messages])],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ANSI], [1], [Use ANSI escape sequences to color log messages])],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ANSI], [0], [Use ANSI escape sequences to color log messages])]
)
AC_ARG_ENABLE([log-origin],
   [AS_HELP_STRING([Include the location in source code every log message originates from])],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ORIGIN], [1], [Include the location in source code every log message originates from])],
   [AC_DEFINE([CLIAUTH_CONFIG_LOG_ORIGIN], [0], [Include the location in source code every log message originates from])]
)
AC_ARG_ENABLE([hash-sha224],
   [AS_HELP_STRING([Enable support for the SHA-224 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA224], [1], [Enable support for the SHA-224 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA224], [0], [Enable support for the SHA-224 hash algorithm])]
)
AC_ARG_ENABLE([hash-sha256],
   [AS_HELP_STRING([Enable support for the SHA-256 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA256], [1], [Enable support for the SHA-256 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA256], [0], [Enable support for the SHA-256 hash algorithm])]
)
AC_ARG_ENABLE([hash-sha384],
   [AS_HELP_STRING([Enable support for the SHA-384 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA384], [1], [Enable support for the SHA-384 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA384], [0], [Enable support for the SHA-384 hash algorithm])]
)
AC_ARG_ENABLE([hash-sha512],
   [AS_HELP_STRING([Enable support for the SHA-512 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA512], [1], [Enable support for the SHA-512 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA512], [0], [Enable support for the SHA-512 hash algorithm])]
)
AC_ARG_ENABLE([hash-sha512-224],
   [AS_HELP_STRING([Enable support for the SHA-512-224 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA512_224], [1], [Enable support for the SHA-512-224 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA512_224], [0], [Enable support for the SHA-512-224 hash algorithm])]
)
AC_ARG_ENABLE([hash-sha512-256],
   [AS_HELP_STRING([Enable support for the SHA-512-256 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA512_256], [1], [Enable support for the SHA-512-256 hash algorithm])],
   [AC_DEFINE([CLIAUTH_CONFIG_HASH_SHA512_256], [0], [Enable support for the SHA-512-256 hash algorithm])]
)

# TODO: Detect this from the target, maybe use $target_cpu?
AC_DEFINE([CLIAUTH_CONFIG_ENDIAN_PLATFORM_IS_BE], [0], [Whether the target platform is big-endian or not])

AC_OUTPUT

