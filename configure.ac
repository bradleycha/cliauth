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

config_enable_target_endian_is_be=0
config_enable_feature_ansi=0
config_enable_feature_log_origin=0
config_enable_feature_hash_sha1=0
config_enable_feature_hash_sha224=0
config_enable_feature_hash_sha256=0
config_enable_feature_hash_sha384=0
config_enable_feature_hash_sha512=0
config_enable_feature_hash_sha512_224=0
config_enable_feature_hash_sha512_256=0

# TODO: avoid copy+pasting descriptions

AC_C_BIGENDIAN(
   [config_enable_target_endian_is_be=1],
   [config_enable_target_endian_is_be=0],
)
AC_ARG_ENABLE([ansi],
   AS_HELP_STRING([--enable-ansi], [Enable support for ANSI escape sequences]),
   [config_enable_feature_ansi=1],
   [config_enable_feature_ansi=0]
)
AC_ARG_ENABLE([log-origin],
   AS_HELP_STRING([--enable-log-origin], [Include the location in source code every log message originates from]),
   [config_enable_feature_log_origin=1],
   [config_enable_feature_log_origin=0]
)
AC_ARG_ENABLE([hash-sha1],
   AS_HELP_STRING([--enable-hash-sha1], [Enable support for the SHA-1 hash algorithm]),
   [config_enable_feature_hash_sha1=1],
   [config_enable_feature_hash_sha1=0]
)
AC_ARG_ENABLE([hash-sha224],
   AS_HELP_STRING([--enable-hash-sha224], [Enable support for the SHA-224 hash algorithm]),
   [config_enable_feature_hash_sha224=1],
   [config_enable_feature_hash_sha224=0]
)
AC_ARG_ENABLE([hash-sha256],
   AS_HELP_STRING([--enable-hash-sha256], [Enable support for the SHA-256 hash algorithm]),
   [config_enable_feature_hash_sha256=1],
   [config_enable_feature_hash_sha256=0]
)
AC_ARG_ENABLE([hash-sha384],
   AS_HELP_STRING([--enable-hash-sha384], [Enable support for the SHA-384 hash algorithm]),
   [config_enable_feature_hash_sha384=1],
   [config_enable_feature_hash_sha384=0]
)
AC_ARG_ENABLE([hash-sha512],
   AS_HELP_STRING([--enable-hash-sha512], [Enable support for the SHA-512 hash algorithm]),
   [config_enable_feature_hash_sha512=1],
   [config_enable_feature_hash_sha512=0]
)
AC_ARG_ENABLE([hash-sha512-224],
   AS_HELP_STRING([--enable-hash-sha512-224], [Enable support for the SHA-512-224 hash algorithm]),
   [config_enable_feature_hash_sha512_224=1],
   [config_enable_feature_hash_sha512_224=0]
)
AC_ARG_ENABLE([hash-sha512-256],
   AS_HELP_STRING([--enable-hash-sha512-256], [Enable support for the SHA-512-256 hash algorithm]),
   [config_enable_feature_hash_sha512_256=1],
   [config_enable_feature_hash_sha512_256=0]
)

AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_ENDIAN_PLATFORM_IS_BE],
   [$config_enable_target_endian_is_be],
   [Whether the target platform is big-endian or not]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_ANSI],
   [$config_enable_feature_ansi],
   [Enable support for ANSI escape sequences]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_LOG_ORIGIN],
   [$config_enable_feature_log_origin],
   [Include the location in source code every log message originates from]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA1],
   [$config_enable_feature_hash_sha1],
   [Enable support for the SHA-1 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA224],
   [$config_enable_feature_hash_sha224],
   [Enable support for the SHA-224 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA256],
   [$config_enable_feature_hash_sha256],
   [Enable support for the SHA-256 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA384],
   [$config_enable_feature_hash_sha384],
   [Enable support for the SHA-384 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA512],
   [$config_enable_feature_hash_sha512],
   [Enable support for the SHA-512 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA512_224],
   [$config_enable_feature_hash_sha512_224],
   [Enable support for the SHA-512-224 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA512_256],
   [$config_enable_feature_hash_sha512_256],
   [Enable support for the SHA-512-256 hash algorithm]
)

AC_OUTPUT

