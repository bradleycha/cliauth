#------------------------------------------------------------------------------#
#                          Copyright (c) CliAuth 2024                          #
#                    https://github.com/bradleycha/cliauth                     #
#------------------------------------------------------------------------------#
# configure.ac - GNU Autoconf script                                           #
#------------------------------------------------------------------------------#

AC_INIT([cliauth], 0.1.1, [bradleycha@proton.me])

AC_CONFIG_SRCDIR([src/cliauth.c])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_HEADERS([build/config.h])

AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC

AC_CHECK_FUNCS([memcpy])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([memcmp])

config_enable_platform_integer_sign_is_sign_magnitude=0
config_enable_platform_integer_sign_is_ones_complement=0
config_enable_platform_integer_sign_is_twos_complement=0
config_enable_platform_endian_is_be=0
config_enable_feature_optional_library_imports=0
config_enable_feature_ansi=0
config_enable_feature_log_origin=0
config_enable_feature_hash_sha1=0
config_enable_feature_hash_sha2_224=0
config_enable_feature_hash_sha2_256=0
config_enable_feature_hash_sha2_384=0
config_enable_feature_hash_sha2_512=0
config_enable_feature_hash_sha2_512_224=0
config_enable_feature_hash_sha2_512_256=0
config_enable_feature_io_buffering=0

# TODO: figure out how to detect this from the target platform
# pretty much every processor since the 70's uses two's complement, so for now
# this is a safe default to use.
config_enable_platform_integer_sign_is_sign_magnitude=0
config_enable_platform_integer_sign_is_ones_complement=0
config_enable_platform_integer_sign_is_twos_complement=1

# TODO: avoid copy+pasting descriptions
# TODO: figure out how to set some features to default to '1'

AC_C_BIGENDIAN(
   [config_enable_platform_endian_is_be=1],
   [config_enable_platform_endian_is_be=0],
)
AC_ARG_ENABLE([optional-library-imports],
   AS_HELP_STRING([--enable-optional-library-imports], [Use optional library functions where possible]),
   [config_enable_feature_optional_library_imports=1],
   [config_enable_feature_optional_library_imports=0]
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
   AS_HELP_STRING([--enable-hash-sha1], [Enable support for the SHA1 hash algorithm]),
   [config_enable_feature_hash_sha1=1],
   [config_enable_feature_hash_sha1=0]
)
AC_ARG_ENABLE([hash-sha2-224],
   AS_HELP_STRING([--enable-hash-sha2-224], [Enable support for the SHA2-224 hash algorithm]),
   [config_enable_feature_hash_sha2_224=1],
   [config_enable_feature_hash_sha2_224=0]
)
AC_ARG_ENABLE([hash-sha2-256],
   AS_HELP_STRING([--enable-hash-sha2-256], [Enable support for the SHA2-256 hash algorithm]),
   [config_enable_feature_hash_sha2_256=1],
   [config_enable_feature_hash_sha2_256=0]
)
AC_ARG_ENABLE([hash-sha2-384],
   AS_HELP_STRING([--enable-hash-sha2-384], [Enable support for the SHA2-384 hash algorithm]),
   [config_enable_feature_hash_sha2_384=1],
   [config_enable_feature_hash_sha2_384=0]
)
AC_ARG_ENABLE([hash-sha2-512],
   AS_HELP_STRING([--enable-hash-sha2-512], [Enable support for the SHA2-512 hash algorithm]),
   [config_enable_feature_hash_sha2_512=1],
   [config_enable_feature_hash_sha2_512=0]
)
AC_ARG_ENABLE([hash-sha2-512-224],
   AS_HELP_STRING([--enable-hash-sha2-512-224], [Enable support for the SHA2-512-224 hash algorithm]),
   [config_enable_feature_hash_sha2_512_224=1],
   [config_enable_feature_hash_sha2_512_224=0]
)
AC_ARG_ENABLE([hash-sha2-512-256],
   AS_HELP_STRING([--enable-hash-sha2-512-256], [Enable support for the SHA2-512-256 hash algorithm]),
   [config_enable_feature_hash_sha2_512_256=1],
   [config_enable_feature_hash_sha2_512_256=0]
)
AC_ARG_ENABLE([io-buffering],
   AS_HELP_STRING([--enable-io-buffering], [Enable support for file IO buffering]),
   [config_enable_feature_io_buffering=1],
   [config_enable_feature_io_buffering=0]
)

AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE],
   [$config_enable_platform_integer_sign_is_sign_magnitude],
   [Whether the target platform uses sign-magnitude to represent signed integers or not]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT],
   [$config_enable_platform_integer_sign_is_ones_complement],
   [Whether the target platform uses one's complement to represent signed integers or not]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT],
   [$config_enable_platform_integer_sign_is_twos_complement],
   [Whether the target platform uses two's complement to represent signed integers or not]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE],
   [$config_enable_platform_endian_is_be],
   [Whether the target platform is big-endian or not]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_OPTIONAL_LIBRARY_IMPORTS],
   [$config_enable_feature_optional_library_imports],
   [Use optional library functions where possible]
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
   [Enable support for the SHA1 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA2_224],
   [$config_enable_feature_hash_sha2_224],
   [Enable support for the SHA2-224 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA2_256],
   [$config_enable_feature_hash_sha2_256],
   [Enable support for the SHA2-256 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA2_384],
   [$config_enable_feature_hash_sha2_384],
   [Enable support for the SHA2-384 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA2_512],
   [$config_enable_feature_hash_sha2_512],
   [Enable support for the SHA2-512 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA2_512_224],
   [$config_enable_feature_hash_sha2_512_224],
   [Enable support for the SHA2-512-224 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_HASH_SHA2_512_256],
   [$config_enable_feature_hash_sha2_512_256],
   [Enable support for the SHA2-512-256 hash algorithm]
)
AC_DEFINE_UNQUOTED([CLIAUTH_CONFIG_IO_BUFFERING],
   [$config_enable_feature_io_buffering],
   [Enable support for file IO buffering]
)

AC_OUTPUT

