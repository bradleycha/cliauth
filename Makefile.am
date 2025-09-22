#------------------------------------------------------------------------------#
#                       Copyright (c) CliAuth 2024, 2025                       #
#                    https://github.com/bradleycha/cliauth                     #
#------------------------------------------------------------------------------#
# Makefile.am - GNU Automake script                                            #
#------------------------------------------------------------------------------#

ACLOCAL_AMFLAGS = -I build/m4

bin_PROGRAMS = \
	cliauth
noinst_PROGRAMS = \
	cliauth_test
lib_LTLIBRARIES = \
	libcliauth.la

AM_CFLAGS = \
	-I$(top_srcdir)/src \
	-std=c89 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Werror

libcliauth_la_LDFLAGS = \
	-release $(PACKAGE_VERSION)

cliauth_LDADD = \
	$(top_builddir)/libcliauth.la
cliauth_test_LDADD = \
	$(top_builddir)/libcliauth.la

cliauth_SOURCES = \
	src/cliauth.c

cliauth_test_SOURCES = \
	src/test/cliauth_test.c \
	src/test/cliauth_test.h \
	src/test/crypto/crypto.c \
	src/test/crypto/crypto.h \
	src/test/crypto/i_hash.c \
	src/test/crypto/i_hash.h \
	src/test/crypto/i_mac.c \
	src/test/crypto/i_mac.h

libcliauth_includedir = $(pkgincludedir)
libcliauth_arch_includedir = $(libcliauth_includedir)/arch
libcliauth_arch_amd64_includedir = $(libcliauth_arch_includedir)/amd64
libcliauth_arch_amd64_memory_includedir = $(libcliauth_arch_amd64_includedir)/memory
libcliauth_arch_ia32_includedir = $(libcliauth_arch_includedir)/ia32
libcliauth_arch_ia32_memory_includedir = $(libcliauth_arch_ia32_includedir)/memory
libcliauth_crypto_includedir = $(libcliauth_includedir)/crypto
libcliauth_database_includedir = $(libcliauth_includedir)/database
libcliauth_io_includedir = $(libcliauth_includedir)/io
libcliauth_io_parse_includedir = $(libcliauth_io_includedir)/parse
libcliauth_math_includedir = $(libcliauth_includedir)/math
libcliauth_memory_includedir = $(libcliauth_includedir)/memory
libcliauth_ui_includedir = $(libcliauth_includedir)/ui

libcliauth_la_SOURCES = \
	src/cliauth/arch/amd64/instruction.c \
	src/cliauth/arch/amd64/memory/endian.c \
	src/cliauth/arch/ia32/instruction.c \
	src/cliauth/arch/ia32/memory/endian.c \
	src/cliauth/crypto/hash.c \
	src/cliauth/crypto/mac.c \
	src/cliauth/crypto/otp.c \
	src/cliauth/database/account.c \
	src/cliauth/io/buffered_stream.c \
	src/cliauth/io/byte_array_mapper.c \
	src/cliauth/io/io.c \
	src/cliauth/io/mapper_stream.c \
	src/cliauth/io/log.c \
	src/cliauth/io/parse/i_digit_to_integer.c \
	src/cliauth/io/parse/string_block_data.c \
	src/cliauth/io/parse/string_integer.c \
	src/cliauth/math/bitwise.c \
	src/cliauth/memory/endian.c \
	src/cliauth/memory/memory.c \
	src/cliauth/ui/args.c
nodist_libcliauth_include_HEADERS = \
	$(top_builddir)/build/cliauth/config.h
libcliauth_include_HEADERS = \
	src/cliauth/cliauth.h \
	src/cliauth/imports.h \
	src/cliauth/types.h
libcliauth_arch_amd64_include_HEADERS = \
	src/cliauth/arch/amd64/instruction.h
libcliauth_arch_amd64_memory_include_HEADERS = \
	src/cliauth/arch/amd64/memory/endian.h
libcliauth_arch_ia32_include_HEADERS = \
	src/cliauth/arch/ia32/instruction.h
libcliauth_arch_ia32_memory_include_HEADERS = \
	src/cliauth/arch/ia32/memory/endian.h
libcliauth_crypto_include_HEADERS = \
	src/cliauth/crypto/hash.h \
	src/cliauth/crypto/mac.h \
	src/cliauth/crypto/otp.h
libcliauth_database_include_HEADERS = \
	src/cliauth/database/account.h
libcliauth_io_include_HEADERS = \
	src/cliauth/io/buffered_stream.h \
	src/cliauth/io/byte_array_mapper.h \
	src/cliauth/io/io.h \
	src/cliauth/io/mapper_stream.h \
	src/cliauth/io/log.h
libcliauth_io_parse_include_HEADERS = \
	src/cliauth/io/parse/i_digit_to_integer.h \
	src/cliauth/io/parse/string_block_data.h \
	src/cliauth/io/parse/string_integer.h
libcliauth_math_include_HEADERS = \
	src/cliauth/math/bitwise.h
libcliauth_memory_include_HEADERS = \
	src/cliauth/memory/endian.h \
	src/cliauth/memory/memory.h
libcliauth_ui_include_HEADERS = \
	src/cliauth/ui/args.h

