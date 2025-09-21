#------------------------------------------------------------------------------#
#                       Copyright (c) CliAuth 2024, 2025                       #
#                    https://github.com/bradleycha/cliauth                     #
#------------------------------------------------------------------------------#
# Makefile.am - GNU Automake script                                            #
#------------------------------------------------------------------------------#

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = \
	cliauth

cliauth_CFLAGS = \
	-I$(top_srcdir)/src \
	-std=c89 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Werror

cliauth_includedir = $(pkgincludedir)
cliauth_arch_includedir = $(cliauth_includedir)/arch
cliauth_arch_amd64_includedir = $(cliauth_arch_includedir)/amd64
cliauth_arch_amd64_memory_includedir = $(cliauth_arch_amd64_includedir)/memory
cliauth_arch_ia32_includedir = $(cliauth_arch_includedir)/ia32
cliauth_arch_ia32_memory_includedir = $(cliauth_arch_ia32_includedir)/memory
cliauth_crypto_includedir = $(cliauth_includedir)/crypto
cliauth_database_includedir = $(cliauth_includedir)/database
cliauth_io_includedir = $(cliauth_includedir)/io
cliauth_io_parse_includedir = $(cliauth_io_includedir)/parse
cliauth_math_includedir = $(cliauth_includedir)/math
cliauth_memory_includedir = $(cliauth_includedir)/memory
cliauth_ui_includedir = $(cliauth_includedir)/ui

cliauth_SOURCES = \
	src/cliauth.c \
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
nodist_cliauth_include_HEADERS = \
	$(top_builddir)/build/cliauth/config.h
cliauth_include_HEADERS = \
	src/cliauth/cliauth.h \
	src/cliauth/imports.h \
	src/cliauth/types.h
cliauth_arch_amd64_include_HEADERS = \
	src/cliauth/arch/amd64/instruction.h
cliauth_arch_amd64_memory_include_HEADERS = \
	src/cliauth/arch/amd64/memory/endian.h
cliauth_arch_ia32_include_HEADERS = \
	src/cliauth/arch/ia32/instruction.h
cliauth_arch_ia32_memory_include_HEADERS = \
	src/cliauth/arch/ia32/memory/endian.h
cliauth_crypto_include_HEADERS = \
	src/cliauth/crypto/hash.h \
	src/cliauth/crypto/mac.h \
	src/cliauth/crypto/otp.h
cliauth_database_include_HEADERS = \
	src/cliauth/database/account.h
cliauth_io_include_HEADERS = \
	src/cliauth/io/buffered_stream.h \
	src/cliauth/io/byte_array_mapper.h \
	src/cliauth/io/io.h \
	src/cliauth/io/mapper_stream.h \
	src/cliauth/io/log.h
cliauth_io_parse_include_HEADERS = \
	src/cliauth/io/parse/i_digit_to_integer.h \
	src/cliauth/io/parse/string_block_data.h \
	src/cliauth/io/parse/string_integer.h
cliauth_math_include_HEADERS = \
	src/cliauth/math/bitwise.h
cliauth_memory_include_HEADERS = \
	src/cliauth/memory/endian.h \
	src/cliauth/memory/memory.h
cliauth_ui_include_HEADERS = \
	src/cliauth/ui/args.h

