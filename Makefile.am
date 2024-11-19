#------------------------------------------------------------------------------#
#                          Copyright (c) CliAuth 2024                          #
#                    https://github.com/bradleycha/cliauth                     #
#------------------------------------------------------------------------------#
# Makefile.am - GNU Automake script                                            #
#------------------------------------------------------------------------------#

bin_PROGRAMS = \
	cliauth

cliauth_CFLAGS = \
	-I$(top_srcdir)/src \
	-std=c89 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Werror

cliauth_SOURCES = \
	src/cliauth.c \
	src/cliauth.h \
	src/imports.h \
	src/types.h \
	src/crypto/mac.c \
	src/crypto/mac.h \
	src/crypto/otp.c \
	src/crypto/otp.h \
	src/crypto/hash/hash.c \
	src/crypto/hash/hash.h \
	src/database/account.c \
	src/database/account.h \
	src/io/buffered_stream.c \
	src/io/buffered_stream.h \
	src/io/byte_array_mapper.c \
	src/io/byte_array_mapper.h \
	src/io/io.c \
	src/io/io.h \
	src/io/mapper_stream.c \
	src/io/mapper_stream.h \
	src/io/log.c \
	src/io/log.h \
	src/io/parse/string_integer.c \
	src/io/parse/string_integer.h \
	src/math/bitwise.c \
	src/math/bitwise.h \
	src/math/endian.c \
	src/math/endian.h \
	src/memory/memory.c \
	src/memory/memory.h \
	src/ui/args.c \
	src/ui/args.h

