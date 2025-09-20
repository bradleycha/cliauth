#------------------------------------------------------------------------------#
#                       Copyright (c) CliAuth 2024, 2025                       #
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
	src/cliauth/arch/amd64/instruction.c\
	src/cliauth/arch/amd64/instruction.h\
	src/cliauth/arch/amd64/memory/endian.c\
	src/cliauth/arch/amd64/memory/endian.h\
	src/cliauth/arch/ia32/instruction.c\
	src/cliauth/arch/ia32/instruction.h\
	src/cliauth/arch/ia32/memory/endian.c\
	src/cliauth/arch/ia32/memory/endian.h\
	src/cliauth/cliauth.c \
	src/cliauth/cliauth.h \
	src/cliauth/imports.h \
	src/cliauth/types.h \
	src/cliauth/crypto/hash.c \
	src/cliauth/crypto/hash.h \
	src/cliauth/crypto/mac.c \
	src/cliauth/crypto/mac.h \
	src/cliauth/crypto/otp.c \
	src/cliauth/crypto/otp.h \
	src/cliauth/database/account.c \
	src/cliauth/database/account.h \
	src/cliauth/io/buffered_stream.c \
	src/cliauth/io/buffered_stream.h \
	src/cliauth/io/byte_array_mapper.c \
	src/cliauth/io/byte_array_mapper.h \
	src/cliauth/io/io.c \
	src/cliauth/io/io.h \
	src/cliauth/io/mapper_stream.c \
	src/cliauth/io/mapper_stream.h \
	src/cliauth/io/log.c \
	src/cliauth/io/log.h \
	src/cliauth/io/parse/i_digit_to_integer.c \
	src/cliauth/io/parse/i_digit_to_integer.h \
	src/cliauth/io/parse/string_block_data.c \
	src/cliauth/io/parse/string_block_data.h \
	src/cliauth/io/parse/string_integer.c \
	src/cliauth/io/parse/string_integer.h \
	src/cliauth/math/bitwise.c \
	src/cliauth/math/bitwise.h \
	src/cliauth/memory/endian.c \
	src/cliauth/memory/endian.h \
	src/cliauth/memory/memory.c \
	src/cliauth/memory/memory.h \
	src/cliauth/ui/args.c \
	src/cliauth/ui/args.h

