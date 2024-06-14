/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/bitwise.c - Implementations for bitwise operations.                    */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "bitwise.h"

#define CLIAUTH_BITWISE_ROTATE_LEFT(bitwidth, value, bits)\
   ((value << bits) | (value >> (bitwidth - bits)))

#define CLIAUTH_BITWISE_ROTATE_RIGHT(bitwidth, value, bits)\
   ((value >> bits) | (value << (bitwidth - bits)))

CliAuthUInt8
cliauth_bitwise_rotate_left_uint8(CliAuthUInt8 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(8, value, bits);
}

CliAuthUInt16
cliauth_bitwise_rotate_left_uint16(CliAuthUInt16 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(16, value, bits);
}

CliAuthUInt32
cliauth_bitwise_rotate_left_uint32(CliAuthUInt32 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(32, value, bits);
}

CliAuthUInt64
cliauth_bitwise_rotate_left_uint64(CliAuthUInt64 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(64, value, bits);
}

CliAuthUInt8
cliauth_bitwise_rotate_right_uint8(CliAuthUInt8 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(8, value, bits);
}

CliAuthUInt16
cliauth_bitwise_rotate_right_uint16(CliAuthUInt16 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(16, value, bits);
}

CliAuthUInt32
cliauth_bitwise_rotate_right_uint32(CliAuthUInt32 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(32, value, bits);
}

CliAuthUInt64
cliauth_bitwise_rotate_right_uint64(CliAuthUInt64 value, CliAuthUInt8 bits) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(64, value, bits);
}

