/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/bitwise.h - Header for various bitwise operations.                    */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_BITWISE_H
#define _CLIAUTH_BITWISE_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

/*----------------------------------------------------------------------------*/
/* Performs a bitwise rotation .  The sign bit is not extended for signed     */
/* integers.                                                                  */
/*----------------------------------------------------------------------------*/
/* value - The number to perform the rotation on.                             */
/*                                                                            */
/* bits - The amount of bits to rotate by.                                    */
/*                                                                            */
/* Return value - The value after bitwise rotation.                           */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_bitwise_rotate_left_uint8(CliAuthUInt8 value, CliAuthUInt8 bits);
CliAuthUInt16
cliauth_bitwise_rotate_left_uint16(CliAuthUInt16 value, CliAuthUInt8 bits);
CliAuthUInt32
cliauth_bitwise_rotate_left_uint32(CliAuthUInt32 value, CliAuthUInt8 bits);
CliAuthUInt64
cliauth_bitwise_rotate_left_uint64(CliAuthUInt64 value, CliAuthUInt8 bits);
CliAuthUInt8
cliauth_bitwise_rotate_right_uint8(CliAuthUInt8 value, CliAuthUInt8 bits);
CliAuthUInt16
cliauth_bitwise_rotate_right_uint16(CliAuthUInt16 value, CliAuthUInt8 bits);
CliAuthUInt32
cliauth_bitwise_rotate_right_uint32(CliAuthUInt32 value, CliAuthUInt8 bits);
CliAuthUInt64
cliauth_bitwise_rotate_right_uint64(CliAuthUInt64 value, CliAuthUInt8 bits);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_BITWISE_H */

