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
/* Performs a bitwise rotation.                                               */
/*----------------------------------------------------------------------------*/
/* value - The number to perform the rotation on.                             */
/*                                                                            */
/* bits - The amount of bits to rotate by.                                    */
/*----------------------------------------------------------------------------*/
/* Return value - The value after bitwise rotation.                           */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_bitwise_rotate_left_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 bits
);
CliAuthUInt16
cliauth_bitwise_rotate_left_uint16(
   CliAuthUInt16 value,
   CliAuthUInt8 bits
);
CliAuthUInt32
cliauth_bitwise_rotate_left_uint32(
   CliAuthUInt32 value,
   CliAuthUInt8 bits
);
CliAuthUInt64
cliauth_bitwise_rotate_left_uint64(
   CliAuthUInt64 value,
   CliAuthUInt8 bits
);
CliAuthUInt8
cliauth_bitwise_rotate_right_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 bits
);
CliAuthUInt16
cliauth_bitwise_rotate_right_uint16(
   CliAuthUInt16 value,
   CliAuthUInt8 bits
);
CliAuthUInt32
cliauth_bitwise_rotate_right_uint32(
   CliAuthUInt32 value,
   CliAuthUInt8 bits
);
CliAuthUInt64
cliauth_bitwise_rotate_right_uint64(
   CliAuthUInt64 value,
   CliAuthUInt8 bits
);

/*----------------------------------------------------------------------------*/
/* Converts a magnitude to its negative signed integer representation.        */
/*----------------------------------------------------------------------------*/
/* magnitude - The magnitude of the number to convert.  The magnitude must be */
/*             within the range of representable values for the given type.   */
/*----------------------------------------------------------------------------*/
/* Return value - The signed integer representation of the magnitude.         */
/*----------------------------------------------------------------------------*/
CliAuthSInt8
cliauth_bitwise_magnitude_deposit_negative_sint8(
   CliAuthUInt8 magnitude
);
CliAuthSInt16
cliauth_bitwise_magnitude_deposit_negative_sint16(
   CliAuthUInt16 magnitude
);
CliAuthSInt32
cliauth_bitwise_magnitude_deposit_negative_sint32(
   CliAuthUInt32 magnitude
);
CliAuthSInt64
cliauth_bitwise_magnitude_deposit_negative_sint64(
   CliAuthUInt64 magnitude
);

/*----------------------------------------------------------------------------*/
/* Extract the magnitude of a negative signed integer.                        */
/*----------------------------------------------------------------------------*/
/* value - The number to extract the magnitude from.                          */
/*----------------------------------------------------------------------------*/
/* Return value - The magnitude of the value.                                 */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_bitwise_magnitude_extract_negative_sint8(
   CliAuthSInt8 value
);
CliAuthUInt16
cliauth_bitwise_magnitude_extract_negative_sint16(
   CliAuthSInt16 value
);
CliAuthUInt32
cliauth_bitwise_magnitude_extract_negative_sint32(
   CliAuthSInt32 value
);
CliAuthUInt64
cliauth_bitwise_magnitude_extract_negative_sint64(
   CliAuthSInt64 value
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_BITWISE_H */

