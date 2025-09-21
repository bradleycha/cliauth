/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/math/bitwise.h - Various bitwise operations.                   */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_MATH_BITWISE_H
#define _CLIAUTH_MATH_BITWISE_H
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"

/*----------------------------------------------------------------------------*/
/* Performs a bitwise rotation.                                               */
/*----------------------------------------------------------------------------*/
/* value -                                                                    */
/*    The number to perform the rotation on.                                  */
/*                                                                            */
/* bits -                                                                     */
/*    The amount of bits to rotate by.                                        */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The value after bitwise rotation.                                       */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_math_bitwise_rotate_left_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 bits
);
CliAuthUInt16
cliauth_math_bitwise_rotate_left_uint16(
   CliAuthUInt16 value,
   CliAuthUInt8 bits
);
CliAuthUInt32
cliauth_math_bitwise_rotate_left_uint32(
   CliAuthUInt32 value,
   CliAuthUInt8 bits
);
CliAuthUInt64
cliauth_math_bitwise_rotate_left_uint64(
   CliAuthUInt64 value,
   CliAuthUInt8 bits
);
CliAuthUInt8
cliauth_math_bitwise_rotate_right_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 bits
);
CliAuthUInt16
cliauth_math_bitwise_rotate_right_uint16(
   CliAuthUInt16 value,
   CliAuthUInt8 bits
);
CliAuthUInt32
cliauth_math_bitwise_rotate_right_uint32(
   CliAuthUInt32 value,
   CliAuthUInt8 bits
);
CliAuthUInt64
cliauth_math_bitwise_rotate_right_uint64(
   CliAuthUInt64 value,
   CliAuthUInt8 bits
);

/*----------------------------------------------------------------------------*/
/* Converts a magnitude to its negative signed integer representation.        */
/*----------------------------------------------------------------------------*/
/* magnitude -                                                                */
/*    The magnitude of the number to convert.  The magnitude must be within   */
/*    the range of representable values for the given type.                   */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The signed integer representation of the magnitude.                     */
/*----------------------------------------------------------------------------*/
CliAuthSInt8
cliauth_math_bitwise_magnitude_deposit_negative_sint8(
   CliAuthUInt8 magnitude
);
CliAuthSInt16
cliauth_math_bitwise_magnitude_deposit_negative_sint16(
   CliAuthUInt16 magnitude
);
CliAuthSInt32
cliauth_math_bitwise_magnitude_deposit_negative_sint32(
   CliAuthUInt32 magnitude
);
CliAuthSInt64
cliauth_math_bitwise_magnitude_deposit_negative_sint64(
   CliAuthUInt64 magnitude
);

/*----------------------------------------------------------------------------*/
/* Extract the magnitude of a negative signed integer.                        */
/*----------------------------------------------------------------------------*/
/* value -                                                                    */
/*    The number to extract the magnitude from.                               */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The magnitude of the value.                                             */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_math_bitwise_magnitude_extract_negative_sint8(
   CliAuthSInt8 value
);
CliAuthUInt16
cliauth_math_bitwise_magnitude_extract_negative_sint16(
   CliAuthSInt16 value
);
CliAuthUInt32
cliauth_math_bitwise_magnitude_extract_negative_sint32(
   CliAuthSInt32 value
);
CliAuthUInt64
cliauth_math_bitwise_magnitude_extract_negative_sint64(
   CliAuthSInt64 value
);

/*----------------------------------------------------------------------------*/
/* Sets bitwise boolean flags in a value.                                     */
/*----------------------------------------------------------------------------*/
/* value -                                                                    */
/*    The base value to set flags in.                                         */
/*                                                                            */
/* flags -                                                                    */
/*    The bit flags to set.                                                   */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of setting bits from 'flags' in 'value'.                     */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_math_bitwise_flags_set_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 flags
);
CliAuthUInt16
cliauth_math_bitwise_flags_set_uint16(
   CliAuthUInt16 value,
   CliAuthUInt16 flags
);
CliAuthUInt32
cliauth_math_bitwise_flags_set_uint32(
   CliAuthUInt32 value,
   CliAuthUInt32 flags
);
CliAuthUInt64
cliauth_math_bitwise_flags_set_uint64(
   CliAuthUInt64 value,
   CliAuthUInt64 flags
);

/*----------------------------------------------------------------------------*/
/* Clears bitwise boolean flags in a value.                                   */
/*----------------------------------------------------------------------------*/
/* value -                                                                    */
/*    The base value to clear flags in.                                       */
/*                                                                            */
/* flags -                                                                    */
/*    The bit flags to clear.                                                 */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of clearing bits from 'flags' in 'value'.                    */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_math_bitwise_flags_clear_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 flags
);
CliAuthUInt16
cliauth_math_bitwise_flags_clear_uint16(
   CliAuthUInt16 value,
   CliAuthUInt16 flags
);
CliAuthUInt32
cliauth_math_bitwise_flags_clear_uint32(
   CliAuthUInt32 value,
   CliAuthUInt32 flags
);
CliAuthUInt64
cliauth_math_bitwise_flags_clear_uint64(
   CliAuthUInt64 value,
   CliAuthUInt64 flags
);

/*----------------------------------------------------------------------------*/
/* Flips bitwise boolean flags in a value.                                    */
/*----------------------------------------------------------------------------*/
/* value -                                                                    */
/*    The base value to flip flags in.                                        */
/*                                                                            */
/* flags -                                                                    */
/*    The bit flags to flip.                                                  */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of flipping bits from 'flags' in 'value'.                    */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_math_bitwise_flags_flip_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 flags
);
CliAuthUInt16
cliauth_math_bitwise_flags_flip_uint16(
   CliAuthUInt16 value,
   CliAuthUInt16 flags
);
CliAuthUInt32
cliauth_math_bitwise_flags_flip_uint32(
   CliAuthUInt32 value,
   CliAuthUInt32 flags
);
CliAuthUInt64
cliauth_math_bitwise_flags_flip_uint64(
   CliAuthUInt64 value,
   CliAuthUInt64 flags
);

/*----------------------------------------------------------------------------*/
/* Checks if any of the specified boolean flags are set.                      */
/*----------------------------------------------------------------------------*/
/* value -                                                                    */
/*    The value to compare.                                                   */
/*                                                                            */
/* flags -                                                                    */
/*    The bit flags to check for.                                             */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    Whether at least one of the flags specified in 'flags' is set in        */
/*    'value'.                                                                */
/*----------------------------------------------------------------------------*/
CliAuthBoolean
cliauth_math_bitwise_flags_check_one_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 flags
);
CliAuthBoolean
cliauth_math_bitwise_flags_check_one_uint16(
   CliAuthUInt16 value,
   CliAuthUInt16 flags
);
CliAuthBoolean
cliauth_math_bitwise_flags_check_one_uint32(
   CliAuthUInt32 value,
   CliAuthUInt32 flags
);
CliAuthBoolean
cliauth_math_bitwise_flags_check_one_uint64(
   CliAuthUInt64 value,
   CliAuthUInt64 flags
);

/*----------------------------------------------------------------------------*/
/* Checks if all of the specified boolean flags are set.                      */
/*----------------------------------------------------------------------------*/
/* value -                                                                    */
/*    The value to compare.                                                   */
/*                                                                            */
/* flags -                                                                    */
/*    The bit flags to check for.                                             */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    Whether all of the flags specified in 'flags' are set in 'value'.       */
/*----------------------------------------------------------------------------*/
CliAuthBoolean
cliauth_math_bitwise_flags_check_all_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 flags
);
CliAuthBoolean
cliauth_math_bitwise_flags_check_all_uint16(
   CliAuthUInt16 value,
   CliAuthUInt16 flags
);
CliAuthBoolean
cliauth_math_bitwise_flags_check_all_uint32(
   CliAuthUInt32 value,
   CliAuthUInt32 flags
);
CliAuthBoolean
cliauth_math_bitwise_flags_check_all_uint64(
   CliAuthUInt64 value,
   CliAuthUInt64 flags
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_MATH_BITWISE_H */

