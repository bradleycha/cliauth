/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/bitwise.c - Implementations for bitwise operations.                    */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "bitwise.h"

#define CLIAUTH_BITWISE_ROTATE_LEFT(bitwidth, value, bits)\
   (((value) << (bits)) | ((value) >> ((bitwidth) - (bits))))

#define CLIAUTH_BITWISE_ROTATE_RIGHT(bitwidth, value, bits)\
   (((value) >> (bits)) | ((value) << ((bitwidth) - (bits))))

CliAuthUInt8
cliauth_bitwise_rotate_left_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(
      sizeof(CliAuthUInt8) * 8,
      value,
      bits
   );
}

CliAuthUInt16
cliauth_bitwise_rotate_left_uint16(
   CliAuthUInt16 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(
      sizeof(CliAuthUInt16) * 8,
      value,
      bits
   );
}

CliAuthUInt32
cliauth_bitwise_rotate_left_uint32(
   CliAuthUInt32 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(
      sizeof(CliAuthUInt32) * 8,
      value,
      bits
   );
}

CliAuthUInt64
cliauth_bitwise_rotate_left_uint64(
   CliAuthUInt64 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_LEFT(
      sizeof(CliAuthUInt64) * 8,
      value,
      bits
   );
}

CliAuthUInt8
cliauth_bitwise_rotate_right_uint8(
   CliAuthUInt8 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(
      sizeof(CliAuthUInt8) * 8,
      value,
      bits
   );
}

CliAuthUInt16
cliauth_bitwise_rotate_right_uint16(
   CliAuthUInt16 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(
      sizeof(CliAuthUInt16) * 8,
      value,
      bits
   );
}

CliAuthUInt32
cliauth_bitwise_rotate_right_uint32(
   CliAuthUInt32 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(
      sizeof(CliAuthUInt32) * 8,
      value,
      bits
   );
}

CliAuthUInt64
cliauth_bitwise_rotate_right_uint64(
   CliAuthUInt64 value,
   CliAuthUInt8 bits
) {
   return CLIAUTH_BITWISE_ROTATE_RIGHT(
      sizeof(CliAuthUInt64) * 8,
      value,
      bits
   );
}

static CliAuthSInt64
cliauth_bitwise_magnitude_deposit_negative_sint64_sign_magnitude(
   CliAuthUInt64 magnitude
) {
   union CliAuthInt64 output;

   /* set magnitude bits */
   output.uint = magnitude;
   
   /* set sign bit */
   output.uint |= (((CliAuthUInt64)(1u)) << ((sizeof(CliAuthUInt64) * 8) - 1));

   return output.sint;
}

static CliAuthSInt64
cliauth_bitwise_magnitude_deposit_negative_sint64_ones_complement(
   CliAuthUInt64 magnitude
) {
   union CliAuthInt64 output;

   /* set magnitude bits */
   output.uint = magnitude;

   /* flip the bits for one's complement */
   output.uint = ~output.uint;

   return output.sint;
}

static CliAuthSInt64
cliauth_bitwise_magnitude_deposit_negative_sint64_twos_complement(
   CliAuthUInt64 magnitude
) {
   union CliAuthInt64 output;

   /* set magnitude bits */
   output.uint = magnitude;

   /* decrement for two's complement */
   output.uint -= 1;

   /* flip the bits of the decremented result */
   output.uint = ~output.uint;

   return output.sint;
}

static CliAuthUInt64
cliauth_bitwise_magnitude_extract_negative_sint64_sign_magnitude(
   CliAuthSInt64 value
) {
   union CliAuthInt64 output;

   /* extract the value's bits */
   output.sint = value;

   /* unset the sign bit */
   output.uint &= ~(((CliAuthUInt64)(1u)) << ((sizeof(CliAuthUInt64) * 8) - 1));

   return output.uint;
}

static CliAuthUInt64
cliauth_bitwise_magnitude_extract_negative_sint64_ones_complement(
   CliAuthSInt64 value
) {
   union CliAuthInt64 output;

   /* extract the value's bits */
   output.sint = value;

   /* flip the value's bits to get the positive equivalent */
   output.uint = ~output.uint;

   return output.uint;
}

static CliAuthUInt64
cliauth_bitwise_magnitude_extract_negative_sint64_twos_complement(
   CliAuthSInt64 value
) {
   union CliAuthInt64 output;

   /* extract the value's bits */
   output.sint = value;

   /* flip the value's bits */
   output.uint = ~output.uint;

   /* increment to get the positive equivalent */
   output.uint += 1;

   return output.uint;
}

CliAuthSInt8
cliauth_bitwise_magnitude_deposit_negative_sint8(
   CliAuthUInt8 magnitude
) {
   return (CliAuthSInt8)cliauth_bitwise_magnitude_deposit_negative_sint64(
      (CliAuthUInt64)magnitude
   );
}

CliAuthSInt16
cliauth_bitwise_magnitude_deposit_negative_sint16(
   CliAuthUInt16 magnitude
) {
   return (CliAuthSInt16)cliauth_bitwise_magnitude_deposit_negative_sint64(
      (CliAuthUInt64)magnitude
   );
}

CliAuthSInt32
cliauth_bitwise_magnitude_deposit_negative_sint32(
   CliAuthUInt32 magnitude
) {
   return (CliAuthSInt32)cliauth_bitwise_magnitude_deposit_negative_sint64(
      (CliAuthUInt64)magnitude
   );
}

CliAuthSInt64
cliauth_bitwise_magnitude_deposit_negative_sint64(
   CliAuthUInt64 magnitude
) {
   CliAuthSInt64 retn;

#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE
   (void)cliauth_bitwise_magnitude_deposit_negative_sint64_ones_complement;
   (void)cliauth_bitwise_magnitude_deposit_negative_sint64_twos_complement;
   retn = cliauth_bitwise_magnitude_deposit_negative_sint64_sign_magnitude(
      magnitude
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT
   (void)cliauth_bitwise_magnitude_deposit_negative_sint64_sign_magnitude;
   (void)cliauth_bitwise_magnitude_deposit_negative_sint64_twos_complement;
   retn = cliauth_bitwise_magnitude_deposit_negative_sint64_ones_complement(
      magnitude
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT
   (void)cliauth_bitwise_magnitude_deposit_negative_sint64_sign_magnitude;
   (void)cliauth_bitwise_magnitude_deposit_negative_sint64_ones_complement;
   retn = cliauth_bitwise_magnitude_deposit_negative_sint64_twos_complement(
      magnitude
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT */

   return retn;
}

CliAuthUInt8
cliauth_bitwise_magnitude_extract_negative_sint8(
   CliAuthSInt8 value
) {
   return (CliAuthUInt8)cliauth_bitwise_magnitude_extract_negative_sint64(
      (CliAuthSInt64)value
   );
}

CliAuthUInt16
cliauth_bitwise_magnitude_extract_negative_sint16(
   CliAuthSInt16 value
) {
   return (CliAuthUInt16)cliauth_bitwise_magnitude_extract_negative_sint64(
      (CliAuthSInt64)value
   );
}

CliAuthUInt32
cliauth_bitwise_magnitude_extract_negative_sint32(
   CliAuthSInt32 value
) {
   return (CliAuthUInt32)cliauth_bitwise_magnitude_extract_negative_sint64(
      (CliAuthSInt64)value
   );
}

CliAuthUInt64
cliauth_bitwise_magnitude_extract_negative_sint64(
   CliAuthSInt64 value
) {
   CliAuthUInt64 retn;

#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE
   (void)cliauth_bitwise_magnitude_extract_negative_sint64_ones_complement;
   (void)cliauth_bitwise_magnitude_extract_negative_sint64_twos_complement;
   retn = cliauth_bitwise_magnitude_extract_negative_sint64_sign_magnitude(
      value
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT
   (void)cliauth_bitwise_magnitude_extract_negative_sint64_sign_magnitude;
   (void)cliauth_bitwise_magnitude_extract_negative_sint64_twos_complement;
   retn = cliauth_bitwise_magnitude_extract_negative_sint64_ones_complement(
      value
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT
   (void)cliauth_bitwise_magnitude_extract_negative_sint64_sign_magnitude;
   (void)cliauth_bitwise_magnitude_extract_negative_sint64_ones_complement;
   retn = cliauth_bitwise_magnitude_extract_negative_sint64_twos_complement(
      value
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT */

   return retn;
}

