/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/otp.c - One-time-password (OTP) algorithm implementations.             */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "otp.h"

#include <string.h>
#include "endian.h"
#include "hash.h"
#include "mac.h"

static CliAuthUInt32
cliauth_otp_hotp_truncate_digest(
   const void * digest,
   CliAuthUInt32 bytes
) {
   const CliAuthUInt8 * digest_bytes;
   CliAuthUInt32 passcode;
   CliAuthUInt8 offset;

   digest_bytes = (const CliAuthUInt8 *)digest;

   /* extracts 4 least significant bits */
   offset = (digest_bytes[bytes - 1]) & 0x0f;

   /* read the bit stream using the offset and convert to the host endian */
   (void)memcpy(&passcode, &digest_bytes[offset], sizeof(passcode));
   passcode = cliauth_endian_host_to_big_uint32(passcode);

   /* discard the top-most bit */
   passcode &= ~(((CliAuthUInt32)1) << ((sizeof(passcode) * 8) - 1));

   return passcode;
}

static CliAuthUInt32
cliauth_otp_hotp_trim_digits(
   CliAuthUInt32 passcode,
   CliAuthUInt8 digits
) {
   CliAuthUInt32 modulus;

   modulus = 1;
   while (digits != 0) {
      modulus *= 10;
      digits--;
   }

   return passcode % modulus;
}

CliAuthUInt32
cliauth_otp_hotp(
   const struct CliAuthHashFunction * hash_function,
   void * hash_context,
   const void * key,
   void * digest_buffer,
   void * key_buffer,
   CliAuthUInt32 key_bytes,
   CliAuthUInt32 block_bytes,
   CliAuthUInt32 digest_bytes,
   CliAuthUInt64 counter,
   CliAuthUInt8 digits
) {
   CliAuthUInt64 counter_big_endian;
   CliAuthUInt32 passcode_untrimmed;
   CliAuthUInt32 passcode_final;

   /* convert counter to big-endian */
   counter_big_endian = cliauth_endian_host_to_big_uint64(counter);

   /* calculate HMAC digest */
   cliauth_mac_hmac(
      hash_function,
      hash_context,
      &counter_big_endian,
      key,
      digest_buffer,
      key_buffer,
      sizeof(counter),
      key_bytes,
      block_bytes,
      digest_bytes
   );

   /* truncate to a 32-bit word and convert to native endian */
   passcode_untrimmed = cliauth_otp_hotp_truncate_digest(
      digest_buffer,
      digest_bytes
   );

   /* modulo to keep only the desired number of digits*/
   passcode_final = cliauth_otp_hotp_trim_digits(
      passcode_untrimmed,
      digits
   );

   return passcode_final;
}

CliAuthUInt64
cliauth_otp_totp_calculate_counter(
   CliAuthUInt64 time_initial,
   CliAuthUInt64 time_current,
   CliAuthUInt64 time_interval
) {
   CliAuthUInt64 counter;

   counter = (time_current - time_initial) / time_interval;

   return counter;
}

