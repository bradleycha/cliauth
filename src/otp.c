/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/otp.c - One-time-password (OTP) algorithm implementations.             */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "otp.h"

#include "memory.h"
#include "endian.h"
#include "hash.h"
#include "mac.h"
#include "io.h"

static CliAuthUInt32
cliauth_otp_hotp_truncate_digest(
   const CliAuthUInt8 digest [],
   CliAuthUInt32 bytes
) {
   const CliAuthUInt8 * digest_bytes;
   CliAuthUInt32 passcode;
   CliAuthUInt8 offset;

   digest_bytes = digest;

   /* extracts 4 least significant bits */
   offset = (digest_bytes[bytes - CLIAUTH_LITERAL_UINT32(1u)]) & CLIAUTH_LITERAL_UINT8(0x0fu);

   /* read the bit stream using the offset and convert to the host endian */
   cliauth_memory_copy(
      &passcode,
      &digest_bytes[offset],
      sizeof(passcode)
   );
   passcode = cliauth_endian_convert_uint32(
      passcode,
      CLIAUTH_ENDIAN_TARGET_BIG
   );

   /* discard the top-most bit */
   passcode &= ~(CLIAUTH_LITERAL_UINT32(1u) << ((sizeof(passcode) * 8) - 1));

   return passcode;
}

static CliAuthUInt32
cliauth_otp_hotp_trim_digits(
   CliAuthUInt32 passcode,
   CliAuthUInt8 digits
) {
   CliAuthUInt32 modulus;

   modulus = CLIAUTH_LITERAL_UINT32(1u);
   while (digits != CLIAUTH_LITERAL_UINT8(0u)) {
      modulus *= CLIAUTH_LITERAL_UINT32(10u);
      digits--;
   }

   return passcode % modulus;
}

void
cliauth_otp_hotp_initialize(
   struct CliAuthOtpHotpContext * context,
   const struct CliAuthHashFunction * hash_function,
   CliAuthUInt64 counter,
   CliAuthUInt8 digits
) {
   cliauth_mac_hmac_initialize(
      &context->hmac_context,
      hash_function
   );

   context->counter = counter;
   context->digits = digits;
   
   return;
}

struct CliAuthIoReadResult
cliauth_otp_hotp_key_digest(
   struct CliAuthOtpHotpContext * context,
   const struct CliAuthIoReader * key_reader,
   CliAuthUInt32 key_bytes
) {
   return cliauth_mac_hmac_key_digest(
      &context->hmac_context,
      key_reader,
      key_bytes
   );
}

CliAuthUInt32
cliauth_otp_hotp_finalize(
   struct CliAuthOtpHotpContext * context
) {
   struct CliAuthIoByteStreamReader counter_byte_stream_reader;
   struct CliAuthIoReader counter_reader;
   union CliAuthInt64 counter_big_endian;
   CliAuthUInt8 * hmac_digest;
   CliAuthUInt32 passcode_untrimmed;
   CliAuthUInt32 passcode_final;

   /* finalize the key digest */
   cliauth_mac_hmac_key_finalize(&context->hmac_context);

   /* convert the counter value to big-endian and digest it as the HMAC */
   /* message */
   counter_big_endian.uint = cliauth_endian_convert_uint64(
      context->counter,
      CLIAUTH_ENDIAN_TARGET_BIG
   );

   cliauth_io_byte_stream_reader_initialize(
      &counter_byte_stream_reader,
      counter_big_endian.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(counter_big_endian))
   );

   counter_reader = cliauth_io_byte_stream_reader_interface(
      &counter_byte_stream_reader
   );

   (void)cliauth_mac_hmac_message_digest(
      &context->hmac_context,
      &counter_reader,
      CLIAUTH_LITERAL_UINT32(sizeof(counter_big_endian))
   );

   /* finalize the HMAC digest */
   hmac_digest = cliauth_mac_hmac_finalize(&context->hmac_context);

   /* truncate to a 32-bit word and convert to native endian */
   passcode_untrimmed = cliauth_otp_hotp_truncate_digest(
      hmac_digest,
      context->hmac_context.hash_function->digest_length
   );

   /* modulo to keep only the desired number of digits*/
   passcode_final = cliauth_otp_hotp_trim_digits(
      passcode_untrimmed,
      context->digits
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

