/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/account.c - Account management implementation.                         */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "account.h"

#include "otp.h"
#include "io.h"

static CliAuthBoolean
cliauth_account_generate_passcode_index_exists(
   CliAuthUInt64 counter_initial,
   CliAuthSInt64 index
) {
   /* basically just checks for integer underflow/overflow, has to be done */
   /* carefully to avoid undefined behavior due to integer wrappping */
   if (index < 0 && CLIAUTH_UINT64_MIN - index > counter_initial) {
      return CLIAUTH_BOOLEAN_FALSE;
   }
   if (index > 0 && CLIAUTH_UINT64_MAX - index < counter_initial) {
      return CLIAUTH_BOOLEAN_FALSE;
   }

   return CLIAUTH_BOOLEAN_TRUE;
}

enum CliAuthAccountGeneratePasscodeResult
cliauth_account_generate_passcode(
   const struct CliAuthAccount * account,
   CliAuthUInt32 * output,
   struct CliAuthOtpHotpContext * hotp_context,
   const struct CliAuthAccountGeneratePasscodeTotpParameters * totp_parameters,
   CliAuthSInt64 index
) {
   struct CliAuthIoByteStreamReader secrets_byte_stream_reader;
   struct CliAuthIoReader secrets_reader;
   CliAuthUInt64 counter;

   /* get the current HOTP counter value */
   switch (account->algorithm.type) {
      case CLIAUTH_ACCOUNT_ALGORITHM_TYPE_HOTP:
         counter = account->algorithm.parameters.hotp.counter;
         break;

      case CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP:
         counter = cliauth_otp_totp_calculate_counter(
            totp_parameters->time_initial,
            totp_parameters->time_current,
            account->algorithm.parameters.totp.period
         );
         break;
   }

   /* check to make sure the given passcode index offset exists */
   if (cliauth_account_generate_passcode_index_exists(
      counter,
      index
   ) == CLIAUTH_BOOLEAN_FALSE) {
      return CLIAUTH_GENERATE_PASSCODE_RESULT_DOES_NOT_EXIST;
   }

   /* apply the index offset */
   counter += index;

   /* run the HOTP algorithm to generate the passcode */
   cliauth_otp_hotp_initialize(
      hotp_context,
      account->hash_function,
      counter,
      account->digits
   );

   cliauth_io_byte_stream_reader_initialize(
      &secrets_byte_stream_reader,
      account->secrets,
      account->secrets_bytes
   );

   secrets_reader = cliauth_io_byte_stream_reader_interface(
      &secrets_byte_stream_reader
   );

   (void)cliauth_otp_hotp_key_digest(
      hotp_context,
      &secrets_reader,
      secrets_byte_stream_reader.length
   );

   *output = cliauth_otp_hotp_finalize(hotp_context);

   return CLIAUTH_GENERATE_PASSCODE_RESULT_SUCCESS;
}

