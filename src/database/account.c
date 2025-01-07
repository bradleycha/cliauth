/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/account.c - Account management implementation.                         */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "database/account.h"

#include "crypto/otp.h"
#include "io/io.h"
#include "io/byte_array_mapper.h"
#include "io/mapper_stream.h"

static CliAuthBoolean
cliauth_database_account_generate_passcode_index_exists(
   CliAuthUInt64 counter_initial,
   CliAuthSInt64 index
) {
   /* basically just checks for integer underflow/overflow, has to be done */
   /* carefully to avoid undefined behavior due to integer wrappping */
   if (
      index < CLIAUTH_LITERAL_SINT64(0, 0, 0, 0) &&
      CLIAUTH_UINT64_MIN - index > counter_initial
   ) {
      return CLIAUTH_BOOLEAN_FALSE;
   }
   if (
      index > CLIAUTH_LITERAL_SINT64(0, 0, 0, 0) &&
      CLIAUTH_UINT64_MAX - index < counter_initial
   ) {
      return CLIAUTH_BOOLEAN_FALSE;
   }

   return CLIAUTH_BOOLEAN_TRUE;
}

enum CliAuthDatabaseAccountGeneratePasscodeResult
cliauth_database_account_generate_passcode(
   const struct CliAuthDatabaseAccount * account,
   CliAuthUInt32 * output,
   struct CliAuthCryptoOtpHotpContext * hotp_context,
   const struct CliAuthDatabaseAccountGeneratePasscodeTotpParameters * totp_parameters,
   CliAuthSInt64 index
) {
   struct CliAuthIoByteArrayMapperReader secrets_byte_array_mapper_reader;
   struct CliAuthIoMapperReader secrets_mapper_reader;
   struct CliAuthIoMapperStreamReader secrets_mapper_stream_reader;
   struct CliAuthIoStreamReader secrets_stream_reader;
   CliAuthUInt64 counter;

   /* get the current HOTP counter value */
   switch (account->algorithm.type) {
      case CLIAUTH_DATABASE_ACCOUNT_ALGORITHM_TYPE_HOTP:
         counter = account->algorithm.parameters.hotp.counter;
         break;

      case CLIAUTH_DATABASE_ACCOUNT_ALGORITHM_TYPE_TOTP:
         counter = cliauth_crypto_otp_totp_calculate_counter(
            totp_parameters->time_initial,
            totp_parameters->time_current,
            account->algorithm.parameters.totp.period
         );
         break;

      default:
         CLIAUTH_UNREACHABLE;
   }

   /* check to make sure the given passcode index offset exists */
   if (cliauth_database_account_generate_passcode_index_exists(
      counter,
      index
   ) == CLIAUTH_BOOLEAN_FALSE) {
      return CLIAUTH_DATABASE_ACCOUNT_GENERATE_PASSCODE_RESULT_DOES_NOT_EXIST;
   }

   /* apply the index offset */
   counter += index;

   /* run the HOTP algorithm to generate the passcode */
   cliauth_crypto_otp_hotp_initialize(
      hotp_context,
      account->hash_function,
      counter,
      account->digits
   );

   secrets_mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &secrets_byte_array_mapper_reader
   );
   secrets_stream_reader = cliauth_io_mapper_stream_reader_interface(
      &secrets_mapper_stream_reader
   );

   cliauth_io_byte_array_mapper_reader_initialize(
      &secrets_byte_array_mapper_reader,
      account->secrets
   );
   cliauth_io_mapper_stream_reader_initialize(
      &secrets_mapper_stream_reader,
      &secrets_mapper_reader,
      account->secrets_bytes,
      CLIAUTH_LITERAL_UINT32(0u)
   );

   /* always return success, so we discard the read result */
   (void)cliauth_crypto_otp_hotp_key_digest(
      hotp_context,
      &secrets_stream_reader,
      account->secrets_bytes
   );

   *output = cliauth_crypto_otp_hotp_finalize(hotp_context);

   return CLIAUTH_DATABASE_ACCOUNT_GENERATE_PASSCODE_RESULT_SUCCESS;
}

