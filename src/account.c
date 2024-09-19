/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/account.c - Account management implementation.                         */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "account.h"

#include "hash.h"
#include "otp.h"
#include "io.h"

/* used to convert a CliAuthAccountHashType into an executable form. */
struct CliAuthAccountHashData {
   const struct CliAuthHashFunction * function;
   CliAuthUInt8 block_bytes;
   CliAuthUInt8 digest_bytes;
};

/* WARNING: these MUST be defined in the *exact* same order as the relative */
/* enum fields in CliAuthAccountHashType. */
static const struct CliAuthAccountHashData 
cliauth_account_generate_passcode_hash_data [CLIAUTH_HASH_ENABLED_COUNT] = {
#if CLIAUTH_CONFIG_HASH_SHA1
   {
      &cliauth_hash_sha1,
      CLIAUTH_HASH_SHA1_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA1_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA2_224
   {
      &cliauth_hash_sha2_224,
      CLIAUTH_HASH_SHA2_224_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA2_224_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA2_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_256
   {
      &cliauth_hash_sha2_256,
      CLIAUTH_HASH_SHA2_256_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA2_256_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA2_256 */
#if CLIAUTH_CONFIG_HASH_SHA2_384
   {
      &cliauth_hash_sha2_384,
      CLIAUTH_HASH_SHA2_384_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA2_384_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA2_384 */
#if CLIAUTH_CONFIG_HASH_SHA2_512
   {
      &cliauth_hash_sha2_512,
      CLIAUTH_HASH_SHA2_512_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA2_512_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_224
   {
      &cliauth_hash_sha2_512_224,
      CLIAUTH_HASH_SHA2_512_224_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA2_512_224_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_256
   {
      &cliauth_hash_sha2_512_256,
      CLIAUTH_HASH_SHA2_512_256_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA2_512_256_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_256 */
};

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
   struct CliAuthAccountGeneratePasscodeBuffer * buffer,
   const struct CliAuthAccountGeneratePasscodeTotpParameters * totp_parameters,
   CliAuthSInt64 index
) {
   struct CliAuthOtpHotpContext hotp_context;
   struct CliAuthIoByteStreamReader secrets_byte_stream_reader;
   struct CliAuthIoReader secrets_reader;
   const struct CliAuthAccountHashData * hash_data;
   CliAuthUInt64 counter;

   /* get the hash algorithm data from the account's hash enum representation */
   hash_data = &cliauth_account_generate_passcode_hash_data[account->hash];

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
      &hotp_context,
      (CliAuthUInt8 *)(&buffer->key),
      (CliAuthUInt8 *)(&buffer->digest),
      hash_data->function,
      &buffer->context,
      hash_data->block_bytes,
      hash_data->digest_bytes,
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
      &hotp_context,
      &secrets_reader,
      secrets_byte_stream_reader.length
   );

   *output = cliauth_otp_hotp_finalize(&hotp_context);

   return CLIAUTH_GENERATE_PASSCODE_RESULT_SUCCESS;
}

