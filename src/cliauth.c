/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth.c - Main application entrypoint                                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "args.h"
#include "hash.h"
#include "otp.h"

#define CLIAUTH_ABOUT PACKAGE_NAME " version " PACKAGE_VERSION

union CliAuthOtpBuffersGenericHashContext {
#if CLIAUTH_CONFIG_HASH_SHA1
   struct CliAuthHashContextSha1 sha1;
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA224
   struct CliAuthHashContextSha232 sha224;
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */
#if CLIAUTH_CONFIG_HASH_SHA256
   struct CliAuthHashContextSha232 sha256;
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */
#if CLIAUTH_CONFIG_HASH_SHA384
   struct CliAuthHashContextSha264 sha384;
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */
#if CLIAUTH_CONFIG_HASH_SHA512
   struct CliAuthHashContextSha264 sha512;
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */
#if CLIAUTH_CONFIG_HASH_SHA512_224
   struct CliAuthHashContextSha264 sha512_224;
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */
#if CLIAUTH_CONFIG_HASH_SHA512_256
   struct CliAuthHashContextSha264 sha512_256;
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */
};

union CliAuthOtpBuffersGenericDigest {
#if CLIAUTH_CONFIG_HASH_SHA1
   CliAuthUInt8 sha1 [CLIAUTH_HASH_SHA1_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA224
   CliAuthUInt8 sha224 [CLIAUTH_HASH_SHA224_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */
#if CLIAUTH_CONFIG_HASH_SHA256
   CliAuthUInt8 sha256 [CLIAUTH_HASH_SHA256_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */
#if CLIAUTH_CONFIG_HASH_SHA384
   CliAuthUInt8 sha384 [CLIAUTH_HASH_SHA384_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */
#if CLIAUTH_CONFIG_HASH_SHA512
   CliAuthUInt8 sha512 [CLIAUTH_HASH_SHA512_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */
#if CLIAUTH_CONFIG_HASH_SHA512_224
   CliAuthUInt8 sha512_224 [CLIAUTH_HASH_SHA512_224_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */
#if CLIAUTH_CONFIG_HASH_SHA512_256
   CliAuthUInt8 sha512_256 [CLIAUTH_HASH_SHA512_256_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */
};

union CliAuthOtpBuffersGenericKey {
#if CLIAUTH_CONFIG_HASH_SHA1
   CliAuthUInt8 sha1 [CLIAUTH_HASH_SHA1_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA224
   CliAuthUInt8 sha224 [CLIAUTH_HASH_SHA224_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */
#if CLIAUTH_CONFIG_HASH_SHA256
   CliAuthUInt8 sha256 [CLIAUTH_HASH_SHA256_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */
#if CLIAUTH_CONFIG_HASH_SHA384
   CliAuthUInt8 sha384 [CLIAUTH_HASH_SHA384_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */
#if CLIAUTH_CONFIG_HASH_SHA512
   CliAuthUInt8 sha512 [CLIAUTH_HASH_SHA512_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */
#if CLIAUTH_CONFIG_HASH_SHA512_224
   CliAuthUInt8 sha512_224 [CLIAUTH_HASH_SHA512_224_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */
#if CLIAUTH_CONFIG_HASH_SHA512_256
   CliAuthUInt8 sha512_256 [CLIAUTH_HASH_SHA512_256_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */
};

/* generic buffers large enough to run every possible hash algorithm. */
/* this union trick allows us to figure out our stack layout/memory usage at */
/* compile time with a runtime-chosen hash function without relying on either */
/* guessing properly sized buffers or using too much preprocessor slop. */
struct CliAuthOtpBuffersGeneric {
   union CliAuthOtpBuffersGenericHashContext hash_context;
   union CliAuthOtpBuffersGenericDigest digest_buffer;
   union CliAuthOtpBuffersGenericKey key_buffer;
};

/* Return status enum for cliauth_main(). */
#define CLIAUTH_EXIT_STATUS_FIELD_COUNT 3
enum CliAuthExitStatus {
   /* The program executed successfully without any errors. */
   CLIAUTH_EXIT_STATUS_SUCCESS = 0,

   /* More arguments were passed than can be handled. */
   CLIAUTH_EXIT_STATUS_MAXIMUM_ARGUMENTS_EXCEEDED = 1,

   /* There was an error parsing the arguments. */
   CLIAUTH_EXIT_STATUS_ARGS_PARSE_ERROR = 2
};

static CliAuthUInt32
cliauth_execute_hotp(
   const struct CliAuthArgsPayload * args,
   struct CliAuthOtpBuffersGeneric * buffers
) {
   CliAuthUInt32 passcode;

   cliauth_log(CLIAUTH_LOG_INFO("initial counter value: %llu"), args->uri.algorithm_parameters.hotp.counter);

   cliauth_log(CLIAUTH_LOG_INFO("generating a passcode using the HOTP algorithm"));

   passcode = cliauth_otp_hotp(
      args->uri.hash->function,
      &buffers->hash_context,
      &args->uri.secrets,
      &buffers->digest_buffer,
      &buffers->key_buffer,
      args->uri.secrets_bytes,
      args->uri.hash->block_bytes,
      args->uri.hash->digest_bytes,
      args->uri.algorithm_parameters.hotp.counter,
      args->uri.digits
   );

   return passcode;
}

static CliAuthUInt32
cliauth_execute_totp(
   const struct CliAuthArgsPayload * args,
   struct CliAuthOtpBuffersGeneric * buffers
) {
   CliAuthUInt32 passcode;

   cliauth_log(CLIAUTH_LOG_INFO("initial time: %llu seconds"), args->time_initial);
   cliauth_log(CLIAUTH_LOG_INFO("current time: %llu seconds"), args->time_current);
   cliauth_log(CLIAUTH_LOG_INFO("period: %llu seconds"), args->uri.algorithm_parameters.totp.period);

   cliauth_log(CLIAUTH_LOG_INFO("generating a passcode using the TOTP algorithm"));

   passcode = cliauth_otp_totp(
      args->uri.hash->function,
      &buffers->hash_context,
      &args->uri.secrets,
      &buffers->digest_buffer,
      &buffers->key_buffer,
      args->uri.secrets_bytes,
      args->uri.hash->block_bytes,
      args->uri.hash->digest_bytes,
      args->time_initial,
      args->time_current,
      args->uri.algorithm_parameters.totp.period,
      args->uri.digits
   );

   return passcode;
}

static enum CliAuthExitStatus
cliauth_main(CliAuthUInt16 argc, const char * const argv []) {
   struct CliAuthArgsPayload args;
   struct CliAuthOtpBuffersGeneric buffers;
   CliAuthUInt32 passcode;

   cliauth_log(CLIAUTH_LOG_INFO(CLIAUTH_ABOUT));

   switch (cliauth_args_parse(&args, argv, argc)) {
      case CLIAUTH_ARGS_PARSE_RESULT_SUCCESS:
         break;

      default:
         cliauth_log(CLIAUTH_LOG_ERROR("failed to parse command-line arguments, exiting"));
         return CLIAUTH_EXIT_STATUS_ARGS_PARSE_ERROR;
   }

   cliauth_log(CLIAUTH_LOG_INFO("issuer: %.*s"), args.uri.issuer_characters, &args.uri.issuer);
   cliauth_log(CLIAUTH_LOG_INFO("account name: %.*s"), args.uri.account_name_characters, &args.uri.account_name);

   switch (args.uri.algorithm) {
      case CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP:
         passcode = cliauth_execute_hotp(&args, &buffers);
         break;

      case CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_TOTP:
         passcode = cliauth_execute_totp(&args, &buffers);
         break;
   }

   cliauth_log(CLIAUTH_LOG_INFO("generated passcode: %0*u"), args.uri.digits, passcode);

   return CLIAUTH_EXIT_STATUS_SUCCESS;
}

int main(int argc, char * argv []) {
   enum CliAuthExitStatus exit_status;

   if (argc > CLIAUTH_UINT16_MAX) {
      return (int)CLIAUTH_EXIT_STATUS_MAXIMUM_ARGUMENTS_EXCEEDED;
   }

   exit_status = cliauth_main(
      (CliAuthUInt16)argc,
      (const char * const *)argv
   );

   return (int)exit_status;
}

