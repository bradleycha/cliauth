/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/args.c - Command-line arguments parsing implementation.                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "args.h"

#include <string.h>
#include <time.h>
#include "account.h"

#define TEST_SECRETS "\xde\xad\xbe\xef"
#define TEST_ISSUER  "Account Authority Inc."
#define TEST_NAME    "user@email.com"

#define TEST_SECRETS_BYTES\
   (((sizeof(TEST_SECRETS) / sizeof(char)) - 1) * sizeof(char))
#define TEST_ISSUER_BYTES\
   (((sizeof(TEST_ISSUER) / sizeof(char)) - 1) * sizeof(char))
#define TEST_NAME_BYTES\
   (((sizeof(TEST_NAME) / sizeof(char)) - 1) * sizeof(char))

enum CliAuthArgsParseResult
cliauth_args_parse(
   struct CliAuthArgsPayload * payload,
   const char * const args [],
   CliAuthUInt16 args_count
) {
   const char * key_uri;
   CliAuthUInt32 key_uri_characters;

   if (args_count < 2) {
      cliauth_log(CLIAUTH_LOG_ERROR("no key URI was given as an argument"));
      return CLIAUTH_ARGS_PARSE_RESULT_MISSING;
   }
   if (args_count > 2) {
      cliauth_log(CLIAUTH_LOG_WARNING("more than 1 argument was given, any excess arguments will be ignored"));
   }

   key_uri = args[1];
   key_uri_characters = strlen(key_uri);

   /* TODO: re-implement key URI parsing */
   cliauth_log(CLIAUTH_LOG_WARNING("key URI parsing is temporarily regressed, arguments parsing will use hard-coded values"));
   (void)key_uri;
   (void)key_uri_characters;

   payload->account.algorithm.type = CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP;
   payload->account.algorithm.parameters.totp.period = 30;

   payload->account.hash = CLIAUTH_ACCOUNT_HASH_TYPE_SHA1;

   (void)memcpy(payload->account.secrets, TEST_SECRETS, TEST_SECRETS_BYTES);
   payload->account.secrets_bytes = TEST_SECRETS_BYTES;

   (void)memcpy(payload->account.issuer, TEST_ISSUER, TEST_ISSUER_BYTES);
   payload->account.issuer_characters = TEST_ISSUER_BYTES / sizeof(char);

   (void)memcpy(payload->account.name, TEST_NAME, TEST_NAME_BYTES);
   payload->account.name_characters = TEST_NAME_BYTES / sizeof(char);

   payload->account.digits = 6;

   payload->totp_parameters.time_initial = 0;
   payload->totp_parameters.time_current = time(CLIAUTH_NULLPTR);

   payload->index = 0;

   return CLIAUTH_ARGS_PARSE_RESULT_SUCCESS;
}

