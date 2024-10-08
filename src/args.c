/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/args.c - Command-line arguments parsing implementation.                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "args.h"

#include <time.h>
#include "memory.h"
#include "hash.h"
#include "account.h"
#include "log.h"

#define TEST_SECRETS "\xde\xad\xbe\xef"
#define TEST_ISSUER  "Account Authority Inc."
#define TEST_NAME    "user@email.com"

#define TEST_SECRETS_BYTES\
   (((sizeof(TEST_SECRETS) / sizeof(char)) - 1u) * sizeof(char))
#define TEST_ISSUER_BYTES\
   (((sizeof(TEST_ISSUER) / sizeof(char)) - 1u) * sizeof(char))
#define TEST_NAME_BYTES\
   (((sizeof(TEST_NAME) / sizeof(char)) - 1u) * sizeof(char))

enum CliAuthArgsParseResult
cliauth_args_parse(
   struct CliAuthArgsPayload * payload,
   const char * const args [],
   CliAuthUInt16 args_count
) {
   const char * key_uri;
   char key_uri_terminator;
   struct CliAuthMemoryFindResult key_uri_terminator_find_result;

   if (args_count < CLIAUTH_LITERAL_UINT16(2u)) {
      cliauth_log(CLIAUTH_LOG_ERROR("no key URI was given as an argument"));
      return CLIAUTH_ARGS_PARSE_RESULT_MISSING;
   }
   if (args_count > CLIAUTH_LITERAL_UINT16(2u)) {
      cliauth_log(CLIAUTH_LOG_WARNING("more than 1 argument was given, any excess arguments will be ignored"));
   }

   key_uri = args[1u];
   key_uri_terminator = '\0';
   key_uri_terminator_find_result = cliauth_memory_find(
      key_uri,
      &key_uri_terminator,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_UINT32_MAX / sizeof(char)),
      CLIAUTH_LITERAL_UINT32(sizeof(char))
   );

   /* TODO: re-implement key URI parsing */
   cliauth_log(CLIAUTH_LOG_WARNING("key URI parsing is temporarily regressed, arguments parsing will use hard-coded values"));
   (void)key_uri;
   (void)key_uri_terminator_find_result;

   payload->account.algorithm.type = CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP;
   payload->account.algorithm.parameters.totp.period = CLIAUTH_LITERAL_UINT64(0u, 30u);

   payload->account.hash_function = &cliauth_hash_sha1;

   cliauth_memory_copy(
      payload->account.secrets,
      TEST_SECRETS,
      CLIAUTH_LITERAL_UINT32(TEST_SECRETS_BYTES)
   );
   payload->account.secrets_bytes = TEST_SECRETS_BYTES;

   cliauth_memory_copy(
      payload->account.issuer,
      TEST_ISSUER,
      CLIAUTH_LITERAL_UINT32(TEST_ISSUER_BYTES)
   );
   payload->account.issuer_characters = CLIAUTH_LITERAL_UINT8(TEST_ISSUER_BYTES / sizeof(char));

   cliauth_memory_copy(
      payload->account.name,
      TEST_NAME,
      TEST_NAME_BYTES
   );
   payload->account.name_characters = CLIAUTH_LITERAL_UINT8(TEST_NAME_BYTES / sizeof(char));

   payload->account.digits = CLIAUTH_LITERAL_UINT8(6u);

   payload->totp_parameters.time_initial = CLIAUTH_LITERAL_UINT64(0u, 0u);
   payload->totp_parameters.time_current = time(CLIAUTH_NULLPTR);

   payload->index = CLIAUTH_LITERAL_SINT64(0u, 0u, 0u, 0u);

   return CLIAUTH_ARGS_PARSE_RESULT_SUCCESS;
}

