/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/ui/args.c - Command-line arguments parsing implementation.     */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/ui/args.h"

#include "cliauth/memory/memory.h"
#include "cliauth/crypto/hash.h"
#include "cliauth/database/account.h"
#include "cliauth/io/log.h"

#include <time.h>

#define TEST_SECRETS "\xde\xad\xbe\xef"
#define TEST_ISSUER  "Account Authority Inc."
#define TEST_NAME    "user@email.com"

#define TEST_SECRETS_BYTES\
   (CLIAUTH_STRING_CHARACTERS(TEST_SECRETS) * sizeof(char))
#define TEST_ISSUER_BYTES\
   (CLIAUTH_STRING_CHARACTERS(TEST_ISSUER) * sizeof(char))
#define TEST_NAME_BYTES\
   (CLIAUTH_STRING_CHARACTERS(TEST_NAME) * sizeof(char))

static const struct CliAuthCryptoHashFunction *
cliauth_args_parse_hash_function(
   const char identifier [],
   CliAuthUInt32 identifier_characters
) {
   const struct CliAuthCryptoHashFunction * hash_iterator;
   CliAuthUInt8 i;

   hash_iterator = cliauth_crypto_hash;
   i = CLIAUTH_CRYPTO_HASH_ENABLED_COUNT;
   while (i != CLIAUTH_LITERAL_UINT8(0u)) {
      if (cliauth_memory_compare(
         hash_iterator->identifier,
         identifier,
         hash_iterator->identifier_characters * sizeof(char),
         identifier_characters * sizeof(char)
      ) == CLIAUTH_BOOLEAN_TRUE) {
         return hash_iterator;
      }

      hash_iterator++;
      i--;
   }

   return CLIAUTH_NULLPTR;
}

enum CliAuthUiArgsParseResult
cliauth_ui_args_parse(
   struct CliAuthUiArgsPayload * payload,
   const char * const args [],
   CliAuthUInt16 args_count
) {
   const char * key_uri;
   CliAuthUInt32 key_uri_characters;
   char key_uri_terminator;
   struct CliAuthMemoryFindResult key_uri_terminator_find_result;
   const struct CliAuthCryptoHashFunction * hash_function;

   if (args_count < CLIAUTH_LITERAL_UINT16(2u)) {
      cliauth_io_log(CLIAUTH_IO_LOG_ERROR("no key URI was given as an argument"));
      return CLIAUTH_UI_ARGS_PARSE_RESULT_MISSING;
   }
   if (args_count > CLIAUTH_LITERAL_UINT16(2u)) {
      cliauth_io_log(CLIAUTH_IO_LOG_WARNING("more than 1 argument was given, any excess arguments will be ignored"));
   }

   key_uri = args[1u];
   key_uri_terminator = '\0';
   key_uri_terminator_find_result = cliauth_memory_find(
      key_uri,
      &key_uri_terminator,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_UINT32_MAX / sizeof(char)),
      CLIAUTH_LITERAL_UINT32(sizeof(char))
   );
   key_uri_characters = key_uri_terminator_find_result.position;

   /* TODO: re-implement key URI parsing, right now we're treating the key */
   /* URI as a hash function identifier and nothing else */
   cliauth_io_log(CLIAUTH_IO_LOG_WARNING("key URI parsing is temporarily regressed, arguments parsing will use hard-coded values, except for the hash algorithm"));

   payload->account.algorithm.type = CLIAUTH_DATABASE_ACCOUNT_ALGORITHM_TYPE_TOTP;
   payload->account.algorithm.parameters.totp.period = CLIAUTH_LITERAL_UINT64(0u, 30u);

   hash_function = cliauth_args_parse_hash_function(key_uri, key_uri_characters);
   if (hash_function == CLIAUTH_NULLPTR) {
      cliauth_io_log(
         CLIAUTH_IO_LOG_ERROR("unknown hash algorithm \'%.*s\'"),
         key_uri_characters,
         key_uri
      );

      return CLIAUTH_UI_ARGS_PARSE_RESULT_INVALID;
   }

   payload->account.hash_function = hash_function;

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

   return CLIAUTH_UI_ARGS_PARSE_RESULT_SUCCESS;
}

