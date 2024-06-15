/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/args.c - Command-line arguments parsing implementation.                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "args.h"

#include <string.h>
#include "account.h"

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
   cliauth_log(CLIAUTH_LOG_WARNING("key URI parsing is temporarily regressed, arguments parsing will always fail"));
   (void)key_uri;
   (void)key_uri_characters;
   (void)payload;
   return CLIAUTH_ARGS_PARSE_RESULT_INVALID;
}

