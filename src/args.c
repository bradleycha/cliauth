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
#include "parse.h"

const char * const
cliauth_args_parse_key_uri_error_name [CLIAUTH_PARSE_KEY_URI_RESULT_FIELD_COUNT] = {
   "malformed URI format",
   "missing algorithm type",
   "missing algorithm secrets",
   "missing hash algorithm",
   "missing initial counter value for HOTP algorithm",
   "invalid text escape sequence",
   "invalid algorithm type",
   "improperly formatted algorithm secrets",
   "unknown hash algorithm",
   "invalid number of passcode digits",
   "invalid period value for TOTP algorithm",
   "invalid initial counter value for HOTP algorithm",
   "the issuer and account name label string is too long",
   "the issuer string is too long",
   "the account name string is too long",
   "the base-32 secrets string is too long"
};

enum CliAuthArgsParseResult
cliauth_args_parse(
   struct CliAuthArgsPayload * payload,
   const char * const args [],
   CliAuthUInt16 args_count
) {
   const char * key_uri;
   CliAuthUInt32 key_uri_characters;
   enum CliAuthParseKeyUriResult parse_key_uri_result;
   const char * error_name;

   if (args_count < 2) {
      cliauth_log(CLIAUTH_LOG_ERROR("no key URI was given as an argument"));
      return CLIAUTH_ARGS_PARSE_RESULT_MISSING;
   }
   if (args_count > 2) {
      cliauth_log(CLIAUTH_LOG_WARNING("more than 1 argument was given, any excess arguments will be ignored"));
   }

   key_uri = args[1];
   key_uri_characters = strlen(key_uri);

   parse_key_uri_result = cliauth_parse_key_uri(
      &payload->uri,
      key_uri,
      key_uri_characters
   );

   if (parse_key_uri_result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
      error_name = cliauth_args_parse_key_uri_error_name[parse_key_uri_result - 1];

      cliauth_log(CLIAUTH_LOG_ERROR("failed to parse key URI: %s"), error_name);

      return CLIAUTH_ARGS_PARSE_RESULT_INVALID;
   }

   payload->time_initial = 0;
   payload->time_current = time(CLIAUTH_NULLPTR);

   return CLIAUTH_ARGS_PARSE_RESULT_SUCCESS;
}

