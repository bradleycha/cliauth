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
cliauth_args_parse_display_otp_uri_failure(
   enum CliAuthParseKeyUriResult result
) {
   enum CliAuthArgsParseResult retn;
   const char * error_name;

   error_name = cliauth_args_parse_key_uri_error_name[result - 1];

   cliauth_log(CLIAUTH_LOG_ERROR("failed to parse key URI: %s"), error_name);

   switch (result) {
      case CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_TYPE:
      case CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_SECRETS:
      case CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HASH:
      case CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HOTP_COUNTER:
         retn = CLIAUTH_ARGS_PARSE_RESULT_MISSING;
         break;

      case CLIAUTH_PARSE_KEY_URI_RESULT_MALFORMED_URI:
      case CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TEXT_ESCAPE:
      case CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TYPE:
      case CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_SECRETS:
      case CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HASH:
      case CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_DIGITS:
      case CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TOTP_PERIOD:
      case CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HOTP_COUNTER:
      case CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_LABEL:
      case CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ISSUER:
      case CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ACCOUNT_NAME:
      case CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_SECRETS:
         retn = CLIAUTH_ARGS_PARSE_RESULT_INVALID;
         break;

      case CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS:
         retn = CLIAUTH_ARGS_PARSE_RESULT_SUCCESS;
         break;
   }

   return retn;
}

enum CliAuthArgsParseResult
cliauth_args_parse(
   struct CliAuthArgsPayload * payload,
   const char * const args [],
   CliAuthUInt16 args_count
) {
   const char * key_uri;
   CliAuthUInt32 key_uri_characters;
   enum CliAuthParseKeyUriResult parse_key_uri_result;

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
      return cliauth_args_parse_display_otp_uri_failure(parse_key_uri_result);
   }

   payload->time_initial = 0;
   payload->time_current = time(NULL);

   return CLIAUTH_ARGS_PARSE_RESULT_SUCCESS;
}

