/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth.c - Main application entrypoint                                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "args.h"
#include "account.h"
#include "log.h"
#include <inttypes.h>

#define CLIAUTH_ABOUT PACKAGE_NAME " version " PACKAGE_VERSION

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

static enum CliAuthExitStatus
cliauth_main(CliAuthUInt16 argc, const char * const argv []) {
   struct CliAuthArgsPayload args;
   enum CliAuthAccountGeneratePasscodeResult passcode_result;
   struct CliAuthAccountGeneratePasscodeBuffer passcode_generate_buffer;
   CliAuthUInt32 passcode;

   cliauth_log(CLIAUTH_LOG_INFO(CLIAUTH_ABOUT));

   switch (cliauth_args_parse(&args, argv, argc)) {
      case CLIAUTH_ARGS_PARSE_RESULT_SUCCESS:
         break;

      default:
         cliauth_log(CLIAUTH_LOG_ERROR("failed to parse command-line arguments, exiting"));
         return CLIAUTH_EXIT_STATUS_ARGS_PARSE_ERROR;
   }

   cliauth_log(
      CLIAUTH_LOG_INFO("account issuer: %.*s"),
      args.account.issuer_characters,
      args.account.issuer
   );
   cliauth_log(
      CLIAUTH_LOG_INFO("account name: %.*s"),
      args.account.name_characters,
      args.account.name
   );

   switch (args.account.algorithm.type) {
      case CLIAUTH_ACCOUNT_ALGORITHM_TYPE_HOTP:
         cliauth_log(
            CLIAUTH_LOG_INFO("counter value: %" PRIu64),
            args.account.algorithm.parameters.hotp.counter
         );
         break;

      case CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP:
         cliauth_log(
            CLIAUTH_LOG_INFO("initial timestamp: %" PRIu64 " seconds"), 
            args.totp_parameters.time_initial
         );
         cliauth_log(
            CLIAUTH_LOG_INFO("current timestamp: %" PRIu64 " seconds"),
            args.totp_parameters.time_current
         );
         cliauth_log(
            CLIAUTH_LOG_INFO("period: %" PRIu64 " seconds"),
            args.account.algorithm.parameters.totp.period
         );
         break;
   }

   cliauth_log(
      CLIAUTH_LOG_INFO("passcode index: %" PRId64),
      args.index
   );

   cliauth_log(CLIAUTH_LOG_INFO("generating a passcode using the given parameters"));

   passcode_result = cliauth_account_generate_passcode(
      &args.account,
      &passcode,
      &passcode_generate_buffer,
      &args.totp_parameters,
      args.index
   );
   switch (passcode_result) {
      case CLIAUTH_GENERATE_PASSCODE_RESULT_SUCCESS:
         cliauth_log(
            CLIAUTH_LOG_INFO("generated passcode: %0*" PRIu32),
            args.account.digits,
            passcode
         );
         break;

      case CLIAUTH_GENERATE_PASSCODE_RESULT_DOES_NOT_EXIST:
         cliauth_log(CLIAUTH_LOG_ERROR("no passcode exists for this index"));
         break;
   }


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

