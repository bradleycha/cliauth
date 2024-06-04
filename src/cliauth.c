/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth.c - Main application entrypoint                                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

#define CLIAUTH_ABOUT PACKAGE_NAME " version " PACKAGE_VERSION

/* Return status enum for cliauth_main(). */
enum CliAuthExitStatus {
   /* The program executed successfully without any errors. */
   CLIAUTH_EXIT_STATUS_SUCCESS = 0,

   /* More arguments were passed than can be handled. */
   CLIAUTH_EXIT_STATUS_MAXIMUM_ARGUMENTS_EXCEEDED = 1
};

static enum CliAuthExitStatus
cliauth_main(CliAuthUInt16 argc, const char * const argv []) {
   (void)argc;
   (void)argv;
   cliauth_log(CLIAUTH_LOG_INFO(CLIAUTH_ABOUT));
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

