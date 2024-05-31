/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth.c - Main application entrypoint                                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include <stdio.h>
#include <limits.h>

#define CLIAUTH_ABOUT PACKAGE_NAME " version " PACKAGE_VERSION "\n"

/* Return status enum for cliauth_main(). */
enum CliAuthExitStatus {
   /* The program executed successfully without any errors. */
   CLIAUTH_EXIT_STATUS_SUCCESS = 0,

   /* More arguments were passed than can be handled. */
   CLIAUTH_EXIT_STATUS_MAXIMUM_ARGUMENTS_EXCEEDED = 1,
};

static enum CliAuthExitStatus
cliauth_main(unsigned short argc, const char * const argv [], const char * const envp []) {
   (void)argc;
   (void)argv;
   (void)envp;
   fputs(CLIAUTH_ABOUT, stdout);
   return CLIAUTH_EXIT_STATUS_SUCCESS;
}

int main(int argc, char * argv [], char * envp []) {
   if (argc > USHRT_MAX) {
      return (int)CLIAUTH_EXIT_STATUS_MAXIMUM_ARGUMENTS_EXCEEDED;
   }

   enum CliAuthExitStatus exit_status = cliauth_main(
      (unsigned short)argc,
      (const char * const *)argv,
      (const char * const *)envp
   );

   return (int)exit_status;
}

