/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/ui/args.h - Command-line arguments parsing header.                     */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_UI_ARGS_H
#define _CLIAUTH_UI_ARGS_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "database/account.h"

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_ui_args_parse().                            */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_UI_ARGS_PARSE_RESULT_SUCCESS - The arguments were parsed           */
/*                                        successfully.                       */
/*                                                                            */
/* CLIAUTH_UI_ARGS_PARSE_RESULT_MISSING - One or more required arguments were */
/*                                        missing.                            */
/*                                                                            */
/* CLIAUTH_UI_ARGS_PARSE_RESULT_INVALID - One or more arguments were given an */
/*                                        invalid value.                      */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_UI_ARGS_PARSE_RESULT_FIELD_COUNT 3u
enum CliAuthUiArgsParseResult {
   CLIAUTH_UI_ARGS_PARSE_RESULT_SUCCESS,
   CLIAUTH_UI_ARGS_PARSE_RESULT_MISSING,
   CLIAUTH_UI_ARGS_PARSE_RESULT_INVALID
};

/*----------------------------------------------------------------------------*/
/* Output parsed arguments from cliauth_ui_args_parse().                      */
/*----------------------------------------------------------------------------*/
/* account - The parsed authenticator account.                                */
/*                                                                            */
/* totp_parameters - TOTP-specific algorithm parameters.  This will only be   */
/*                   valid when the account's authenticator algorithm type is */
/*                   'CLIAUTH_DATABASE_ACCOUNT_ALGORITHM_TYPE_TOTP'.          */
/*                                                                            */
/* index - The password index to generate, relative to the currently valid    */
/*         password.  See the documentation for                               */
/*         'cliauth_database_account_generate_password()' for more            */
/*         information.                                                       */
/*----------------------------------------------------------------------------*/
struct CliAuthUiArgsPayload {
   struct CliAuthDatabaseAccount account;
   struct CliAuthDatabaseAccountGeneratePasscodeTotpParameters totp_parameters;
   CliAuthSInt64 index;
};

/*----------------------------------------------------------------------------*/
/* Parses command-line arguments using an array of string arguments.          */
/*----------------------------------------------------------------------------*/
/* payload - A pointer to a CliAuthUiArgsPayload struct where the final       */
/*          output will be stored.  The data stored in this pointer will only */
/*          be valid if the function returns                                  */
/*          'CLIAUTH_UI_ARGS_PARSE_RESULT_SUCCESS'.                           */
/*                                                                            */
/* args - An array of strings which represent the input arguments from the    */
/*        command-line.  Each string in the array should be null-terminated.  */
/*                                                                            */
/* args_count - The number of strings in 'args'.                              */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the output state of the parsed         */
/*                arguments in 'payload'.                                     */
/*----------------------------------------------------------------------------*/
enum CliAuthUiArgsParseResult
cliauth_ui_args_parse(
   struct CliAuthUiArgsPayload * payload,
   const char * const args [],
   CliAuthUInt16 args_count
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_UI_ARGS_H */

