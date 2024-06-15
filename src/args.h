/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/args.h - Command-line arguments parsing header.                        */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_ARGS_H
#define _CLIAUTH_ARGS_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "account.h"

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_args_parse().                               */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_ARGS_PARSE_RESULT_SUCCESS - The arguments were parsed              */
/*                                     successfully.                          */
/*                                                                            */
/* CLIAUTH_ARGS_PARSE_RESULT_MISSING - One or more required arguments were    */
/*                                     missing.                               */
/*                                                                            */
/* CLIAUTH_ARGS_PARSE_RESULT_INVALID - One or more arguments were given an    */
/*                                     invalid value.                         */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ARGS_PARSE_RESULT_FIELD_COUNT 3
enum CliAuthArgsParseResult {
   CLIAUTH_ARGS_PARSE_RESULT_SUCCESS,
   CLIAUTH_ARGS_PARSE_RESULT_MISSING,
   CLIAUTH_ARGS_PARSE_RESULT_INVALID
};

/*----------------------------------------------------------------------------*/
/* Output parsed arguments from cliauth_args_parse().                         */
/*----------------------------------------------------------------------------*/
/* account - The parsed authenticator account .                               */
/*                                                                            */
/* totp_parameters - TOTP-specific algorithm parameters.  This will only be   */
/*                   valid when the account's authenticator algorithm type is */
/*                   'CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP'.                   */
/*                                                                            */
/* index - The password index to generate, relative to the currently valid    */
/*         password.  See the documentation for                               */
/*         'cliauth_account_generate_password()' for more information.        */
/*----------------------------------------------------------------------------*/
struct CliAuthArgsPayload {
   struct CliAuthAccount account;
   struct CliAuthAccountGeneratePasscodeTotpParameters totp_parameters;
   CliAuthSInt64 index;
};

/*----------------------------------------------------------------------------*/
/* Parses command-line arguments using an array of string arguments.          */
/*----------------------------------------------------------------------------*/
/* payload - A pointer to a CliAuthArgsPayload struct where the final output  */
/*          will be stored.  The data stored in this pointer will only be     */
/*          valid if the function returns                                     */
/*          'CLIAUTH_ARGS_PARSE_RESULT_SUCCESS'.                              */
/*                                                                            */
/* args - An array of strings which represent the input arguments from the    */
/*        command-line.  Each string in the array should be null-terminated.  */
/*                                                                            */
/* args_count - The number of strings in 'args'.                              */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the output state of the parsed         */
/*                arguments in 'payload'.                                     */
/*----------------------------------------------------------------------------*/
enum CliAuthArgsParseResult
cliauth_args_parse(
   struct CliAuthArgsPayload * payload,
   const char * const args [],
   CliAuthUInt16 args_count
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_ARGS_H */

