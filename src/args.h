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
#include "parse.h"

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
/* uri - The parsed OTP URI data.                                             */
/*                                                                            */
/* time_initial - The initial time value for the TOTP algorithm.  This will   */
/*                always be less than or equal to 'time_current'.             */
/*                                                                            */
/* time_current - The current time value for the TOTP algorithm.  This will   */
/*                always be greater than or equal to 'time_initial'.          */
/*----------------------------------------------------------------------------*/
struct CliAuthArgsPayload {
   struct CliAuthParseKeyUriPayload uri;
   CliAuthUInt64 time_initial;
   CliAuthUInt64 time_current;
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

