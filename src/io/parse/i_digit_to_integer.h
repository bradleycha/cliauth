/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/parse/i_digit_to_integer.h - Internal interface to convert a        */
/*    digit character to its integer representation.                          */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_H
#define _CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

/*----------------------------------------------------------------------------*/
/* The result status of parsing a digit character to an integer value.        */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS -                       */
/*    Integer digit parsing was successful.                                   */
/*                                                                            */
/* CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT -                 */
/*    The digit character could not be parsed into an integer value.          */
/*----------------------------------------------------------------------------*/
enum CliAuthIoParseIDigitToIntegerStatus {
   CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS,
   CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT
};

/*----------------------------------------------------------------------------*/
/* A function which parses a digit character to an integer value.             */
/*----------------------------------------------------------------------------*/
/* output -                                                                   */
/*    The parsed integer value.  This will only be valid if                   */
/*    'CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS' is returned.       */
/*                                                                            */
/* digit -                                                                    */
/*    The digit character to parse.                                           */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of parsing the digit character.                              */
/*----------------------------------------------------------------------------*/
typedef enum CliAuthIoParseIDigitToIntegerStatus (*CliAuthIoParseIDigitToIntegerFunction)(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
);

/*----------------------------------------------------------------------------*/
/* Functions which parse a digit character from a given base into an integer. */
/* See the documentation for CliAuthIoParseIDigitToIntegerFunction for more   */
/* information.                                                               */
/*----------------------------------------------------------------------------*/
enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_2(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
);
enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_8(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
);
enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_10(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
);
enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_16(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
);
enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_32(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_H */

