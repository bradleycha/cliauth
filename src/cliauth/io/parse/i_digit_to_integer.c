/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/io/parse/i_digit_to_integer.c - Digit character to integer     */
/*    conversion implementations.                                             */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/io/parse/i_digit_to_integer.h"

enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_2(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('1')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT;
}

enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_8(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('7')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT;
}

enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_10(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('9')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT;
}

enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_16(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('9')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }
   if (digit >= CLIAUTH_LITERAL_UINT8('a') && digit <= CLIAUTH_LITERAL_UINT8('f')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('a') + CLIAUTH_LITERAL_UINT8(10u);
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }
   if (digit >= CLIAUTH_LITERAL_UINT8('A') && digit <= CLIAUTH_LITERAL_UINT8('F')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('A') + CLIAUTH_LITERAL_UINT8(10u);
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT;
}

enum CliAuthIoParseIDigitToIntegerStatus
cliauth_io_parse_i_digit_to_integer_base_32(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('a') && digit <= CLIAUTH_LITERAL_UINT8('z')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('a');
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }
   if (digit >= CLIAUTH_LITERAL_UINT8('A') && digit <= CLIAUTH_LITERAL_UINT8('Z')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('A');
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }
   if (digit >= CLIAUTH_LITERAL_UINT8('2') && digit <= CLIAUTH_LITERAL_UINT8('7')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('2') + CLIAUTH_LITERAL_UINT8(26u);
      return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT;
}

