/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/parse.h - Data serializers and deserializers header.                   */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_PARSE_H
#define _CLIAUTH_PARSE_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io.h"

/*----------------------------------------------------------------------------*/
/* The result status of parsing an integer from a string.                     */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS - The integer was parsed       */
/*                                               successfully.                */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_STATUS_IO_ERROR - An IO read error occurred.  */
/*                                                                            */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT - An invalid digit for   */
/*                                                     the expected base was  */
/*                                                     encountered.           */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE - The number is outside   */
/*                                                    the range of possible   */
/*                                                    values for the given    */
/*                                                    integer type.           */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_STATUS_UNEXPECTED_SIGN - A sign character was */
/*                                                       found when the sign  */
/*                                                       was already given.   */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_STRING_INTEGER_STATUS_FIELD_COUNT 5u
enum CliAuthParseStringIntegerStatus {
   CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS,
   CLIAUTH_PARSE_STRING_INTEGER_STATUS_IO_ERROR,
   CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT,
   CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE,
   CLIAUTH_PARSE_STRING_INTEGER_STATUS_UNEXPECTED_SIGN
};

/*----------------------------------------------------------------------------*/
/* The result of attempting to parse an integer from a string.                */
/*----------------------------------------------------------------------------*/
/* status - The status of the integer parsing.                                */
/*                                                                            */
/* read_result - The read result.  This will contain further details about    */
/*               potential IO read errors.                                    */
/*----------------------------------------------------------------------------*/
struct CliAuthParseStringIntegerResult {
   enum CliAuthParseStringIntegerStatus status;
   struct CliAuthIoReadResult read_result;
};

/*----------------------------------------------------------------------------*/
/* A sign to parse a string integer as.                                       */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_STRING_INTEGER_SIGN_POSITIVE - Treat the string integer as   */
/*                                              positive.                     */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_SIGN_NEGATIVE - Treat the string integer as   */
/*                                              negative.                     */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_SIGN_AUTOMATIC - The integer string's sign    */
/*                                               will be determined from the  */
/*                                               prefix character.            */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_STRING_INTEGER_SIGN_FIELD_COUNT 3u
enum CliAuthParseStringIntegerSign {
   CLIAUTH_PARSE_STRING_INTEGER_SIGN_POSITIVE,
   CLIAUTH_PARSE_STRING_INTEGER_SIGN_NEGATIVE,
   CLIAUTH_PARSE_STRING_INTEGER_SIGN_AUTOMATIC
};

/*----------------------------------------------------------------------------*/
/* A base to parse a string integer as.                                       */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_STRING_INTEGER_BASE_2 - A base-2 integer string, also known  */
/*                                       as a binary string.  The following   */
/*                                       characters have the given decimal    */
/*                                       value:                               */
/*                                                                            */
/*                                       0 - 0                                */
/*                                       1 - 1                                */
/*                                                                            */
/*                                       The base character for base-2 is     */
/*                                       'b'.                                 */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_BASE_8 - A base-8 integer string, also known  */
/*                                       as an octal string.  The following   */
/*                                       characters have the given decimal    */
/*                                       value:                               */
/*                                                                            */
/*                                       0 - 0                                */
/*                                       1 - 1                                */
/*                                       2 - 2                                */
/*                                       3 - 3                                */
/*                                       4 - 4                                */
/*                                       5 - 5                                */
/*                                       6 - 6                                */
/*                                       7 - 7                                */
/*                                                                            */
/*                                       The base character for base-8 is     */
/*                                       'o'.                                 */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_BASE_10 - A base-10 integer string, also      */
/*                                        known as a decimal string.  The     */
/*                                        following characters have the given */
/*                                        decimal value:                      */
/*                                                                            */
/*                                        0 - 0                               */
/*                                        1 - 1                               */
/*                                        2 - 2                               */
/*                                        3 - 3                               */
/*                                        4 - 4                               */
/*                                        5 - 5                               */
/*                                        6 - 6                               */
/*                                        7 - 7                               */
/*                                        8 - 8                               */
/*                                        9 - 9                               */
/*                                                                            */
/*                                        There is no base character for      */
/*                                        base-10.  An integer string with no */
/*                                        prefix will default to base-10.     */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_BASE_16 - A base-16 integer string, also      */
/*                                        known as a hexadecimal string.  The */
/*                                        following characters have the given */
/*                                        hexadecimal value:                  */
/*                                                                            */
/*                                        0    - 0                            */
/*                                        1    - 1                            */
/*                                        2    - 2                            */
/*                                        3    - 3                            */
/*                                        4    - 4                            */
/*                                        5    - 5                            */
/*                                        6    - 6                            */
/*                                        7    - 7                            */
/*                                        8    - 8                            */
/*                                        9    - 9                            */
/*                                        a, A - 10                           */
/*                                        b, B - 11                           */
/*                                        c, C - 12                           */
/*                                        d, D - 13                           */
/*                                        e, E - 14                           */
/*                                        f, F - 15                           */
/*                                                                            */
/*                                        The base character for base-16 is   */
/*                                        'x'.                                */
/*                                                                            */
/* CLIAUTH_PARSE_STRING_INTEGER_BASE_AUTOMATIC - The integer string's base    */
/*                                               will be determined           */
/*                                               automatically from the       */
/*                                               prefix character.            */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_STRING_INTEGER_BASE_FIELD_COUNT 5u
enum CliAuthParseStringIntegerBase {
   /* this is only used to define enum values and should never be used */
   _CLIAUTH_PARSE_STRING_INTEGER_BASE_START_INDEX = -1,

   CLIAUTH_PARSE_STRING_INTEGER_BASE_2,
   CLIAUTH_PARSE_STRING_INTEGER_BASE_8,
   CLIAUTH_PARSE_STRING_INTEGER_BASE_10,
   CLIAUTH_PARSE_STRING_INTEGER_BASE_16,

   /* this must be the last enum variant */
   CLIAUTH_PARSE_STRING_INTEGER_BASE_AUTOMATIC
};

/*----------------------------------------------------------------------------*/
/* Attempts to read and parse an integer from a text stream.                  */
/*----------------------------------------------------------------------------*/
/* output - The final parsed integer.  The integer will only be valid if the  */
/*          'status' field of the return result is                            */
/*          'CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS'.                    */
/*                                                                            */
/* reader - The reader interface to read from.  The integer string should     */
/*          take the following format:                                        */
/*                                                                            */
/*          [sign][base][characters]                                          */
/*                                                                            */
/*          sign - Whether the number is positive or negative.  This can      */
/*                 either be '+' for positive, or '-' for negative.  This     */
/*                 will default to positive when not present.  If the         */
/*                 'sign' parameter is not                                    */
/*                 'CLIAUTH_PARSE_STRING_INTEGER_SIGN_AUTOMATIC', an error    */
/*                 will be returned if the sign character is present.         */
/*                                                                            */
/*          base - The base of the integer.  This is a '0' character followed */
/*                 by the base character, which can be found in the           */
/*                 documentation for CliAuthParseStringIntegerBase.  This     */
/*                 will default to base-10 when not present.  If the 'base'   */
/*                 parameter is not                                           */
/*                 'CLIAUTH_PARSE_STRING_INTEGER_SIGN_AUTOMATIC', an error    */
/*                 will be returned if the base lharacters are present.       */
/*                                                                            */
/*          characters - The integer string characters.  Valid characters for */
/*                       each possible base can be found in the documentation */
/*                       for CliAuthParseStringIntegerBase.                   */
/*                                                                            */
/* characters - The number of characters to read from 'reader'.               */
/*                                                                            */
/* base - The base to parse the integer string in.                            */
/*----------------------------------------------------------------------------*/
/* Return value - The result of parsing the integer.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint8(
   CliAuthUInt8 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint16(
   CliAuthUInt16 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint32(
   CliAuthUInt32 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint64(
   CliAuthUInt64 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint8(
   CliAuthSInt8 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint16(
   CliAuthSInt16 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint32(
   CliAuthSInt32 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);
struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint64(
   CliAuthSInt64 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_PARSE_H */

