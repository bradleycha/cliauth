/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/parse/string_integer.h - String integer parser.                     */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_PARSE_STRING_INTEGER_H
#define _CLIAUTH_IO_PARSE_STRING_INTEGER_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io/io.h"

/*----------------------------------------------------------------------------*/
/* The result status of digesting string integer characters.                  */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS -                    */
/*    The integer was parsed successfully.                                    */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_IO_ERROR -                   */
/*    An I/O error occurred.                                                  */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_INVALID_DIGIT -              */
/*    An invalid digit for the expected base was encountered.                 */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_OUT_OF_RANGE -               */
/*    The number is outside the range of possible values for the given        */
/*    allowable range.                                                        */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_UNEXPECTED_SIGN -            */
/*    A sign character was found when the sign was already given.             */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_FIELD_COUNT 5u
enum CliAuthIoParseStringIntegerDigestStatus {
   CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS,
   CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_IO_ERROR,
   CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_INVALID_DIGIT,
   CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_OUT_OF_RANGE,
   CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_UNEXPECTED_SIGN
};

/*----------------------------------------------------------------------------*/
/* The payload struct for when an invalid digit is encountered.               */
/*----------------------------------------------------------------------------*/
/* digit -                                                                    */
/*    The digit which could not be parsed.                                    */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringIntegerDigestPayloadInvalidDigit {
   CliAuthUInt8 digit;
};

/*----------------------------------------------------------------------------*/
/* The payload struct for when an unexpected sign character is encountered.   */
/*----------------------------------------------------------------------------*/
/* character -                                                                */
/*    The unexpected sign character.                                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringIntegerDigestPayloadUnexpectedSign {
   CliAuthUInt8 character;
};

/*----------------------------------------------------------------------------*/
/* The payload struct for when a status enum contains additional data.        */
/*----------------------------------------------------------------------------*/
/* invalid_digit -                                                            */
/*    The payload data for CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_...  */
/*    ...INVALID_DIGIT.                                                       */
/*                                                                            */
/* unexpected_sign -                                                          */
/*    The payload data for CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_...  */
/*    ...UNEXPECTED_SIGN.                                                     */
/*----------------------------------------------------------------------------*/
union CliAuthIoParseStringIntegerDigestPayload {
   struct CliAuthIoParseStringIntegerDigestPayloadInvalidDigit invalid_digit;
   struct CliAuthIoParseStringIntegerDigestPayloadUnexpectedSign unexpected_sign;
};

/*----------------------------------------------------------------------------*/
/* The result of attempting to digest bytes into a string integer parser.     */
/*----------------------------------------------------------------------------*/
/* status -                                                                   */
/*    The status of the string integer digestion.                             */
/*                                                                            */
/* payload -                                                                  */
/*    Additional data relevant to the status of string integer digestion.     */
/*                                                                            */
/* read_result -                                                              */
/*    The I/O read result.  This will contain further details about potential */
/*    I/O read errors.                                                        */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringIntegerDigestResult {
   enum CliAuthIoParseStringIntegerDigestStatus status;
   union CliAuthIoParseStringIntegerDigestPayload payload;
   struct CliAuthIoResult read_result;
};

/*----------------------------------------------------------------------------*/
/* A sign to parse a string integer as.                                       */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_POSITIVE -                            */
/*    Treat the string integer as positive.                                   */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_NEGATIVE -                            */
/*    Treat the string integer as negative.                                   */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC -                           */
/*    The integer string's sign will be determined from the prefix character. */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_FIELD_COUNT 3u
enum CliAuthIoParseStringIntegerSign {
   CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_POSITIVE,
   CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_NEGATIVE,
   CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC
};

/*----------------------------------------------------------------------------*/
/* A base to parse a string integer as.                                       */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_2 -                                   */
/*    A base-2 integer string, also known as a binary string.  The following  */
/*    characters have the given decimal value:                                */
/*                                                                            */
/*    0 - 0                                                                   */
/*    1 - 1                                                                   */
/*                                                                            */
/*    The base character for base-2 is 'b'.                                   */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_8 -                                   */
/*    A base-8 integer string, also known as an octal string.  The following  */
/*    characters have the given decimal value:                                */
/*                                                                            */
/*    0 - 0                                                                   */
/*    1 - 1                                                                   */
/*    2 - 2                                                                   */
/*    3 - 3                                                                   */
/*    4 - 4                                                                   */
/*    5 - 5                                                                   */
/*    6 - 6                                                                   */
/*    7 - 7                                                                   */
/*                                                                            */
/*    The base character for base-8 is 'o'.                                   */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_10 -                                  */
/*    A base-10 integer string, also known as a decimal string.  The          */
/*    following characters have the given decimal value:                      */
/*                                                                            */
/*    0 - 0                                                                   */
/*    1 - 1                                                                   */
/*    2 - 2                                                                   */
/*    3 - 3                                                                   */
/*    4 - 4                                                                   */
/*    5 - 5                                                                   */
/*    6 - 6                                                                   */
/*    7 - 7                                                                   */
/*    8 - 8                                                                   */
/*    9 - 9                                                                   */
/*                                                                            */
/*    There is no base character for base-10.  An integer string with no      */
/*    prefix will default to base-10.                                         */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_16 -                                  */
/*    A base-16 integer string, also known as a hexadecimal string.  The      */
/*    following characters have the given hexadecimal value:                  */
/*                                                                            */
/*    0    - 0                                                                */
/*    1    - 1                                                                */
/*    2    - 2                                                                */
/*    3    - 3                                                                */
/*    4    - 4                                                                */
/*    5    - 5                                                                */
/*    6    - 6                                                                */
/*    7    - 7                                                                */
/*    8    - 8                                                                */
/*    9    - 9                                                                */
/*    a, A - 10                                                               */
/*    b, B - 11                                                               */
/*    c, C - 12                                                               */
/*    d, D - 13                                                               */
/*    e, E - 14                                                               */
/*    f, F - 15                                                               */
/*                                                                            */
/*    The base character for base-16 is 'x'.                                  */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_AUTOMATIC -                           */
/*    The integer string's base will be determined automatically from the     */
/*    prefix character.                                                       */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_FIELD_COUNT 5u
enum CliAuthIoParseStringIntegerBase {
   /* this is only used to define enum values and should never be used */
   _CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_START_INDEX = -1,

   CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_2,
   CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_8,
   CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_10,
   CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_16,

   /* this must be the last enum variant */
   CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_AUTOMATIC
};

/*----------------------------------------------------------------------------*/
/* A sign-magnitude integer value.                                            */
/*----------------------------------------------------------------------------*/
/* sign -                                                                     */
/*    Whether the value is positive or negative.  This should never be set to */
/*    CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC.                         */
/*                                                                            */
/* magnitude -                                                                */
/*    The distance of the value from zero.                                    */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringIntegerValue {
   enum CliAuthIoParseStringIntegerSign sign;
   CliAuthUInt64 magnitude;
};

/*----------------------------------------------------------------------------*/
/* A range of values to consider when parsing a string integer.               */
/*----------------------------------------------------------------------------*/
/* minimum_magnitude_negative -                                               */
/*    The minimum negative magnitude to consider.  All values below will give */
/*    an error.                                                               */
/*                                                                            */
/* maximum_magnitude_positive -                                               */
/*    The maximum positive magnitude to consider.  All values above will give */
/*    an error.                                                               */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringIntegerRange {
   CliAuthUInt64 minimum_magnitude_negative;
   CliAuthUInt64 maximum_magnitude_positive;
};

/*----------------------------------------------------------------------------*/
/* Context for the string integer parser.                                     */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringIntegerContext {
   /* the current value for all successfully parsed digits */
   struct CliAuthIoParseStringIntegerValue value;

   /* the base to parse digits as, this should never be set to automatic */
   enum CliAuthIoParseStringIntegerBase base;

   /* the range of values to consider */
   struct CliAuthIoParseStringIntegerRange range;
   
   /* boolean flags related to parsing state */
   CliAuthUInt8 flags;
};

/*----------------------------------------------------------------------------*/
/* Initializes a given string integer parser context.                         */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The string integer parser context to initialize.                        */
/*                                                                            */
/* sign -                                                                     */
/*    The sign to parse the string integer in.                                */
/*                                                                            */
/* base -                                                                     */
/*    The base to parse the string integer in.                                */
/*                                                                            */
/* range -                                                                    */
/*    The range of valid values to parse the string integer with.  Allowing a */
/*    range of values which may result in out-of-range integers for the       */
/*    desired output type will result in undefined behavior.                  */
/*----------------------------------------------------------------------------*/
void
cliauth_io_parse_string_integer_initialize(
   struct CliAuthIoParseStringIntegerContext * context,
   enum CliAuthIoParseStringIntegerSign sign,
   enum CliAuthIoParseStringIntegerBase base,
   const struct CliAuthIoParseStringIntegerRange * range
);

/*----------------------------------------------------------------------------*/
/* Attempts to read and digest bytes as characters into a string integer      */
/* parser from a reader.                                                      */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The string integer parser context to digest bytes into.  This must      */
/*    first have been initialized with                                        */
/*    cliauth_io_parse_string_integer_initialize().                           */
/*                                                                            */
/* reader -                                                                   */
/*    The stream reader interface to read from.  The integer string should    */
/*    take the following format:                                              */
/*                                                                            */
/*    [sign][base][characters]                                                */
/*                                                                            */
/*    sign -                                                                  */
/*       Whether the number is positive or negative.  This can either be '+'  */
/*       for positive, or '-' for negative.  This will default to positive    */
/*       when not present.  If the 'sign' parameter is not                    */
/*       'CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC', an error will be   */
/*       returned if the sign character is present.                           */
/*                                                                            */
/*    base -                                                                  */
/*       The base of the integer.  This is a '0' character followed by the    */
/*       base character, which can be found in the documentation for          */
/*       CliAuthIoParseStringIntegerBase.  This will default to base-10 when  */
/*       not present.  If the 'base' parameter is not                         */
/*       'CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC', an error will be   */
/*       returned if the base characters are present.                         */
/*                                                                            */
/*    characters -                                                            */
/*       The integer string characters.  Valid characters for each possible   */
/*       base can be found in the documentation for                           */
/*       CliAuthIoParseStringIntegerBase.                                     */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to read from 'reader'.                              */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of digesting the bytes from the reader.                      */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringIntegerDigestResult
cliauth_io_parse_string_integer_digest(
   struct CliAuthIoParseStringIntegerContext * context,
   const struct CliAuthIoStreamReader * reader,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Retrieves the current parsed string integer and converts to a standard     */
/* integer type.                                                              */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The string integer parser context to digest bytes into.  This must      */
/*    first have been initialized with                                        */
/*    cliauth_io_parse_string_integer_initialize().  The state will be        */
/*    preserved and may still have characters digested after calling this     */
/*    function.                                                               */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The final digested integer.  This function assumes that the range of    */
/*    values to be considered will always be valid for the given integer      */
/*    type.  If the range of values may result in an integer which is         */
/*    unrepresentable in the given integer size, it will result in undefined  */
/*    behavior.                                                               */
/*----------------------------------------------------------------------------*/
CliAuthUInt8
cliauth_io_parse_string_integer_finalize_uint8(
   struct CliAuthIoParseStringIntegerContext * context
);
CliAuthUInt16
cliauth_io_parse_string_integer_finalize_uint16(
   struct CliAuthIoParseStringIntegerContext * context
);
CliAuthUInt32
cliauth_io_parse_string_integer_finalize_uint32(
   struct CliAuthIoParseStringIntegerContext * context
);
CliAuthUInt64
cliauth_io_parse_string_integer_finalize_uint64(
   struct CliAuthIoParseStringIntegerContext * context
);
CliAuthSInt8
cliauth_io_parse_string_integer_finalize_sint8(
   struct CliAuthIoParseStringIntegerContext * context
);
CliAuthSInt16
cliauth_io_parse_string_integer_finalize_sint16(
   struct CliAuthIoParseStringIntegerContext * context
);
CliAuthSInt32
cliauth_io_parse_string_integer_finalize_sint32(
   struct CliAuthIoParseStringIntegerContext * context
);
CliAuthSInt64
cliauth_io_parse_string_integer_finalize_sint64(
   struct CliAuthIoParseStringIntegerContext * context
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_PARSE_STRING_INTEGER_H */

