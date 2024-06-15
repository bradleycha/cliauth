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

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_parse_integer_*().                          */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS - The integer was parsed              */
/*                                        successfully.                       */
/*                                                                            */
/* CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING - One or more invalid        */
/*                                                 characters were            */
/*                                                 encountered.               */
/*                                                                            */
/* CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE - The number cannot be           */
/*                                             stored inside the integer      */
/*                                             without overflow/underflow.    */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_INTEGER_RESULT_FIELD_COUNT 3
enum CliAuthParseIntegerResult {
   CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS,
   CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING,
   CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE
};

/*----------------------------------------------------------------------------*/
/* Parses a decimal string to an integer.                                     */
/*----------------------------------------------------------------------------*/
/* output - The resulting parsed integer.  This is only valid if the function */
/*          returns 'CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS'.                   */
/*                                                                            */
/* text - A string which contains the integer to be parsed.  This string does */
/*        not need to be null-terminated.                                     */
/*                                                                            */
/* text_characters - The length of 'text' in characters.                      */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the state of the parsed integer in     */
/*                'output'.                                                   */
/*----------------------------------------------------------------------------*/
enum CliAuthParseIntegerResult
cliauth_parse_integer_uint64(
   CliAuthUInt64 * output,
   const char text [],
   CliAuthUInt32 text_characters
);

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_parse_base32_decode().                      */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS - The base-32 string was        */
/*                                              decoded successfully.         */
/*                                                                            */
/* CLIAUTH_PARSE_BASE32_DECODE_RESULT_INVALID_ENCODING - One or more invalid  */
/*                                                       characters were      */
/*                                                       encountered.         */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_BASE32_DECODE_RESULT_FIELD_COUNT 2
enum CliAuthParseBase32DecodeResult {
   CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS,
   CLIAUTH_PARSE_BASE32_DECODE_RESULT_INVALID_ENCODING
};

/*----------------------------------------------------------------------------*/
/* Decodes an RFC 4648 base-32 ASCII string to an array of bytes.             */
/*----------------------------------------------------------------------------*/
/* output - A byte array to store the resulting bytes in.  Any remaining      */
/*          characters which cannot create a full byte will be truncated.     */
/*          This array must be large enough to store the decoded input        */
/*          string.  The required size of this buffer in bytes can be         */
/*          determined with the following formula:                            */
/*                                                                            */
/*          maximum bytes = floor(maximum base-32 string length * 5 / 8)      */
/*                                                                            */
/*          Conversely, the following formula can be used to calculate the    */
/*          maximum acceptable base-32 string length from a known buffer      */
/*          length:                                                           */
/*                                                                            */
/*          maximum base-32 string length = ceil(maximum bytes * 8 / 5)       */
/*                                                                            */
/*          The decoded byte data will only be valid if the function returns  */
/*          'CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS'.                     */
/*                                                                            */
/* output_bytes - A pointer to the variable to store the final length of the  */
/*                decoded byte data to.  The output byte length will only be  */
/*                valid is the function returns                               */
/*                'CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS'.               */
/*                                                                            */
/* input - The base-32 string to be decoded.  This string does not have to be */
/*         null-terminated.                                                   */
/*                                                                            */
/* input_characters - The length of 'input' in characters.                    */
/*----------------------------------------------------------------------------*/
/* Return value - The output state of the decoded base-32 string in 'output'. */
/*----------------------------------------------------------------------------*/
enum CliAuthParseBase32DecodeResult
cliauth_parse_base32_decode(
   void * output,
   CliAuthUInt32 * output_bytes,
   const char input [],
   CliAuthUInt32 input_characters
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_PARSE_H */

