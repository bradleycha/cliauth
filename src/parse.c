/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/parse.c - Data serializer and deserializer implementations.            */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "parse.h"

#include <string.h>

static enum CliAuthParseIntegerResult
cliauth_parse_integer_digit(
   CliAuthUInt8 * output,
   char character
) {
   if (character < '0' || character > '9') {
      return CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING;
   }

   *output = character - '0';

   return CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS;
}

#define CLIAUTH_PARSE_INTEGER_UINT64_MAX_DIGITS 20

enum CliAuthParseIntegerResult
cliauth_parse_integer_uint64(
   CliAuthUInt64 * output,
   const char text [],
   CliAuthUInt32 text_characters
) {
   enum CliAuthParseIntegerResult result;
   const char * text_iter;
   CliAuthUInt32 digits_parsed;
   CliAuthUInt8 digit;

   /* initialize running total to zero */
   *output = 0;

   /* parse and accumulate each digit */
   digits_parsed = 0;
   text_iter = text;
   while (text_characters != 0) {
      /* check if we've reached the maximum number of digits */
      if (digits_parsed == CLIAUTH_PARSE_INTEGER_UINT64_MAX_DIGITS) {
         return CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE;
      }

      /* shift the current total up by 1 decimal digit */
      *output *= 10;

      /* attempt to convert the digit to numerical representation */
      result = cliauth_parse_integer_digit(&digit, *text_iter);
      if (result != CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS) {
         return result;
      }

      /* chech to make sure this won't overflow */
      if (CLIAUTH_UINT64_MAX - *output < digit) {
         return CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE;
      }

      /* append the new digit */
      *output += digit;

      /* iterate to next digit */
      text_iter++;
      text_characters--;
      digits_parsed++;
   }

   return CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS;
}

static CliAuthBoolean
cliauth_parse_base32_is_valid_character(char digit) {
   if (digit >= 'A' && digit <= 'Z') {
      return CLIAUTH_BOOLEAN_TRUE;
   }
   if (digit >= '2' && digit <= '7') {
      return CLIAUTH_BOOLEAN_TRUE;
   }

   return CLIAUTH_BOOLEAN_FALSE;
}

static CliAuthUInt8
cliauth_parse_base32_digit(char digit) {
   if (digit >= '2' && digit <= '7') {
      return digit - '2' + 26;
   }

   return digit - 'A';
}

static CliAuthUInt16
cliauth_parse_base32_append_shift_buffer(CliAuthUInt8 value, CliAuthUInt8 current_bits) {
   CliAuthUInt16 output;

   output = (CliAuthUInt16)value;
   output = output << ((sizeof(CliAuthUInt16) * 8) - 5 - current_bits);

   return output;
}

static CliAuthUInt8
cliauth_parse_base32_take_byte(CliAuthUInt16 shift_buffer) {
   return (CliAuthUInt8)(shift_buffer >> 8);
}

enum CliAuthParseBase32DecodeResult
cliauth_parse_base32_decode(
   void * output,
   CliAuthUInt32 * output_bytes,
   const char input [],
   CliAuthUInt32 input_characters
) {
   CliAuthUInt8 * output_iter;
   const char * input_iter;
   CliAuthUInt16 shift_buffer;
   CliAuthUInt8 value; 
   CliAuthUInt8 shift_buffer_bits;
   char digit;

   /* this algorithm basically uses a 16-bit integer to server as a buffer to */
   /* shift and append bits from left to right.  if we have 8 or more bits */
   /* stored in the shift buffer, we form a complete byte from it and shift */
   /* left by 8 to start forming a new byte. */

   output_iter = (CliAuthUInt8 *)output;
   input_iter = input;
   shift_buffer = 0;
   shift_buffer_bits = 0;
   *output_bytes = 0;

   while (input_characters != 0) {
      digit = *input_iter;

      /* check if the character is just padding */
      if (digit == '=') {
         input_iter++;
         input_characters--;
         continue;
      }

      /* verify the character is a valid base32 digit */
      if (cliauth_parse_base32_is_valid_character(digit) == CLIAUTH_BOOLEAN_FALSE) {
         return CLIAUTH_PARSE_BASE32_DECODE_RESULT_INVALID_ENCODING;
      }

      /* parse the digit into its integer value */
      value = cliauth_parse_base32_digit(digit);

      /* append the digit bits to the shift buffer */
      shift_buffer |= cliauth_parse_base32_append_shift_buffer(value, shift_buffer_bits);
      shift_buffer_bits += 5;

      /* if possible, form a complete byte */
      if (shift_buffer_bits >= 8) {
         *output_iter = cliauth_parse_base32_take_byte(shift_buffer);
         *output_bytes += 1;

         shift_buffer <<= 8;
         shift_buffer_bits -= 8;

         output_iter++;
      }

      input_iter++;
      input_characters--;
   }

   /* any remaining bits that don't form a full byte are discarded */

   return CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS;
}

