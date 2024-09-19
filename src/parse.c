/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/parse.c - Data serializer and deserializer implementations.            */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "parse.h"

#include "io.h"
#include "bitwise.h"

/* an integer represented in sign-magnitude format*/
struct CliAuthParseStringIntegerSignMagnitude {
   enum CliAuthParseStringIntegerSign sign;
   CliAuthUInt64 magnitude;
};

/* general parsing state for string integers */
struct CliAuthParseStringIntegerState {
   /* the base to parse digits as */
   enum CliAuthParseStringIntegerBase base;

   /* the current value */
   struct CliAuthParseStringIntegerSignMagnitude value;

   /* the number of remaining characters */
   CliAuthUInt32 characters_remaining;

   /* whether to automatically detect the sign or not */
   CliAuthBoolean detect_sign;

   /* whether to automatically detect the base or not */
   CliAuthBoolean detect_base;

   /* whether the sign character was encountered yet */
   CliAuthBoolean encountered_sign;

   /* whether the base prefix character was encountered */
   CliAuthBoolean encountered_base_prefix;

   /* whether the base prefix character was encountered on the last character */
   CliAuthBoolean encountered_base_prefix_previous;

   /* whether the base character was encountered */
   CliAuthBoolean encountered_base;

   /* whether a normal digit was encountered */
   CliAuthBoolean encountered_digit;
};

/* parses a character into its integer value */
typedef enum CliAuthParseStringIntegerStatus (*CliAuthParseStringIntegerBaseDigitContextParser)(
   CliAuthUInt8 * output,
   char digit
);

/* information used to parse digits in an arbitrary number base */
struct CliAuthParseStringIntegerBaseDigitContext {
   CliAuthParseStringIntegerBaseDigitContextParser parser;
   CliAuthUInt8 value;
};

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_base_digit_context_parser_base_2(
   CliAuthUInt8 * output,
   char digit
) {
   if (digit >= '0' && digit <= '1') {
      *output = (CliAuthUInt8)(digit - '0');
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT;
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_base_digit_context_parser_base_8(
   CliAuthUInt8 * output,
   char digit
) {
   if (digit >= '0' && digit <= '7') {
      *output = (CliAuthUInt8)(digit - '0');
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT;
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_base_digit_context_parser_base_10(
   CliAuthUInt8 * output,
   char digit
) {
   if (digit >= '0' && digit <= '9') {
      *output = (CliAuthUInt8)(digit - '0');
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT;
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_base_digit_context_parser_base_16(
   CliAuthUInt8 * output,
   char digit
) {
   if (digit >= '0' && digit <= '9') {
      *output = (CliAuthUInt8)(digit - '0');
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
   }
   if (digit >= 'a' && digit <= 'f') {
      *output = (CliAuthUInt8)(digit - 'a') + 10;
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
   }
   if (digit >= 'A' && digit <= 'F') {
      *output = (CliAuthUInt8)(digit - 'A') + 10;
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
   }

   return CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT;
}

/* table of base digit contexts for every possible base */
static const struct CliAuthParseStringIntegerBaseDigitContext
cliauth_parse_string_integer_base_digit_contexts [CLIAUTH_PARSE_STRING_INTEGER_BASE_FIELD_COUNT - 1] = {
   { /* CLIAUTH_PARSE_STRING_INTEGER_BASE_2 */
      cliauth_parse_string_integer_base_digit_context_parser_base_2,
      2
   },
   { /* CLIAUTH_PARSE_STRING_INTEGER_BASE_8 */
      cliauth_parse_string_integer_base_digit_context_parser_base_8,
      8
   },
   { /* CLIAUTH_PARSE_STRING_INTEGER_BASE_10 */
      cliauth_parse_string_integer_base_digit_context_parser_base_10,
      10
   },
   { /* CLIAUTH_PARSE_STRING_INTEGER_BASE_16 */
      cliauth_parse_string_integer_base_digit_context_parser_base_16,
      16
   }
};

/* initializes the string integer parsing state to default values */
static void
cliauth_parse_string_integer_state_initialize(
   struct CliAuthParseStringIntegerState * state,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base,
   CliAuthUInt32 characters
) {
   state->value.magnitude = 0;
   state->characters_remaining = characters;
   state->encountered_sign = CLIAUTH_BOOLEAN_FALSE;
   state->encountered_base_prefix = CLIAUTH_BOOLEAN_FALSE;
   state->encountered_base_prefix_previous = CLIAUTH_BOOLEAN_FALSE;
   state->encountered_base = CLIAUTH_BOOLEAN_FALSE;
   state->encountered_digit = CLIAUTH_BOOLEAN_FALSE;

   if (sign == CLIAUTH_PARSE_STRING_INTEGER_SIGN_AUTOMATIC) {
      state->value.sign = CLIAUTH_PARSE_STRING_INTEGER_SIGN_POSITIVE;
      state->detect_sign = CLIAUTH_BOOLEAN_TRUE;
   } else {
      state->value.sign = sign;
      state->detect_sign = CLIAUTH_BOOLEAN_FALSE;
   }

   if (base == CLIAUTH_PARSE_STRING_INTEGER_BASE_AUTOMATIC) {
      state->base = CLIAUTH_PARSE_STRING_INTEGER_BASE_10;
      state->detect_base = CLIAUTH_BOOLEAN_TRUE;
   } else {
      state->base = base;
      state->detect_base = CLIAUTH_BOOLEAN_FALSE;
   }

   return;
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_state_digest_magnitude_digit(
   struct CliAuthParseStringIntegerState * state,
   char digit
) {
   enum CliAuthParseStringIntegerStatus status;
   const struct CliAuthParseStringIntegerBaseDigitContext * base_digit_context;
   CliAuthUInt8 value;
   CliAuthUInt64 magnitude_appended;

   /* get the base digit context struct */
   base_digit_context = &cliauth_parse_string_integer_base_digit_contexts[state->base];

   /* convert the digit into its integer value */
   status = base_digit_context->parser(
      &value,
      digit
   );
   if (status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
      return status;
   }

   /* prepare to append the digit to the magnitude */
   magnitude_appended = state->value.magnitude;

   /* shift the existing magnitude up one digit, checking if it will overflow */
   if (magnitude_appended > CLIAUTH_UINT64_MAX / base_digit_context->value) {
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE;
   }
   magnitude_appended *= base_digit_context->value;

   /* append the digit, checking if it will overflow */
   if (magnitude_appended > CLIAUTH_UINT64_MAX - value) {
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE;
   }
   magnitude_appended += value;

   /* store the new magnitude */
   state->value.magnitude = magnitude_appended;

   return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
}

#define CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_POSITIVE\
   '+'
#define CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_NEGATIVE\
   '-'
#define CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_ESCAPE\
   '0'
#define CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_2\
   'b'
#define CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_8\
   'o'
#define CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_16\
   'x'

/* TODO: Add new API for iterating over UTF-8 and UTF-16 strings.  This code */
/* only works for ASCII.  This shouldn't require too much modifications to */
/* existing code: use codepoints instead of raw chars.  The real work is */
/* iterating over strings in differing formats. */

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_state_digest_prefix_character_sign(
   struct CliAuthParseStringIntegerState * state,
   char character
) {
   enum CliAuthParseStringIntegerSign sign;

   if (state->detect_sign == CLIAUTH_BOOLEAN_FALSE) {
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_UNEXPECTED_SIGN;
   }
   if (state->encountered_sign == CLIAUTH_BOOLEAN_TRUE) {
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT;
   }
   if (state->encountered_base_prefix == CLIAUTH_BOOLEAN_TRUE) {
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT;
   }
   if (state->encountered_digit == CLIAUTH_BOOLEAN_TRUE) {
      return CLIAUTH_PARSE_STRING_INTEGER_STATUS_INVALID_DIGIT;
   }

   switch (character) {
      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_POSITIVE:
         sign = CLIAUTH_PARSE_STRING_INTEGER_SIGN_POSITIVE;
         break;

      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_NEGATIVE:
         sign = CLIAUTH_PARSE_STRING_INTEGER_SIGN_NEGATIVE;
         break;
   }

   state->value.sign = sign;
   state->encountered_sign = CLIAUTH_BOOLEAN_TRUE;

   return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_state_digest_prefix_character_base_prefix(
   struct CliAuthParseStringIntegerState * state,
   char character
) {
   enum CliAuthParseStringIntegerStatus status;

   /* if we aren't using automatic sign detection, parse as a digit but also */
   /* note that we passed the base prefix */
   if (
      state->detect_base == CLIAUTH_BOOLEAN_FALSE ||
      state->encountered_digit == CLIAUTH_BOOLEAN_TRUE
   ) {
      status = cliauth_parse_string_integer_state_digest_magnitude_digit(
         state,
         character
      );
   } else {
      status = CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
      state->encountered_base_prefix = CLIAUTH_BOOLEAN_TRUE;
      state->encountered_base_prefix_previous = CLIAUTH_BOOLEAN_TRUE;
   }

   return status;
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_state_digest_prefix_character_base(
   struct CliAuthParseStringIntegerState * state,
   char character
) {
   enum CliAuthParseStringIntegerBase base;

   /* if we aren't parsing a base, just treat the character as a digit */
   if (
      state->detect_base == CLIAUTH_BOOLEAN_FALSE ||
      state->encountered_base_prefix_previous == CLIAUTH_BOOLEAN_FALSE
   ) {
      return cliauth_parse_string_integer_state_digest_magnitude_digit(
         state,
         character
      );
   }

   /* attempt to convert the character to its relevant base, note how the */
   /* previous code makes it impossible to parse an invalid prefix */
   switch (character) {
      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_2:
         base = CLIAUTH_PARSE_STRING_INTEGER_BASE_2;
         break;

      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_8:
         base = CLIAUTH_PARSE_STRING_INTEGER_BASE_8;
         break;

      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_16:
         base = CLIAUTH_PARSE_STRING_INTEGER_BASE_16;
         break;
   }

   /* mark the base character as encountered and set the new base */
   state->base = base;
   state->encountered_base_prefix_previous = CLIAUTH_BOOLEAN_FALSE;
   state->encountered_base = CLIAUTH_BOOLEAN_TRUE;

   return CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS;
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_state_digest_prefix_character_default(
   struct CliAuthParseStringIntegerState * state,
   char character
) {
   enum CliAuthParseStringIntegerStatus status;

   /* if we just encountered the base prefix, make sure to parse it */
   if (state->encountered_base_prefix_previous == CLIAUTH_BOOLEAN_TRUE) {
      status = cliauth_parse_string_integer_state_digest_magnitude_digit(
         state,
         CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_ESCAPE
      );
      state->encountered_base_prefix_previous = CLIAUTH_BOOLEAN_FALSE;

      if (status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
         return status;
      }
   }

   state->encountered_digit = CLIAUTH_BOOLEAN_TRUE;

   return cliauth_parse_string_integer_state_digest_magnitude_digit(
      state,
      character
   );
}

static enum CliAuthParseStringIntegerStatus
cliauth_parse_string_integer_state_digest_prefix_character(
   struct CliAuthParseStringIntegerState * state,
   char character
) {
   enum CliAuthParseStringIntegerStatus status; 

   switch (character) {
      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_POSITIVE:
      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_NEGATIVE:
         status = cliauth_parse_string_integer_state_digest_prefix_character_sign(
            state,
            character
         );
         break;

      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_ESCAPE:
         status = cliauth_parse_string_integer_state_digest_prefix_character_base_prefix(
            state,
            character
         );
         break;

      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_2:
      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_8:
      case CLIAUTH_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_16:
         status = cliauth_parse_string_integer_state_digest_prefix_character_base(
            state,
            character
         );
         break;

      default:
         status = cliauth_parse_string_integer_state_digest_prefix_character_default(
            state,
            character
         );
         break;
   }

   return status;
}

/* the maximum possible number of characters the prefix can be */
/* ex: -0x, +0b */
#define CLIAUTH_PARSE_STRING_INTEGER_PREFIX_MAX_CHARACTERS\
   3

static struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_state_digest_prefix(
   struct CliAuthParseStringIntegerState * state,
   const struct CliAuthIoReader * reader
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthUInt8 prefix_buffer [CLIAUTH_PARSE_STRING_INTEGER_PREFIX_MAX_CHARACTERS];
   CliAuthUInt32 prefix_characters;
   const CliAuthUInt8 * prefix_iter;

   /* decide on the number of characters to read in.  if the length of the */
   /* entire string is less than the maximum prefix length, read in the whole */
   /* string as the prefix characters. */
   if (state->characters_remaining < CLIAUTH_PARSE_STRING_INTEGER_PREFIX_MAX_CHARACTERS) {
      prefix_characters = state->characters_remaining;
   } else {
      prefix_characters = CLIAUTH_PARSE_STRING_INTEGER_PREFIX_MAX_CHARACTERS;
   }

   /* attempt to read in the prefix string */
   result.read_result = cliauth_io_reader_read_all(
      reader,
      prefix_buffer,
      prefix_characters * sizeof(char)
   );
   state->characters_remaining -= result.read_result.bytes / sizeof(char);

   if (result.read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
      result.status = CLIAUTH_PARSE_STRING_INTEGER_STATUS_IO_ERROR;
      return result;
   }

   /* parse all the characters in the prefix */
   prefix_iter = prefix_buffer;
   while (prefix_characters != 0) {
      result.status = cliauth_parse_string_integer_state_digest_prefix_character(
         state,
         *prefix_iter
      );
      if (result.status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
         return result;
      }

      prefix_iter++;
      prefix_characters--;
   }

   /* successful result status is already set, return success */
   return result;
}

static struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_state_digest_magnitude(
   struct CliAuthParseStringIntegerState * state,
   const struct CliAuthIoReader * reader
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthUInt32 bytes_read;
   CliAuthUInt8 digit;

   bytes_read = 0;
   while (state->characters_remaining != 0) {
      result.read_result = cliauth_io_reader_read_all(
         reader,
         &digit,
         sizeof(digit)
      );
      bytes_read += result.read_result.bytes;

      if (result.read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
         result.status = CLIAUTH_PARSE_STRING_INTEGER_STATUS_IO_ERROR;
         return result;
      }

      result.status = cliauth_parse_string_integer_state_digest_magnitude_digit(
         state,
         digit
      );

      if (result.status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
         result.read_result.bytes = bytes_read;
         return result;
      }

      state->characters_remaining -= 1;
   }

   result.read_result.bytes = bytes_read;
   return result;
}

/* parses a string integer to its sign-magnitude representation */
static struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sign_magnitude(
   struct CliAuthParseStringIntegerSignMagnitude * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   struct CliAuthParseStringIntegerResult result;
   struct CliAuthParseStringIntegerState state;
   CliAuthUInt32 bytes_read;

   /* initialize the parsing state */
   cliauth_parse_string_integer_state_initialize(
      &state,
      sign,
      base,
      characters
   );
   bytes_read = 0;

   /* attempt to parse the sign character and base */
   result = cliauth_parse_string_integer_state_digest_prefix(
      &state,
      reader
   );
   bytes_read += result.read_result.bytes;

   if (result.status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
      result.read_result.bytes = bytes_read;
      return result;
   }

   /* attempt to parse the rest of the characters as the magnitude */
   result = cliauth_parse_string_integer_state_digest_magnitude(
      &state,
      reader
   );
   bytes_read += result.read_result.bytes;

   if (result.status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
      result.read_result.bytes = bytes_read;
      return result;
   }
   
   /* write the final sign and magnitude integer */
   *output = state.value;

   /* results are reused from previous function call, just need to accumulate */
   /* the total number of read bytes */
   result.read_result.bytes = bytes_read;
   return result;
}

/* parses a string integer to its maximum representable unsigned integer */
/* value */
static struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint(
   CliAuthUInt64 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base,
   CliAuthUInt64 maximum_value_magnitude
) {
   struct CliAuthParseStringIntegerResult result;
   struct CliAuthParseStringIntegerSignMagnitude sign_magnitude;

   /* parse the string integer to sign and magnitude */
   result = cliauth_parse_string_integer_sign_magnitude(
      &sign_magnitude,
      reader,
      characters,
      sign,
      base
   );
   if (result.status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
      return result;
   }

   /* guard against a corner case where a negative zero will be considered out of range */
   if (sign_magnitude.magnitude == 0) {
      *output = 0;
      return result;
   }

   /* make sure the magnitude is within range */
   if (sign_magnitude.magnitude > maximum_value_magnitude) {
      result.status = CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE;
      return result;
   }

   /* make sure the value is positive */
   if (sign_magnitude.sign == CLIAUTH_PARSE_STRING_INTEGER_SIGN_NEGATIVE) {
      result.status = CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE;
      return result;
   }

   /* output the parsed integer */
   *output = sign_magnitude.magnitude;

   return result;
}

static void
cliauth_parse_string_integer_sint_positive(
   CliAuthSInt64 * output,
   struct CliAuthParseStringIntegerResult * result,
   CliAuthUInt64 magnitude,
   CliAuthUInt64 maximum_value_magnitude
) {
   union CliAuthInt64 value;

   if (magnitude > maximum_value_magnitude) {
      result->status = CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE;
      return;
   }

   value.uint = magnitude;

   *output = value.sint;
   
   return;
}

static void
cliauth_parse_string_integer_sint_negative(
   CliAuthSInt64 * output,
   struct CliAuthParseStringIntegerResult * result,
   CliAuthUInt64 magnitude,
   CliAuthUInt64 minimum_value_magnitude
) {
   if (magnitude > minimum_value_magnitude) {
      result->status = CLIAUTH_PARSE_STRING_INTEGER_STATUS_OUT_OF_RANGE;
      return;
   }

   *output = cliauth_bitwise_magnitude_deposit_negative_sint64(
      magnitude
   );
   
   return;
}

/* parses a string integer to its maximum representable signed integer value */
static struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint(
   CliAuthSInt64 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base,
   CliAuthUInt64 maximum_value_magnitude,
   CliAuthUInt64 minimum_value_magnitude
) {
   struct CliAuthParseStringIntegerResult result;
   struct CliAuthParseStringIntegerSignMagnitude sign_magnitude;

   /* parse the string integer to sign and magnitude */
   result = cliauth_parse_string_integer_sign_magnitude(
      &sign_magnitude,
      reader,
      characters,
      sign,
      base
   );
   if (result.status != CLIAUTH_PARSE_STRING_INTEGER_STATUS_SUCCESS) {
      return result;
   }

   /* check for zero magnitude to prevent possible issues with checks and */
   /* conversion, similar to the check in the uint version */
   if (sign_magnitude.magnitude == 0) {
      *output = 0;
      return result;
   }

   /* perform range checking and sign conversion */
   if (sign_magnitude.sign == CLIAUTH_PARSE_STRING_INTEGER_SIGN_POSITIVE) {
      cliauth_parse_string_integer_sint_positive(
         output,
         &result,
         sign_magnitude.magnitude,
         maximum_value_magnitude
      );
   }
   if (sign_magnitude.sign == CLIAUTH_PARSE_STRING_INTEGER_SIGN_NEGATIVE) {
      cliauth_parse_string_integer_sint_negative(
         output,
         &result,
         sign_magnitude.magnitude,
         minimum_value_magnitude
      );
   }

   /* the result will be leftover from the previous function calls, so no */
   /* additional checks or enum setting is necessary */
   return result;
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint8(
   CliAuthUInt8 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthUInt64 generic_output;

   result = cliauth_parse_string_integer_uint(
      &generic_output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_UINT8_MAX
   );

   *output = (CliAuthUInt8)generic_output;

   return result;
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint16(
   CliAuthUInt16 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthUInt64 generic_output;

   result = cliauth_parse_string_integer_uint(
      &generic_output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_UINT16_MAX
   );

   *output = (CliAuthUInt16)generic_output;

   return result;
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint32(
   CliAuthUInt32 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthUInt64 generic_output;

   result = cliauth_parse_string_integer_uint(
      &generic_output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_UINT32_MAX
   );

   *output = (CliAuthUInt32)generic_output;

   return result;
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_uint64(
   CliAuthUInt64 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   /* we are already in the native type, no conversion needed */
   return cliauth_parse_string_integer_uint(
      output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_UINT64_MAX
   );
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint8(
   CliAuthSInt8 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthSInt64 generic_output;

   result = cliauth_parse_string_integer_sint(
      &generic_output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_SINT8_MAX,
      cliauth_bitwise_magnitude_extract_negative_sint64(
         (CliAuthSInt64)CLIAUTH_SINT8_MIN
      )
   );

   *output = (CliAuthSInt8)generic_output;

   return result;
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint16(
   CliAuthSInt16 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthSInt64 generic_output;

   result = cliauth_parse_string_integer_sint(
      &generic_output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_SINT16_MAX,
      cliauth_bitwise_magnitude_extract_negative_sint64(
         (CliAuthSInt64)CLIAUTH_SINT16_MIN
      )
   );

   *output = (CliAuthSInt16)generic_output;

   return result;
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint32(
   CliAuthSInt32 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   struct CliAuthParseStringIntegerResult result;
   CliAuthSInt64 generic_output;

   result = cliauth_parse_string_integer_sint(
      &generic_output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_SINT32_MAX,
      cliauth_bitwise_magnitude_extract_negative_sint64(
         (CliAuthSInt64)CLIAUTH_SINT32_MIN
      )
   );

   *output = (CliAuthSInt32)generic_output;

   return result;
}

struct CliAuthParseStringIntegerResult
cliauth_parse_string_integer_sint64(
   CliAuthSInt64 * output,
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 characters,
   enum CliAuthParseStringIntegerSign sign,
   enum CliAuthParseStringIntegerBase base
) {
   /* again, we are already using the native types so no conversion is needed */
   return cliauth_parse_string_integer_sint(
      output,
      reader,
      characters,
      sign,
      base,
      CLIAUTH_SINT64_MAX,
      cliauth_bitwise_magnitude_extract_negative_sint64(
         CLIAUTH_SINT64_MIN
      )
   );
}

