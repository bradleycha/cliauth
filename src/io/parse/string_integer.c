/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/parse/string_integer.c - String integer parser implementation.      */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io/parse/string_integer.h"

#include "io/io.h"
#include "memory/memory.h"
#include "math/bitwise.h"

/* if the sign should be detected automatically or not */
#define CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_DETECT_SIGN\
   CLIAUTH_LITERAL_UINT8(1u << 0u)
/* if the base should be detected automatically or not */
#define CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_DETECT_BASE\
   CLIAUTH_LITERAL_UINT8(1u << 1u)
/* whether the sign character was encountered yet */
#define CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_SIGN\
   CLIAUTH_LITERAL_UINT8(1u << 2u)
/* whether the base prefix character was encountered */
#define CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE_PREFIX\
   CLIAUTH_LITERAL_UINT8(1u << 3u)
/* whether the base prefix character was encountered on the last character */
#define CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE_PREFIX_PREVIOUS\
   CLIAUTH_LITERAL_UINT8(1u << 4u)
/* whether the base character was encountered */
#define CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE\
   CLIAUTH_LITERAL_UINT8(1u << 5u)
/* whether a normal digit was encountered */
#define CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_DIGIT\
   CLIAUTH_LITERAL_UINT8(1u << 6u)

enum CliAuthIoParseStringIntegerDigitParserStatus {
   CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS,
   CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_INVALID
};

/* a function which parses a digit into its value */
typedef enum CliAuthIoParseStringIntegerDigitParserStatus (*CliAuthIoParseStringIntegerDigitParserFunction)(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
);

/* a parser function with its relevant base */
struct CliAuthIoParseStringIntegerDigitParser {
   CliAuthIoParseStringIntegerDigitParserFunction parser;  
   CliAuthUInt8 base;
};

static enum CliAuthIoParseStringIntegerDigitParserStatus
cliauth_io_parse_string_integer_digit_parser_base_2(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('1')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_INVALID;
}

static enum CliAuthIoParseStringIntegerDigitParserStatus
cliauth_io_parse_string_integer_digit_parser_base_8(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('7')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_INVALID;
}

static enum CliAuthIoParseStringIntegerDigitParserStatus
cliauth_io_parse_string_integer_digit_parser_base_10(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('9')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_INVALID;
}

static enum CliAuthIoParseStringIntegerDigitParserStatus
cliauth_io_parse_string_integer_digit_parser_base_16(
   CliAuthUInt8 * output,
   CliAuthUInt8 digit
) {
   if (digit >= CLIAUTH_LITERAL_UINT8('0') && digit <= CLIAUTH_LITERAL_UINT8('9')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('0');
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS;
   }
   if (digit >= CLIAUTH_LITERAL_UINT8('a') && digit <= CLIAUTH_LITERAL_UINT8('f')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('a') + CLIAUTH_LITERAL_UINT8(10u);
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS;
   }
   if (digit >= CLIAUTH_LITERAL_UINT8('A') && digit <= CLIAUTH_LITERAL_UINT8('F')) {
      *output = digit - CLIAUTH_LITERAL_UINT8('A') + CLIAUTH_LITERAL_UINT8(10u);
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS;
   }

   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_INVALID;
}

/* table of all digit parsers */
static const struct CliAuthIoParseStringIntegerDigitParser
cliauth_io_parse_string_integer_digit_parsers [CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_FIELD_COUNT - 1] = {
   { /* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_2 */
      cliauth_io_parse_string_integer_digit_parser_base_2,
      CLIAUTH_LITERAL_UINT8(2u)
   },
   { /* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_8 */
      cliauth_io_parse_string_integer_digit_parser_base_8,
      CLIAUTH_LITERAL_UINT8(8u)
   },
   { /* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_10 */
      cliauth_io_parse_string_integer_digit_parser_base_10,
      CLIAUTH_LITERAL_UINT8(10u)
   },
   { /* CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_16 */
      cliauth_io_parse_string_integer_digit_parser_base_16,
      CLIAUTH_LITERAL_UINT8(16u)
   }
};

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character_magnitude(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   const struct CliAuthIoParseStringIntegerDigitParser * digit_parser;
   enum CliAuthIoParseStringIntegerDigitParserStatus digit_parser_status;
   CliAuthUInt8 digit_value;
   CliAuthUInt64 magnitude_max;
   CliAuthUInt64 magnitude_new;

   /* get the relevant digit parser */
   digit_parser = &cliauth_io_parse_string_integer_digit_parsers[context->base];

   /* attempt to convert the digit to its integer value */
   digit_parser_status = digit_parser->parser(&digit_value, character);
   switch (digit_parser_status) {
      case CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_SUCCESS:
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_DIGIT_PARSER_STATUS_INVALID:
         return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_INVALID_DIGIT;

      default:
         CLIAUTH_UNREACHABLE;
   }

   /* prepare to append the digit to the magnitude */
   magnitude_new = context->value.magnitude;

   /* choose which maximum magnitude we care about */
   switch (context->value.sign) {
      case CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_POSITIVE:
         magnitude_max = context->range.maximum_magnitude_positive;
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_NEGATIVE:
         magnitude_max = context->range.minimum_magnitude_negative;
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC:
         CLIAUTH_UNREACHABLE;

      default:
         CLIAUTH_UNREACHABLE;
   }

   /* shift the magnitude over for the new digit, checking if it will */
   /* overflow */
   if (magnitude_new > magnitude_max / digit_parser->base) {
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_OUT_OF_RANGE;
   }
   magnitude_new *= digit_parser->base;

   /* append the new digit to the shifted magnitude, checking if it will */
   /* overflow */
   if (magnitude_new > magnitude_max - digit_value) {
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_OUT_OF_RANGE;
   }
   magnitude_new += digit_value;

   /* store the new magnitude and return */
   context->value.magnitude = magnitude_new;
   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS;
}

#define CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_POSITIVE\
   CLIAUTH_LITERAL_UINT8('+')
#define CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_NEGATIVE\
   CLIAUTH_LITERAL_UINT8('-')
#define CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_PREFIX\
   CLIAUTH_LITERAL_UINT8('0')
#define CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_2\
   CLIAUTH_LITERAL_UINT8('b')
#define CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_8\
   CLIAUTH_LITERAL_UINT8('o')
#define CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_16\
   CLIAUTH_LITERAL_UINT8('x')

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character_prefix_as_magnitude(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   enum CliAuthIoParseStringIntegerDigestStatus status;

   status = cliauth_io_parse_string_integer_digest_character_magnitude(
      context,
      character
   );

   /* this switches from prefix digestion to magnitude digestion for */
   /* subsequent characters if we successfully digested this character */
   if (status == CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS) {
      context->flags = cliauth_math_bitwise_flags_set_uint8(
         context->flags,
         CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_DIGIT
      );
   }

   return status;
}

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character_prefix_sign(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   enum CliAuthIoParseStringIntegerSign sign;

   if (cliauth_math_bitwise_flags_check_one_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_DETECT_SIGN
   ) == CLIAUTH_BOOLEAN_FALSE) {
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_UNEXPECTED_SIGN;
   }
   if (cliauth_math_bitwise_flags_check_one_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_SIGN |
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE_PREFIX
   ) == CLIAUTH_BOOLEAN_TRUE) {
      return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_INVALID_DIGIT;
   }

   switch (character) {
      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_POSITIVE:
         sign = CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_POSITIVE;
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_NEGATIVE:
         sign = CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_NEGATIVE;
         break;

      default:
         CLIAUTH_UNREACHABLE;
   }

   context->value.sign = sign;
   context->flags = cliauth_math_bitwise_flags_set_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_SIGN
   );

   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS;
}

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character_prefix_base_prefix(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   /* if we aren't using automatic sign detection, parse as a digit but also */
   /* note that we passed the base prefix */
   if (cliauth_math_bitwise_flags_check_one_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_DETECT_BASE
   ) == CLIAUTH_BOOLEAN_FALSE) {
      return cliauth_io_parse_string_integer_digest_character_prefix_as_magnitude(
         context,
         character
      );
   }

   context->flags = cliauth_math_bitwise_flags_set_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE_PREFIX |
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE_PREFIX_PREVIOUS
   );

   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS;
}

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character_prefix_base(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   enum CliAuthIoParseStringIntegerBase base;

   /* if we aren't parsing a base, just treat the character as a digit */
   if (cliauth_math_bitwise_flags_check_one_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_DETECT_BASE
   ) == CLIAUTH_BOOLEAN_FALSE) {
      return cliauth_io_parse_string_integer_digest_character_prefix_as_magnitude(
         context,
         character
      );
   }

   switch (character) {
      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_2:
         base = CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_2;
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_8:
         base = CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_8;
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_16:
         base = CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_16;
         break;

      default:
         CLIAUTH_UNREACHABLE;
   }

   context->base = base;
   context->flags = cliauth_math_bitwise_flags_clear_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE_PREFIX_PREVIOUS
   );
   context->flags = cliauth_math_bitwise_flags_set_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_BASE
   );

   return CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS;
}

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character_prefix_default(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   /* ignore parsing the base prefix character as it has no value in any of */
   /* our bases.  simply just switch over to parsing magnitude digits */
   return cliauth_io_parse_string_integer_digest_character_prefix_as_magnitude(
      context,
      character
   );
}

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character_prefix(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   enum CliAuthIoParseStringIntegerDigestStatus status;

   switch (character) {
      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_POSITIVE:
      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_SIGN_NEGATIVE:
         status = cliauth_io_parse_string_integer_digest_character_prefix_sign(
            context,
            character
         );
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_PREFIX:
         status = cliauth_io_parse_string_integer_digest_character_prefix_base_prefix(
            context,
            character
         );
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_2:
      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_8:
      case CLIAUTH_IO_PARSE_STRING_INTEGER_PREFIX_CHARACTER_BASE_16:
         status = cliauth_io_parse_string_integer_digest_character_prefix_base(
            context,
            character
         );
         break;

      default:
         status = cliauth_io_parse_string_integer_digest_character_prefix_default(
            context,
            character
         );
         break;
   }

   return status;
}

static enum CliAuthIoParseStringIntegerDigestStatus
cliauth_io_parse_string_integer_digest_character(
   struct CliAuthIoParseStringIntegerContext * context,
   CliAuthUInt8 character
) {
   enum CliAuthIoParseStringIntegerDigestStatus status;

   /* check whether we've already parsed the prefix or not */
   if (cliauth_math_bitwise_flags_check_one_uint8(
      context->flags,
      CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_ENCOUNTERED_DIGIT
   ) == CLIAUTH_BOOLEAN_TRUE) {
      status = cliauth_io_parse_string_integer_digest_character_magnitude(
         context,
         character
      );
   } else {
      status = cliauth_io_parse_string_integer_digest_character_prefix(
         context,
         character
      );
   }

   return status;
}

void
cliauth_io_parse_string_integer_initialize(
   struct CliAuthIoParseStringIntegerContext * context,
   enum CliAuthIoParseStringIntegerSign sign,
   enum CliAuthIoParseStringIntegerBase base,
   const struct CliAuthIoParseStringIntegerRange * range
) {
   context->value.magnitude = CLIAUTH_LITERAL_UINT64(0u, 0u);
   cliauth_memory_copy(
      &context->range,
      range,
      CLIAUTH_LITERAL_UINT32(sizeof(context->range))
   );
   context->flags = CLIAUTH_LITERAL_UINT8(0x00u);

   if (sign == CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC) {
      context->value.sign = CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_POSITIVE;
      context->flags = cliauth_math_bitwise_flags_set_uint8(
         context->flags,
         CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_DETECT_SIGN
      );
   } else {
      context->value.sign = sign;
   }

   if (base == CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_AUTOMATIC) {
      context->base = CLIAUTH_IO_PARSE_STRING_INTEGER_BASE_10;
      context->flags = cliauth_math_bitwise_flags_set_uint8(
         context->flags,
         CLIAUTH_IO_PARSE_STRING_INTEGER_CONTEXT_FLAG_DETECT_BASE
      );
   } else {
      context->base = base;
   }
   
   return;
}

struct CliAuthIoParseStringIntegerDigestResult
cliauth_io_parse_string_integer_digest(
   struct CliAuthIoParseStringIntegerContext * context,
   const struct CliAuthIoStreamReader * reader,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoParseStringIntegerDigestResult result;
   CliAuthUInt32 bytes_read;
   CliAuthUInt8 character;

   bytes_read = CLIAUTH_LITERAL_UINT32(0u);
   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      /* in the future, we will replace this with more advanced function so */
      /* we can support unicode */
      /* also note that there's no contingency for partial read results.  for */
      /* now this is fine since a character can only be a single byte, however */
      /* in the future we will need a circular read buffer. */
      result.read_result = cliauth_io_stream_reader_read(
         reader,
         &character,
         CLIAUTH_LITERAL_UINT32(sizeof(character))
      );
      bytes_read += result.read_result.bytes;

      if (result.read_result.status != CLIAUTH_IO_STATUS_SUCCESS) {
         result.status = CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_IO_ERROR;
         return result;
      }

      result.status = cliauth_io_parse_string_integer_digest_character(
         context,
         character
      );

      switch (result.status) {
         case CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_SUCCESS:
            break;

         case CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_IO_ERROR:
            goto error_exit;

         case CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_INVALID_DIGIT:
            result.payload.invalid_digit.digit = character;
            goto error_exit;

         case CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_OUT_OF_RANGE:
            goto error_exit;

         case CLIAUTH_IO_PARSE_STRING_INTEGER_DIGEST_STATUS_UNEXPECTED_SIGN:
            result.payload.unexpected_sign.character = character;
            goto error_exit;

         error_exit:
            result.read_result.bytes = bytes_read;
            return result;

         default:
            CLIAUTH_UNREACHABLE;
      }

      bytes -= CLIAUTH_LITERAL_UINT32(sizeof(character));
   }
   
   result.read_result.bytes = bytes_read;
   return result;
}

/* note that for all these finalization functions, we don't perform any */
/* safety checks.  that's because it's documented undefined behavior to allow */
/* a range of values which will result in an invalid cast that leads to */
/* undefined behavior.  thus, we always assume each cast is valid. */

CliAuthUInt8
cliauth_io_parse_string_integer_finalize_uint8(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthUInt8 value;

   value = (CliAuthUInt8)cliauth_io_parse_string_integer_finalize_uint64(
      context
   );

   return value;
}

CliAuthUInt16
cliauth_io_parse_string_integer_finalize_uint16(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthUInt16 value;

   value = (CliAuthUInt16)cliauth_io_parse_string_integer_finalize_uint64(
      context
   );

   return value;
}

CliAuthUInt32
cliauth_io_parse_string_integer_finalize_uint32(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthUInt32 value;

   value = (CliAuthUInt32)cliauth_io_parse_string_integer_finalize_uint64(
      context
   );

   return value;
}

CliAuthUInt64
cliauth_io_parse_string_integer_finalize_uint64(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthUInt64 value;

   value = context->value.magnitude;

   return value;
}

CliAuthSInt8
cliauth_io_parse_string_integer_finalize_sint8(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthSInt8 value;

   value = (CliAuthSInt8)cliauth_io_parse_string_integer_finalize_sint64(
      context
   );

   return value;
}

CliAuthSInt16
cliauth_io_parse_string_integer_finalize_sint16(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthSInt16 value;

   value = (CliAuthSInt16)cliauth_io_parse_string_integer_finalize_sint64(
      context
   );

   return value;
}

CliAuthSInt32
cliauth_io_parse_string_integer_finalize_sint32(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthSInt32 value;

   value = (CliAuthSInt32)cliauth_io_parse_string_integer_finalize_sint64(
      context
   );

   return value;
}

CliAuthSInt64
cliauth_io_parse_string_integer_finalize_sint64(
   struct CliAuthIoParseStringIntegerContext * context
) {
   CliAuthSInt64 value;

   switch (context->value.sign) {
      case CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_POSITIVE:
         value = context->value.magnitude;
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_NEGATIVE:
         value = -context->value.magnitude;
         break;

      case CLIAUTH_IO_PARSE_STRING_INTEGER_SIGN_AUTOMATIC:
         CLIAUTH_UNREACHABLE;

      default:
         CLIAUTH_UNREACHABLE;
   }

   return value;
}

