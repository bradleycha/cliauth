/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/parse.c - Data serializer and deserializer implementations.            */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "parse.h"

#include <string.h>
#include "hash.h"

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

/* identifiers stored with #define to allow use of sizeof() */
#if CLIAUTH_CONFIG_HASH_SHA1
#define CLIAUTH_PARSE_HASH_IDENTIFIER_SHA1 "sha1"
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA224
#define CLIAUTH_PARSE_HASH_IDENTIFIER_SHA224 "sha224"
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */
#if CLIAUTH_CONFIG_HASH_SHA256
#define CLIAUTH_PARSE_HASH_IDENTIFIER_SHA256 "sha256"
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */
#if CLIAUTH_CONFIG_HASH_SHA384
#define CLIAUTH_PARSE_HASH_IDENTIFIER_SHA384 "sha384"
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */
#if CLIAUTH_CONFIG_HASH_SHA512
#define CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512 "sha512"
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */
#if CLIAUTH_CONFIG_HASH_SHA512_224
#define CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512_224 "sha512-224"
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */
#if CLIAUTH_CONFIG_HASH_SHA512_256
#define CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512_256 "sha512-256"
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */

struct CliAuthParseHashIdentifier {
   const char * text;
   CliAuthUInt8 characters;
};

static const struct CliAuthParseHashIdentifier
cliauth_parse_hash_identifier_list [CLIAUTH_HASH_ENABLED_COUNT] = {
#if CLIAUTH_CONFIG_HASH_SHA1
   {
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA1,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA1) / sizeof(char)) - 1
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA224
   {
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA224,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA224) / sizeof(char)) - 1
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */
#if CLIAUTH_CONFIG_HASH_SHA256
   {
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA256,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA256) / sizeof(char)) - 1
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */
#if CLIAUTH_CONFIG_HASH_SHA384
   {
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA384,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA384) / sizeof(char)) - 1
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */
#if CLIAUTH_CONFIG_HASH_SHA512
   {
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512) / sizeof(char)) - 1
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */
#if CLIAUTH_CONFIG_HASH_SHA512_224
   {
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512_224,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512_224) / sizeof(char)) - 1
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */
#if CLIAUTH_CONFIG_HASH_SHA512_256
   {
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512_256,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA512_256) / sizeof(char)) - 1
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */
};

static const struct CliAuthParseHashPayload
cliauth_parse_hash_payload_list [CLIAUTH_HASH_ENABLED_COUNT] = {
#if CLIAUTH_CONFIG_HASH_SHA1
   {
      &cliauth_hash_sha1,
      CLIAUTH_HASH_SHA1_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA1_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA224
   {
      &cliauth_hash_sha224,
      CLIAUTH_HASH_SHA224_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA224_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */
#if CLIAUTH_CONFIG_HASH_SHA256
   {
      &cliauth_hash_sha256,
      CLIAUTH_HASH_SHA256_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA256_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */
#if CLIAUTH_CONFIG_HASH_SHA384
   {
      &cliauth_hash_sha384,
      CLIAUTH_HASH_SHA384_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA384_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */
#if CLIAUTH_CONFIG_HASH_SHA512
   {
      &cliauth_hash_sha512,
      CLIAUTH_HASH_SHA512_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA512_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */
#if CLIAUTH_CONFIG_HASH_SHA512_224
   {
      &cliauth_hash_sha512_224,
      CLIAUTH_HASH_SHA512_224_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA512_224_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */
#if CLIAUTH_CONFIG_HASH_SHA512_256
   {
      &cliauth_hash_sha512_256,
      CLIAUTH_HASH_SHA512_256_INPUT_BLOCK_LENGTH,
      CLIAUTH_HASH_SHA512_256_DIGEST_LENGTH
   },
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */
};

static CliAuthBoolean
cliauth_parse_hash_identifier_compare(
   const struct CliAuthParseHashIdentifier * identifier_compare,
   const char identifier_given [],
   CliAuthUInt32 identifier_given_characters
) {
   if (identifier_compare->characters != identifier_given_characters) {
      return CLIAUTH_BOOLEAN_FALSE;
   }
   if (memcmp(
      identifier_compare->text,
      identifier_given,
      identifier_given_characters * sizeof(char)
   ) != 0) {
      return CLIAUTH_BOOLEAN_FALSE;
   }

   return CLIAUTH_BOOLEAN_TRUE;
}

enum CliAuthParseHashResult
cliauth_parse_hash_identifier(
   const struct CliAuthParseHashPayload * * payload,
   const char identifier [],
   CliAuthUInt32 identifier_characters
) {
   const struct CliAuthParseHashIdentifier * identifier_iter;
   const struct CliAuthParseHashPayload * payload_iter;
   CliAuthUInt8 i;

   identifier_iter = cliauth_parse_hash_identifier_list;
   payload_iter = cliauth_parse_hash_payload_list;
   i = CLIAUTH_HASH_ENABLED_COUNT;

   while (i != 0) {
      if (cliauth_parse_hash_identifier_compare(
         identifier_iter,
         identifier,
         identifier_characters
      ) == CLIAUTH_BOOLEAN_TRUE) {
         *payload = payload_iter;
         return CLIAUTH_PARSE_HASH_RESULT_SUCCESS;
      }

      identifier_iter++;
      payload_iter++;
      i--;
   }
   
   return CLIAUTH_PARSE_HASH_RESULT_UNKNOWN_IDENTIFIER;
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

struct CliAuthParseKeyUriState {
   struct CliAuthParseKeyUriPayload * payload;
   const char * uri_iter;
   CliAuthUInt32 uri_iter_characters;
   CliAuthBoolean required_present_secrets;
   CliAuthBoolean required_present_hash;
   CliAuthBoolean required_present_hotp_counter;
};

static void
cliauth_parse_key_uri_state_initialize(
   struct CliAuthParseKeyUriState * state,
   struct CliAuthParseKeyUriPayload * payload,
   const char uri [],
   CliAuthUInt32 uri_characters
) {
   /* initialize non algorithm specific payload defaults */
   payload->issuer_characters = CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_ISSUER_CHARACTERS;
   payload->account_name_characters = CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_ACCOUNT_NAME_CHARACTERS;
   payload->digits = CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_DIGITS;
   
   /* initialize state machine */
   state->payload = payload;
   state->uri_iter = uri;
   state->uri_iter_characters = uri_characters;
   state->required_present_secrets = CLIAUTH_BOOLEAN_FALSE;
   state->required_present_hotp_counter = CLIAUTH_BOOLEAN_FALSE;

   /* if SHA1 hash is enabled, set it by default, otherwise the algorithm */
   /* will be a required parameter */
#if CLIAUTH_CONFIG_HASH_SHA1
   (void)cliauth_parse_hash_identifier(
      &payload->hash,
      CLIAUTH_PARSE_HASH_IDENTIFIER_SHA1,
      (sizeof(CLIAUTH_PARSE_HASH_IDENTIFIER_SHA1) / sizeof(char)) - 1
   );
   state->required_present_hash = CLIAUTH_BOOLEAN_TRUE;
#else /* CLIAUTH_CONFIG_HASH_SHA1 */
   state->required_present_hash = CLIAUTH_BOOLEAN_FALSE;
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */

   return;
}

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_state_finalize(struct CliAuthParseKeyUriState * state) {
   /* check all required values are present */
   if (state->required_present_secrets == CLIAUTH_BOOLEAN_FALSE) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_SECRETS;
   }
   if (state->required_present_hash == CLIAUTH_BOOLEAN_FALSE) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HASH;
   }
   if (state->payload->algorithm == CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP && state->required_present_hotp_counter) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HOTP_COUNTER;
   }

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

#define CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL\
   CLIAUTH_UINT32_MAX

/* finds the index of the first character in a string, or */
/* CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL if not found.*/
static CliAuthUInt32
cliauth_parse_key_uri_find_character_position(
   const char text [],
   CliAuthUInt32 text_characters,
   char character
) {
   const char * text_iter;

   text_iter = text;
   while (text_characters != 0) {
      if (text_iter[0] == character) {
         return text_iter - text;
      }

      text_iter++;
      text_characters--;
   }

   return CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL;
}

enum CliAuthParseKeyUriDecodeTextEscapeResult {
   CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS,
   CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_INVALID_ENCODING
};

static enum CliAuthParseKeyUriDecodeTextEscapeResult
cliauth_parse_key_uri_decode_text_escape_nibble(
   CliAuthUInt8 * output,
   char character
) {
   /* convert from uppercase to lowercase */
   if (character >= 'A' && character <= 'Z') {
      character += 'a' - 'A';
   }

   /* check for digit 0-9 */
   if (character >= '0' && character <= '9') {
      *output = character - '0';
      return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS;
   }

   /* check for digit a-f */
   if (character >= 'a' && character <= 'f') {
      *output = character - 'a' + 0xa;
      return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS;
   }

   /* uh-oh! invalid encoding! */
   return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_INVALID_ENCODING;
}

static enum CliAuthParseKeyUriDecodeTextEscapeResult
cliauth_parse_key_uri_decode_text_escape_hex(
   CliAuthUInt8 * output,
   const char text []
) {
   enum CliAuthParseKeyUriDecodeTextEscapeResult result;
   CliAuthUInt8 nibble;
   CliAuthUInt8 i;

   i = 2;
   *output = 0x00;
   while (i != 0) {
      /* parse the current character as a nibble */
      result = cliauth_parse_key_uri_decode_text_escape_nibble(
         &nibble,
         *text
      );
      if (result != CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS) {
         return result;
      }

      /* slot the bits into the output byte */
      *output |= (nibble << ((i - 1) * 4));

      text++;
      i--;
   }

   return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS;
}

static enum CliAuthParseKeyUriDecodeTextEscapeResult
cliauth_parse_key_uri_decode_text_escape(
   char * output,
   const char text []
) {
   enum CliAuthParseKeyUriDecodeTextEscapeResult result;
   CliAuthUInt8 digit;

   /* convert from a a hex string to a byte */
   result = cliauth_parse_key_uri_decode_text_escape_hex(
      &digit,
      text
   );
   if (result != CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS) {
      return result;
   }

   /* make sure the escaped character is printable */
   if (digit < 0x20 || digit > 0x7e) {
      return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_INVALID_ENCODING;
   }

   /* write the parsed character */
   *output = (char)digit;

   return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS;
}

enum CliAuthParseKeyUriDecodeTextResult {
   CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_SUCCESS,
   CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_BUFFER_TOO_SHORT,
   CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_INVALID_ESCAPE
};

#define CLIAUTH_PARSE_KEY_RUI_DECODE_TEXT_SENTINEL_ESCAPE '%'

static enum CliAuthParseKeyUriDecodeTextResult
cliauth_parse_key_uri_decode_text(
   char output [],
   const char text [],
   CliAuthUInt32 * output_characters,
   CliAuthUInt32 output_characters_max,
   CliAuthUInt32 text_characters
) {
   enum CliAuthParseKeyUriDecodeTextEscapeResult decode_result;
   char decoded_escape;

   *output_characters = 0;

   while (text_characters != 0) {
      /* error out if we run out of buffer space */
      if (output_characters_max == 0) {
         return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_BUFFER_TOO_SHORT;
      }

      /* increment the number of characters we've parsed */
      *output_characters += 1;

      /* if this isn't an escaped sequence, simply copy the character */
      if (*text != CLIAUTH_PARSE_KEY_RUI_DECODE_TEXT_SENTINEL_ESCAPE) {
         *output = *text;

         output++;
         text++;
         output_characters_max--;
         text_characters--;
         continue;
      }

      /* make sure we have enough characters in the escape sequence */
      if (text_characters < 3) {
         return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_INVALID_ESCAPE;
      }

      /* decode the escape sequence */
      decode_result = cliauth_parse_key_uri_decode_text_escape(
         &decoded_escape,
         text + 1
      );
      switch (decode_result) {
         case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_SUCCESS:
            break;

         case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_ESCAPE_RESULT_INVALID_ENCODING:
            return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_INVALID_ESCAPE;
      }

      /* write the decoded escape sequence */
      *output = decoded_escape;

      /* advance past the escape sequence */
      output += 1;
      text += 3;
      output_characters_max -= 1;
      text_characters -= 3;
   }

   return CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_SUCCESS;
}

#define CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH "otpauth://"
#define CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH_LENGTH\
   (sizeof(CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH) - 1)

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_protocol(struct CliAuthParseKeyUriState * state) {
   /* verify the protocol is correct */
   if (state->uri_iter_characters < CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH_LENGTH) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MALFORMED_URI;
   }
   if (memcmp(
      state->uri_iter,
      CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH,
      CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH_LENGTH * sizeof(char)
   ) != 0) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MALFORMED_URI;
   }

   /* advance past the protocol */
   state->uri_iter += CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH_LENGTH;
   state->uri_iter_characters -= CLIAUTH_PARSE_KEY_URI_PROTOCOL_OTPAUTH_LENGTH;

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

#define CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_SUFFIX "otp"
#define CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_SUFFIX_LENGTH\
   (sizeof(CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_SUFFIX) - 1)

#define CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_LENGTH\
   (CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_SUFFIX_LENGTH + 1)

#define CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_PREFIX_HOTP 'h'
#define CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_PREFIX_TOTP 't'

static void
cliauth_parse_key_uri_algorithm_type_hotp(struct CliAuthParseKeyUriState * state) {
   /* set algorithm type to hotp */
   state->payload->algorithm = CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP;

   return;
}

static void
cliauth_parse_key_uri_algorithm_type_totp(struct CliAuthParseKeyUriState * state) {
   /* set algorithm type to totp */
   state->payload->algorithm = CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_TOTP;

   /* set totp-specific payload defaults */
   state->payload->algorithm_parameters.totp.period = CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_TOTP_PERIOD;

   return;
}

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_algorithm_type(struct CliAuthParseKeyUriState * state) {
   CliAuthUInt32 slash_position;

   /* verify the string is not empty */
   if (state->uri_iter_characters == 0) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_TYPE;
   }

   /* find the index of the first forward slash */
   slash_position = cliauth_parse_key_uri_find_character_position(
      state->uri_iter,
      state->uri_iter_characters,
      '/'
   );

   /* verify a forward slash is present */
   if (slash_position == CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MALFORMED_URI;
   }

   /* verify the algorithm type is of form "*otp" */
   if (slash_position != CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_LENGTH) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TYPE;
   }
   if (memcmp(
      state->uri_iter + 1,
      CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_SUFFIX,
      CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_SUFFIX_LENGTH * sizeof(char)
   ) != 0) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TYPE;
   }

   /* decide which algorithm type to set */
   switch (state->uri_iter[0]) {
      case CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_PREFIX_HOTP:
         cliauth_parse_key_uri_algorithm_type_hotp(state);
         break;

      case CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_PREFIX_TOTP:
         cliauth_parse_key_uri_algorithm_type_totp(state);
         break;

      default:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TYPE;
   }

   /* advance past the algorithm type */
   state->uri_iter += CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_LENGTH + 1;
   state->uri_iter_characters -= CLIAUTH_PARSE_KEY_URI_ALGORITHM_TYPE_LENGTH + 1;

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

#define CLIAUTH_PARSE_KEY_URI_LABEL_SENTINEL_QUERY    '?'
#define CLIAUTH_PARSE_KEY_URI_LABEL_SENTINEL_SEPERATE ':'
#define CLIAUTH_PARSE_KEY_URI_LABEL_DECODE_BUFFER_LENGTH\
   (\
      CLIAUTH_PARSE_KEY_URI_PAYLOAD_ISSUER_MAX_LENGTH +\
      CLIAUTH_PARSE_KEY_URI_PAYLOAD_ACCOUNT_NAME_MAX_LENGTH +\
      1\
   )

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_label(struct CliAuthParseKeyUriState * state) {
   char label_parsed[CLIAUTH_PARSE_KEY_URI_LABEL_DECODE_BUFFER_LENGTH];
   enum CliAuthParseKeyUriDecodeTextResult decode_result;
   const char * label;
   const char * issuer;
   const char * account_name;
   CliAuthUInt32 label_characters;
   CliAuthUInt32 issuer_characters;
   CliAuthUInt32 account_name_characters;
   CliAuthUInt32 label_parsed_characters;
   CliAuthUInt32 query_position;
   CliAuthUInt32 seperate_position;

   /* find the position of the query character */
   query_position = cliauth_parse_key_uri_find_character_position(
      state->uri_iter,
      state->uri_iter_characters,
      CLIAUTH_PARSE_KEY_URI_LABEL_SENTINEL_QUERY
   );

   /* determine the length of the label string based on the location of the */
   /* query character and advance the iterator */
   label = state->uri_iter;
   switch (query_position) {
      case CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL:
         label_characters = state->uri_iter_characters;
         state->uri_iter += state->uri_iter_characters;
         state->uri_iter_characters = 0;
         break;

      default:
         label_characters = query_position;
         state->uri_iter += label_characters + 1;
         state->uri_iter_characters -= label_characters + 1;
         break;
   }

   /* decode the escaped text into plaintext, storing the new character count */
   /* in label_parsed_characters */
   decode_result = cliauth_parse_key_uri_decode_text(
      label_parsed,
      label,
      &label_parsed_characters,
      CLIAUTH_PARSE_KEY_URI_LABEL_DECODE_BUFFER_LENGTH,
      label_characters
   );
   switch (decode_result) {
      case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_SUCCESS:
         break;

      case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_BUFFER_TOO_SHORT:
         return CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_LABEL;

      case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_INVALID_ESCAPE:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TEXT_ESCAPE;
   }

   /* find the position of the seperate character, if present */
   seperate_position = cliauth_parse_key_uri_find_character_position(
      label_parsed,
      label_parsed_characters,
      CLIAUTH_PARSE_KEY_URI_LABEL_SENTINEL_SEPERATE
   );

   /* split the label into issuer and account name based on the seperator */
   switch (seperate_position) {
      case CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL:
         issuer = label_parsed;
         issuer_characters = 0;
         account_name = label_parsed;
         account_name_characters = label_parsed_characters;
         break;

      default:
         issuer = label_parsed;
         issuer_characters = seperate_position;
         account_name = label_parsed + issuer_characters + 1;
         account_name_characters = label_parsed_characters - issuer_characters - 1;
         break;
   }

   /* verify the lengths are within bounds, this has to be done again because */
   /* the previous check from decoding only applies to the entire string, not */
   /* the individual issuer or account name strings */
   if (issuer_characters > CLIAUTH_PARSE_KEY_URI_PAYLOAD_ISSUER_MAX_LENGTH) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ISSUER;
   }
   if (account_name_characters > CLIAUTH_PARSE_KEY_URI_PAYLOAD_ACCOUNT_NAME_MAX_LENGTH) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ACCOUNT_NAME;
   }

   /* write the issuer and account name strings */
   (void)memcpy(
      &state->payload->issuer,
      issuer,
      issuer_characters * sizeof(char)
   );
   (void)memcpy(
      &state->payload->account_name,
      account_name,
      account_name_characters * sizeof(char)
   );
   state->payload->issuer_characters = (CliAuthUInt8)issuer_characters;
   state->payload->account_name_characters = (CliAuthUInt8)account_name_characters;

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

struct CliAuthParseKeyUriQueryKey {
   const char * text;
   CliAuthUInt8 characters;
};

typedef enum CliAuthParseKeyUriResult(*CliAuthParseKeyUriQueryParser)(
   struct CliAuthParseKeyUriState * state,
   const char value [],
   CliAuthUInt32 value_characters
);

#define CLIAUTH_PARSE_KEY_URI_QUERY_KEYS 6

#define CLIAUTH_PARSE_KEY_URI_QUERY_KEY_SECRET     "secret"
#define CLIAUTH_PARSE_KEY_URI_QUERY_KEY_ISSUER     "issuer"
#define CLIAUTH_PARSE_KEY_URI_QUERY_KEY_ALGORITHM  "algorithm"
#define CLIAUTH_PARSE_KEY_URI_QUERY_KEY_DIGITS     "digits"
#define CLIAUTH_PARSE_KEY_URI_QUERY_KEY_COUNTER    "counter"
#define CLIAUTH_PARSE_KEY_URI_QUERY_KEY_PERIOD     "period"

#define CLIAUTH_PARSE_KEY_URI_QUERY_SECRET_MAX_LENGTH\
   (((CLIAUTH_PARSE_KEY_URI_PAYLOAD_SECRETS_MAX_LENGTH * 8) + 5) / 5)

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query_secret(
   struct CliAuthParseKeyUriState * state,
   const char value [],
   CliAuthUInt32 value_characters
) {
   enum CliAuthParseBase32DecodeResult decode_result;
   CliAuthUInt32 secrets_bytes;

   if (value_characters > CLIAUTH_PARSE_KEY_URI_QUERY_SECRET_MAX_LENGTH) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_SECRETS;
   }

   decode_result = cliauth_parse_base32_decode(
      &state->payload->secrets,
      &secrets_bytes,
      value,
      value_characters
   );
   switch (decode_result) {
      case CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS:
         break;

      case CLIAUTH_PARSE_BASE32_DECODE_RESULT_INVALID_ENCODING:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_SECRETS;
   }

   /* this will always be valid due to the previous check */
   state->payload->secrets_bytes = (CliAuthUInt8)secrets_bytes;

   state->required_present_secrets = CLIAUTH_BOOLEAN_TRUE;

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query_issuer(
   struct CliAuthParseKeyUriState * state,
   const char value [],
   CliAuthUInt32 value_characters
) {
   enum CliAuthParseKeyUriDecodeTextResult decode_result;
   CliAuthUInt32 decoded_characters;

   decode_result = cliauth_parse_key_uri_decode_text(
      state->payload->issuer,
      value,
      &decoded_characters,
      CLIAUTH_PARSE_KEY_URI_PAYLOAD_ISSUER_MAX_LENGTH,
      value_characters
   );
   switch (decode_result) {
      case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_SUCCESS:
         break;

      case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_BUFFER_TOO_SHORT:
         return CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ISSUER;

      case CLIAUTH_PARSE_KEY_URI_DECODE_TEXT_RESULT_INVALID_ESCAPE:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TEXT_ESCAPE;
   }

   /* always valid because this is checked above */
   state->payload->issuer_characters = (CliAuthUInt8)decoded_characters;
   
   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query_algorithm(
   struct CliAuthParseKeyUriState * state,
   const char value [],
   CliAuthUInt32 value_characters
) {
   enum CliAuthParseHashResult parse_result;

   parse_result = cliauth_parse_hash_identifier(
      &state->payload->hash,
      value,
      value_characters
   );
   switch (parse_result) {
      case CLIAUTH_PARSE_HASH_RESULT_SUCCESS:
         break;

      case CLIAUTH_PARSE_HASH_RESULT_UNKNOWN_IDENTIFIER:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HASH;
   }

   state->required_present_hash = CLIAUTH_BOOLEAN_TRUE;
   
   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query_digits(
   struct CliAuthParseKeyUriState * state,
   const char value [],
   CliAuthUInt32 value_characters
) {
   enum CliAuthParseIntegerResult parse_result;
   CliAuthUInt64 parsed;

   parse_result = cliauth_parse_integer_uint64(
      &parsed,
      value,
      value_characters
   );
   switch (parse_result) {
      case CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS:
         break;

      case CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_DIGITS;

      case CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_DIGITS;
   }

   if (parsed < 1 || parsed > 9) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_DIGITS;
   }

   state->payload->digits = (CliAuthUInt64)parsed;

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query_counter(
   struct CliAuthParseKeyUriState * state,
   const char value [],
   CliAuthUInt32 value_characters
) {
   enum CliAuthParseIntegerResult parse_result;
   CliAuthUInt64 parsed;

   parse_result = cliauth_parse_integer_uint64(
      &parsed,
      value,
      value_characters
   );
   switch (parse_result) {
      case CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS:
         break;

      case CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HOTP_COUNTER;

      case CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HOTP_COUNTER;
   }

   switch (state->payload->algorithm) {
      case CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP:
         state->payload->algorithm_parameters.hotp.counter = parsed;
         break;

      case CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_TOTP:
         /* ignore for totp, still validated using parser */
         break;
   }

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query_period(
   struct CliAuthParseKeyUriState * state,
   const char value [],
   CliAuthUInt32 value_characters
) {
   enum CliAuthParseIntegerResult parse_result;
   CliAuthUInt64 parsed;

   parse_result = cliauth_parse_integer_uint64(
      &parsed,
      value,
      value_characters
   );
   switch (parse_result) {
      case CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS:
         break;

      case CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TOTP_PERIOD;

      case CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE:
         return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TOTP_PERIOD;
   }

   if (parsed < 1) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TOTP_PERIOD;
   }

   switch (state->payload->algorithm) {
      case CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP:
         /* ignore for hotp, still validated using parser */
         break;

      case CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_TOTP:
         state->payload->algorithm_parameters.totp.period = parsed;
         break;
   }

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

static const struct CliAuthParseKeyUriQueryKey
cliauth_parse_key_uri_query_key_identifiers [CLIAUTH_PARSE_KEY_URI_QUERY_KEYS] = {
   {
      CLIAUTH_PARSE_KEY_URI_QUERY_KEY_SECRET,
      (sizeof(CLIAUTH_PARSE_KEY_URI_QUERY_KEY_SECRET) / sizeof(char)) - 1
   },
   {
      CLIAUTH_PARSE_KEY_URI_QUERY_KEY_ISSUER,
      (sizeof(CLIAUTH_PARSE_KEY_URI_QUERY_KEY_ISSUER) / sizeof(char)) - 1
   },
   {
      CLIAUTH_PARSE_KEY_URI_QUERY_KEY_ALGORITHM,
      (sizeof(CLIAUTH_PARSE_KEY_URI_QUERY_KEY_ALGORITHM) / sizeof(char)) - 1
   },
   {
      CLIAUTH_PARSE_KEY_URI_QUERY_KEY_DIGITS,
      (sizeof(CLIAUTH_PARSE_KEY_URI_QUERY_KEY_DIGITS) / sizeof(char)) - 1
   },
   {
      CLIAUTH_PARSE_KEY_URI_QUERY_KEY_COUNTER,
      (sizeof(CLIAUTH_PARSE_KEY_URI_QUERY_KEY_COUNTER) / sizeof(char)) - 1
   },
   {
      CLIAUTH_PARSE_KEY_URI_QUERY_KEY_PERIOD,
      (sizeof(CLIAUTH_PARSE_KEY_URI_QUERY_KEY_PERIOD) / sizeof(char)) - 1
   },
};

static const CliAuthParseKeyUriQueryParser
cliauth_parse_key_uri_query_key_parsers [CLIAUTH_PARSE_KEY_URI_QUERY_KEYS] = {
   cliauth_parse_key_uri_query_secret,
   cliauth_parse_key_uri_query_issuer,
   cliauth_parse_key_uri_query_algorithm,
   cliauth_parse_key_uri_query_digits,
   cliauth_parse_key_uri_query_counter,
   cliauth_parse_key_uri_query_period,
};

static CliAuthBoolean
cliauth_parse_key_uri_query_key_parsers_identifier_compare(
   const struct CliAuthParseKeyUriQueryKey * identifier_compare,
   const char identifier_given [],
   CliAuthUInt32 identifier_given_characters
) {
   if (identifier_compare->characters != identifier_given_characters) {
      return CLIAUTH_BOOLEAN_FALSE;
   }
   if (memcmp(
      identifier_compare->text,
      identifier_given,
      identifier_given_characters * sizeof(char)
   ) != 0) {
      return CLIAUTH_BOOLEAN_FALSE;
   }

   return CLIAUTH_BOOLEAN_TRUE;
}

static CliAuthParseKeyUriQueryParser
cliauth_parse_key_uri_query_match_key(
   const char key [],
   CliAuthUInt32 key_characters
) {
   const struct CliAuthParseKeyUriQueryKey * key_iter;
   const CliAuthParseKeyUriQueryParser * parser_iter;
   CliAuthUInt8 i;

   key_iter = cliauth_parse_key_uri_query_key_identifiers;
   parser_iter = cliauth_parse_key_uri_query_key_parsers;
   i = CLIAUTH_PARSE_KEY_URI_QUERY_KEYS;

   while (i != 0) {
      if (cliauth_parse_key_uri_query_key_parsers_identifier_compare(
         key_iter,
         key,
         key_characters
      ) == CLIAUTH_BOOLEAN_TRUE) {
         return *parser_iter;
      }

      key_iter++;
      parser_iter++;
      i--;
   }

   return NULL;
}

#define CLIAUTH_PARSE_KEY_URI_QUERY_SENTINEL_SEPERATE '='

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query(
   struct CliAuthParseKeyUriState * state,
   const char query [],
   CliAuthUInt32 query_characters
) {
   enum CliAuthParseKeyUriResult result;
   CliAuthParseKeyUriQueryParser parser;
   const char * key;
   const char * value;
   CliAuthUInt32 key_seperator_position;
   CliAuthUInt32 key_characters;
   CliAuthUInt32 value_characters;

   /* find the position the the key/value seperator */
   key_seperator_position = cliauth_parse_key_uri_find_character_position(
      query,
      query_characters,
      CLIAUTH_PARSE_KEY_URI_QUERY_SENTINEL_SEPERATE
   );

   /* make sure the seperator sentinel is present */
   if (key_seperator_position == CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_MALFORMED_URI;
   }

   /* split the query into its key and value */
   key = query;
   key_characters = key_seperator_position;
   value = query + key_characters + 1;
   value_characters = query_characters - key_characters - 1;

   /* match the key to its relevant parser */
   parser = cliauth_parse_key_uri_query_match_key(key, key_characters);

   /* ignore queries which don't have a parser */
   if (parser == NULL) {
      return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
   }

   /* run the parser on the value */
   result = parser(state, value, value_characters);
   if (result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
      return result;
   }

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

#define CLIAUTH_PARSE_KEY_URI_QUERY_CHAIN_SENTINEL_SEPERATE '&'

static enum CliAuthParseKeyUriResult
cliauth_parse_key_uri_query_chain(struct CliAuthParseKeyUriState * state) {
   enum CliAuthParseKeyUriResult result;
   const char * query;
   CliAuthUInt32 query_seperator_position;
   CliAuthUInt32 query_characters;

   /* parse individual queries until we iterate over the rest of the string */
   while (state->uri_iter_characters != 0) {
      /* find the position of the query seperator */
      query_seperator_position = cliauth_parse_key_uri_find_character_position(
         state->uri_iter,
         state->uri_iter_characters,
         CLIAUTH_PARSE_KEY_URI_QUERY_CHAIN_SENTINEL_SEPERATE
      );

      /* create the string slice and advance the iterator */
      query = state->uri_iter;
      switch (query_seperator_position) {
         case CLIAUTH_PARSE_KEY_URI_FIND_CHARACTER_POSITION_NULL:
            query_characters = state->uri_iter_characters;
            state->uri_iter += state->uri_iter_characters;
            state->uri_iter_characters = 0;
            break;

         default:
            /* makes sure to account for the seperator token */
            query_characters = query_seperator_position;
            state->uri_iter += query_characters + 1;
            state->uri_iter_characters -= query_characters + 1;
            break;
      }

      /* parse the query */
      result = cliauth_parse_key_uri_query(state, query, query_characters);
      if (result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
         return result;
      }
   }

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

enum CliAuthParseKeyUriResult
cliauth_parse_key_uri(
   struct CliAuthParseKeyUriPayload * payload,
   const char uri [],
   CliAuthUInt32 uri_characters
) {
   struct CliAuthParseKeyUriState state;
   enum CliAuthParseKeyUriResult result;

   /* initialize parser state machine */
   cliauth_parse_key_uri_state_initialize(
      &state,
      payload,
      uri,
      uri_characters
   );

   /* check for the key URI protocol text */
   result = cliauth_parse_key_uri_protocol(&state);
   if (result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
      return result;
   }

   /* parse the algorithm type */
   result = cliauth_parse_key_uri_algorithm_type(&state);
   if (result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
      return result;
   }

   /* parse the label (issuer + account name) */
   result = cliauth_parse_key_uri_label(&state);
   if (result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
      return result;
   }

   /* parse all the query data */
   result = cliauth_parse_key_uri_query_chain(&state);
   if (result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
      return result;
   }

   /* finalize and verify all required data is present */
   result = cliauth_parse_key_uri_state_finalize(&state);
   if (result != CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS) {
      return result;
   }

   return CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS;
}

