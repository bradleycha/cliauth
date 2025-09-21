/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/io/parse/string_block_data.c - String block data parser        */
/*    implementations.                                                        */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/io/parse/string_block_data.h"

#include "cliauth/io/io.h"
#include "cliauth/io/parse/i_digit_to_integer.h"

/* initializes the base-specific context member */
typedef void (*CliAuthIoParseStringBlockDataFunctionInitialize)(
   struct CliAuthIoParseStringBlockDataContext * context
);

/* flushes the shift buffer, returning the write result */
typedef struct CliAuthIoResult (*CliAuthIoParseStringBlockDataFunctionFlush)(
   struct CliAuthIoParseStringBlockDataContext * context,
   const struct CliAuthIoStreamWriter * writer
);

/* attempts to digest a single digit character */
typedef enum CliAuthIoParseStringBlockDataDigestStatus (*CliAuthIoParseStringBlockDataFunctionDigestDigit)(
   struct CliAuthIoParseStringBlockDataContext * context,
   CliAuthUInt8 digit
);

/* stores all the relevant functions for a given base */
struct CliAuthIoParseStringBlockDataFunctions {
   CliAuthIoParseStringBlockDataFunctionInitialize initialize;
   CliAuthIoParseStringBlockDataFunctionFlush flush;
   CliAuthIoParseStringBlockDataFunctionDigestDigit digest_digit;
};

static void
cliauth_io_parse_string_block_data_base_16_initialize(
   struct CliAuthIoParseStringBlockDataContext * context
) {
   struct _CliAuthIoParseStringBlockDataContextBase16 * context_base16;

   context_base16 = &context->context_base.base16;

   context_base16->shift_buffer = CLIAUTH_LITERAL_UINT8(0u);
   context_base16->hexits_count = CLIAUTH_LITERAL_UINT8(0u);

   return;
}

static struct CliAuthIoResult
cliauth_io_parse_string_block_data_base_16_flush(
   struct CliAuthIoParseStringBlockDataContext * context,
   const struct CliAuthIoStreamWriter * writer
) {
   struct CliAuthIoResult result;
   struct _CliAuthIoParseStringBlockDataContextBase16 * context_base16;

   context_base16 = &context->context_base.base16;

   /* we only want to flush when the shift buffer is full */
   if (context_base16->hexits_count != CLIAUTH_LITERAL_UINT8(2u)) {
      result.status = CLIAUTH_IO_STATUS_SUCCESS;
      result.bytes = CLIAUTH_LITERAL_UINT32(0u);
      return result;
   }

   /* don't worry about partial writes or endianess, we are only writing a */
   /* single byte */
   result = cliauth_io_stream_writer_write(
      writer,
      &context_base16->shift_buffer,
      sizeof(CliAuthUInt8)
   );
   if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
      return result;
   }

   /* clear the shift buffer since it should now be completely drained */
   context_base16->shift_buffer = CLIAUTH_LITERAL_UINT8(0u);
   context_base16->hexits_count = CLIAUTH_LITERAL_UINT8(0u);

   return result;
}

static enum CliAuthIoParseStringBlockDataDigestStatus
cliauth_io_parse_string_block_data_base_16_digest_digit(
   struct CliAuthIoParseStringBlockDataContext * context,
   CliAuthUInt8 digit
) {
   struct _CliAuthIoParseStringBlockDataContextBase16 * context_base16;
   enum CliAuthIoParseIDigitToIntegerStatus parse_digit_status;
   CliAuthUInt8 value;

   context_base16 = &context->context_base.base16;

   parse_digit_status = cliauth_io_parse_i_digit_to_integer_base_16(
      &value,
      digit
   );
   switch (parse_digit_status) {
      case CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS:
         break;

      case CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT:
         return CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_INVALID_DIGIT;

      default:
         CLIAUTH_UNREACHABLE;
   }

   /* this will never overflow since we flush the shift buffer before */
   /* digesting the character */
   context_base16->shift_buffer <<= CLIAUTH_LITERAL_UINT8(4u);
   context_base16->shift_buffer |= value;
   context_base16->hexits_count += CLIAUTH_LITERAL_UINT8(1u);

   return CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_SUCCESS;
}

static void
cliauth_io_parse_string_block_data_base_32_initialize(
   struct CliAuthIoParseStringBlockDataContext * context
) {
   struct _CliAuthIoParseStringBlockDataContextBase32 * context_base32;

   context_base32 = &context->context_base.base32;

   context_base32->shift_buffer_and_bits_count = CLIAUTH_LITERAL_UINT16(0u);

   return;
}

/* the base-32 context's 16-bit word represented in a sane way. */
struct CliAuthIoParseStringBlockDataBase32ContextWord {
   CliAuthUInt16 shift_buffer;
   CliAuthUInt8 bits_count;
};

static struct CliAuthIoParseStringBlockDataBase32ContextWord
cliauth_io_parse_string_block_data_base_32_context_word_unpack(
   CliAuthUInt16 context_word
) {
   struct CliAuthIoParseStringBlockDataBase32ContextWord retn;

   retn.shift_buffer = ((context_word & CLIAUTH_LITERAL_UINT16(0x0fffu)) << CLIAUTH_LITERAL_UINT8(4u));
   retn.bits_count = ((CliAuthUInt8)(context_word >> CLIAUTH_LITERAL_UINT8(12u)));

   return retn;
}

static CliAuthUInt16
cliauth_io_parse_string_block_data_base_32_context_word_repack(
   const struct CliAuthIoParseStringBlockDataBase32ContextWord * context_word
) {
   CliAuthUInt16 retn;

   retn = (context_word->shift_buffer >> CLIAUTH_LITERAL_UINT8(4u));
   retn |= (((CliAuthUInt16)(context_word->bits_count)) << CLIAUTH_LITERAL_UINT8(12u));

   return retn;
}

static struct CliAuthIoResult
cliauth_io_parse_string_block_data_base_32_flush(
   struct CliAuthIoParseStringBlockDataContext * context,
   const struct CliAuthIoStreamWriter * writer
) {
   struct CliAuthIoResult result;
   struct _CliAuthIoParseStringBlockDataContextBase32 * context_base32;
   struct CliAuthIoParseStringBlockDataBase32ContextWord context_base32_word;
   CliAuthUInt8 byte;

   context_base32 = &context->context_base.base32;

   context_base32_word = cliauth_io_parse_string_block_data_base_32_context_word_unpack(
      context_base32->shift_buffer_and_bits_count
   );

   if (context_base32_word.bits_count < CLIAUTH_LITERAL_UINT8(8u)) {
      result.status = CLIAUTH_IO_STATUS_SUCCESS;
      result.bytes = CLIAUTH_LITERAL_UINT32(0u);
      return result;
   }

   /* take most-significant 8 bits, since we're buffering starting from the */
   /* left */
   byte = (context_base32_word.shift_buffer >> CLIAUTH_LITERAL_UINT8(8u));

   /* only writing a single byte, no need to worry about endianess or partial */
   /* writes */
   result = cliauth_io_stream_writer_write(
      writer,
      &byte,
      CLIAUTH_LITERAL_UINT32(sizeof(CliAuthUInt8))
   );
   if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
      return result;
   }

   /* discard the upper 8 bits of the shift buffer that we just wrote */
   context_base32_word.shift_buffer <<= CLIAUTH_LITERAL_UINT8(8u);
   context_base32_word.bits_count -= CLIAUTH_LITERAL_UINT8(8u);

   context_base32->shift_buffer_and_bits_count = cliauth_io_parse_string_block_data_base_32_context_word_repack(
      &context_base32_word
   );

   return result;
}

static enum CliAuthIoParseStringBlockDataDigestStatus
cliauth_io_parse_string_block_data_base_32_digest_digit(
   struct CliAuthIoParseStringBlockDataContext * context,
   CliAuthUInt8 digit
) {
   struct _CliAuthIoParseStringBlockDataContextBase32 * context_base32;
   struct CliAuthIoParseStringBlockDataBase32ContextWord context_base32_word;
   enum CliAuthIoParseIDigitToIntegerStatus parse_digit_status;
   CliAuthUInt8 value;
   CliAuthUInt8 shift_amount;

   context_base32 = &context->context_base.base32;

   context_base32_word = cliauth_io_parse_string_block_data_base_32_context_word_unpack(
      context_base32->shift_buffer_and_bits_count
   );

   /* ignore the pad character...why is this even a thing? */
   if (digit == CLIAUTH_LITERAL_UINT8('=')) {
      return CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_SUCCESS;
   }

   parse_digit_status = cliauth_io_parse_i_digit_to_integer_base_32(
      &value,
      digit
   );
   switch (parse_digit_status) {
      case CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_SUCCESS:
         break;

      case CLIAUTH_IO_PARSE_I_DIGIT_TO_INTEGER_STATUS_INVALID_DIGIT:
         return CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_INVALID_DIGIT;

      default:
         CLIAUTH_UNREACHABLE;
   }

   /* calculate the number of bits to shift the value by to append to the */
   /* shift buffer */
   shift_amount = CLIAUTH_LITERAL_UINT8(16u - 5u) - context_base32_word.bits_count;

   /* append to the shift buffer.  this will never overflow since we flush */
   /* just before this function */
   context_base32_word.shift_buffer |= (((CliAuthUInt16)(value)) << shift_amount);
   context_base32_word.bits_count += CLIAUTH_LITERAL_UINT8(5u);

   context_base32->shift_buffer_and_bits_count = cliauth_io_parse_string_block_data_base_32_context_word_repack(
      &context_base32_word
   );

   return CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_SUCCESS;
}

const struct CliAuthIoParseStringBlockDataFunctions
cliauth_io_parse_string_block_data_functions [CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_FIELD_COUNT] = {
   { /* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_16 */
      cliauth_io_parse_string_block_data_base_16_initialize,
      cliauth_io_parse_string_block_data_base_16_flush,
      cliauth_io_parse_string_block_data_base_16_digest_digit
   },
   { /* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_32 */
      cliauth_io_parse_string_block_data_base_32_initialize,
      cliauth_io_parse_string_block_data_base_32_flush,
      cliauth_io_parse_string_block_data_base_32_digest_digit
   }
};

void
cliauth_io_parse_string_block_data_initialize(
   struct CliAuthIoParseStringBlockDataContext * context,
   enum CliAuthIoParseStringBlockDataBase base
) {
   const struct CliAuthIoParseStringBlockDataFunctions * functions;

   functions = &cliauth_io_parse_string_block_data_functions[base];

   functions->initialize(context);
   context->base = base;

   return;
}

struct CliAuthIoParseStringBlockDataDigestResult
cliauth_io_parse_string_block_data_digest(
   struct CliAuthIoParseStringBlockDataContext * context,
   const struct CliAuthIoStreamReader * reader,
   const struct CliAuthIoStreamWriter * writer,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoParseStringBlockDataDigestResult result;
   const struct CliAuthIoParseStringBlockDataFunctions * functions;
   CliAuthUInt32 read_bytes;
   CliAuthUInt32 written_bytes;
   CliAuthUInt8 character;

   functions = &cliauth_io_parse_string_block_data_functions[context->base];
   read_bytes = CLIAUTH_LITERAL_UINT32(0u);
   written_bytes = CLIAUTH_LITERAL_UINT32(0u);

   /* if the first flush fails, this will be returned uninitialized, so we */
   /* have to initialize it manually for safety */
   result.read_result.status = CLIAUTH_IO_STATUS_SUCCESS;

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      /* preliminary flush to ensure the shift buffer won't overflow */
      result.write_result = functions->flush(context, writer);
      written_bytes += result.write_result.bytes;
      if (result.write_result.status != CLIAUTH_IO_STATUS_SUCCESS) {
         result.status = CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_IO_WRITE_ERROR;
         goto exit;
      }

      /* attempt to read in the next character, this doesn't need an */
      /* interruptible read buffer since we're only reading a single byte */
      /* for now */
      result.read_result = cliauth_io_stream_reader_read(
         reader,
         &character,
         CLIAUTH_LITERAL_UINT32(sizeof(character))
      );
      read_bytes += result.read_result.bytes;
      if (result.read_result.status != CLIAUTH_IO_STATUS_SUCCESS) {
         result.status = CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_IO_READ_ERROR;
         goto exit;
      }

      result.status = functions->digest_digit(context, character);
      switch (result.status) {
         case CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_SUCCESS:
            break;

         case CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_INVALID_DIGIT:
            result.payload.invalid_digit.digit = character;
            goto exit;

         default:
            /* I/O errors were handled above, should never be reachable */
            CLIAUTH_UNREACHABLE;
      }
      if (result.status != CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_SUCCESS) {
         goto exit;
      }

      bytes -= CLIAUTH_LITERAL_UINT32(sizeof(character));
   }

   /* status enums are set above, will only be set to success values if we */
   /* reach here without a goto jump */
exit:
   result.read_result.bytes = read_bytes;
   result.write_result.bytes = written_bytes;
   return result;
}

struct CliAuthIoResult
cliauth_io_parse_string_block_data_finalize(
   struct CliAuthIoParseStringBlockDataContext * context,
   const struct CliAuthIoStreamWriter * writer
) {
   const struct CliAuthIoParseStringBlockDataFunctions * functions;

   functions = &cliauth_io_parse_string_block_data_functions[context->base];

   /* we simply just flush the shift buffer, discarding any remainder bits */
   return functions->flush(context, writer);
}

