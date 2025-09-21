/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/io/parse/string_block_data.h - String block data parser.       */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_H
#define _CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_H
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/io/io.h"

/*----------------------------------------------------------------------------*/
/* The result status of digesting string block data characters.               */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_SUCCESS -                 */
/*    The string block data was parsed successfully.                          */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_IO_READ_ERROR -           */
/*    An I/O error occurred during reading.                                   */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_IO_WRITE_ERROR -          */
/*    An I/O error occurred during writing.                                   */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_INVALID_DIGIT -           */
/*    An invalid digit for the given base was encountered.                    */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_FIELD_COUNT 4u
enum CliAuthIoParseStringBlockDataDigestStatus {
   CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_SUCCESS,
   CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_IO_READ_ERROR,
   CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_IO_WRITE_ERROR,
   CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_STATUS_INVALID_DIGIT
};

/*----------------------------------------------------------------------------*/
/* The payload struct for when an invalid digit is encountered.               */
/*----------------------------------------------------------------------------*/
/* digit -                                                                    */
/*    The digit which could not be parsed.                                    */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringBlockDataDigestPayloadInvalidDigit {
   CliAuthUInt8 digit;
};

/*----------------------------------------------------------------------------*/
/* The payload struct for when a status enum contains additional data.        */
/*----------------------------------------------------------------------------*/
/* invalid_digit -                                                            */
/*    The payload data for CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_DIGEST_...      */
/*    ...STATUS_INVALID_DIGIT.                                                */
/*----------------------------------------------------------------------------*/
union CliAuthIoParseStringBlockDataDigestPayload {
   struct CliAuthIoParseStringBlockDataDigestPayloadInvalidDigit invalid_digit;
};

/*----------------------------------------------------------------------------*/
/* The result of digest characters from a block data string.                  */
/*----------------------------------------------------------------------------*/
/* status -                                                                   */
/*    The status of the string block data digestion.                          */
/*                                                                            */
/* payload -                                                                  */
/*    Additional data relevant to the status of the string block data         */
/*    digestion.                                                              */
/*                                                                            */
/* read_result -                                                              */
/*    The I/O read result.  This will contain further details about potential */
/*    I/O read errors.                                                        */
/*                                                                            */
/* write_result -                                                             */
/*    The I/O write result.  This will contain further details about          */
/*    potential I/O read errors.                                              */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringBlockDataDigestResult {
   enum CliAuthIoParseStringBlockDataDigestStatus status;
   union CliAuthIoParseStringBlockDataDigestPayload payload;
   struct CliAuthIoResult read_result;
   struct CliAuthIoResult write_result;
};

/*----------------------------------------------------------------------------*/
/* A base to digest string block data characters in.                          */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_16 -                               */
/*    A base-16 block data string, also known as hexadecimal block data.      */
/*                                                                            */
/* CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_32 -                               */
/*    A base-32 block data string.                                            */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_FIELD_COUNT 2u
enum CliAuthIoParseStringBlockDataBase {
   /* this is only used to define enum values and should never be used */
   _CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_START_INDEX = -1,

   CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_16,
   CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_BASE_32
};

struct _CliAuthIoParseStringBlockDataContextBase16 {
   /* stores the previously parsed hexit bits. may be full in the event of a */
   /* flush error. */
   CliAuthUInt8 shift_buffer;

   /* the number of hexits stored in the shift buffer.  should never be */
   /* greater than '2'. */
   CliAuthUInt8 hexits_count;
};

struct _CliAuthIoParseStringBlockDataContextBase32 {
   /* this is a little weird.  up to 12 bits can be in the shift buffer at */
   /* once, which can cram both the shift buffer and bits count into a single */
   /* 16-bit word. the lower 12 bits contain the shift buffer, and the upper */
   /* 4 bits contain the number of bits in the shift buffer. */
   CliAuthUInt16 shift_buffer_and_bits_count;
};

union _CliAuthIoParseStringBlockDataContextBase {
   struct _CliAuthIoParseStringBlockDataContextBase16 base16;
   struct _CliAuthIoParseStringBlockDataContextBase32 base32;
};

/*----------------------------------------------------------------------------*/
/* Generic context for a string block data parser.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringBlockDataContext {
   union _CliAuthIoParseStringBlockDataContextBase context_base;
   enum CliAuthIoParseStringBlockDataBase base;
};

/*----------------------------------------------------------------------------*/
/* Initializes a string block data context.                                   */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The string block data context to initialize.                            */
/*                                                                            */
/* base -                                                                     */
/*    The base to parse digit characters as.                                  */
/*----------------------------------------------------------------------------*/
void
cliauth_io_parse_string_block_data_initialize(
   struct CliAuthIoParseStringBlockDataContext * context,
   enum CliAuthIoParseStringBlockDataBase base
);

/*----------------------------------------------------------------------------*/
/* Attempts to digest string block data characters, outputting to a stream    */
/* writer.                                                                    */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The string block data context to digest into.  This context must have   */
/*    first been initialized with the base's initialize function and must not */
/*    have been finalized by the base's finalize function.                    */
/*                                                                            */
/* reader -                                                                   */
/*    The I/O stream reader to read characters from.                          */
/*                                                                            */
/* writer -                                                                   */
/*    The I/O stream writer to write parsed binary data to.                   */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to read from 'reader'.                              */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of digesting the string block data characters.               */
/*----------------------------------------------------------------------------*/
struct CliAuthIoParseStringBlockDataDigestResult
cliauth_io_parse_string_block_data_digest(
   struct CliAuthIoParseStringBlockDataContext * context,
   const struct CliAuthIoStreamReader * reader,
   const struct CliAuthIoStreamWriter * writer,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to finalize the string block data context, flushing any remaining */
/* data.                                                                      */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The string block data context to finalize.  This context must first     */
/*    have been initialized with the base's initialize function.  Any excess  */
/*    bits which cannot form a complete byte will be discarded.               */
/*                                                                            */
/* writer -                                                                   */
/*    The I/O stream writer to flush any remaining binary data to.            */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of writing the remaining binary data.                        */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_parse_string_block_data_finalize(
   struct CliAuthIoParseStringBlockDataContext * context,
   const struct CliAuthIoStreamWriter * writer
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_PARSE_STRING_BLOCK_DATA_H */

