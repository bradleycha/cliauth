/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/io/mapper_stream.c - I/O stream over an I/O mapper             */
/*    implementations.                                                        */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/io/mapper_stream.h"

#include "cliauth/io/io.h"

static struct CliAuthIoResult
cliauth_io_mapper_stream_reader_read(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoResult result;
   struct CliAuthIoMapperStreamReader * reader;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_read_count;

   reader = (struct CliAuthIoMapperStreamReader *)context;

   bytes_remaining = reader->length - reader->position;

   if (bytes_remaining == CLIAUTH_LITERAL_UINT32(0u)) {
      result.status = CLIAUTH_IO_STATUS_END_OF_STREAM;
      result.bytes = CLIAUTH_LITERAL_UINT32(0u);
      return result;
   }

   if (bytes > bytes_remaining) {
      bytes_read_count = bytes_remaining;
   } else {
      bytes_read_count = bytes;
   }

   result = cliauth_io_mapper_reader_read(
      reader->backing_mapper_reader,
      buffer,
      bytes_read_count,
      reader->position
   );
   reader->position += result.bytes;

   return result;
}

static struct CliAuthIoResult
cliauth_io_mapper_stream_writer_write(
   void * context,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoResult result;
   struct CliAuthIoMapperStreamWriter * writer;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_write_count;

   writer = (struct CliAuthIoMapperStreamWriter *)context;

   bytes_remaining = writer->length - writer->position;

   if (bytes_remaining == CLIAUTH_LITERAL_UINT32(0u)) {
      result.status = CLIAUTH_IO_STATUS_END_OF_STREAM;
      result.bytes = CLIAUTH_LITERAL_UINT32(0u);
      return result;
   }

   if (bytes > bytes_remaining) {
      bytes_write_count = bytes_remaining;
   } else {
      bytes_write_count = bytes;
   }

   result = cliauth_io_mapper_writer_write(
      writer->backing_mapper_writer,
      data,
      bytes_write_count,
      writer->position
   );
   writer->position += result.bytes;

   return result;
}

void
cliauth_io_mapper_stream_reader_initialize(
   struct CliAuthIoMapperStreamReader * context,
   const struct CliAuthIoMapperReader * backing_mapper_reader,
   CliAuthUInt32 length,
   CliAuthUInt32 offset
) {
   context->backing_mapper_reader = backing_mapper_reader;
   context->length = length;
   context->position = offset;

   return;
}

void
cliauth_io_mapper_stream_writer_initialize(
   struct CliAuthIoMapperStreamWriter * context,
   const struct CliAuthIoMapperWriter * backing_mapper_writer,
   CliAuthUInt32 length,
   CliAuthUInt32 offset
) {
   context->backing_mapper_writer = backing_mapper_writer;
   context->length = length;
   context->position = offset;

   return;
}

struct CliAuthIoStreamReader
cliauth_io_mapper_stream_reader_interface(
   struct CliAuthIoMapperStreamReader * context
) {
   struct CliAuthIoStreamReader retn;

   retn.read = cliauth_io_mapper_stream_reader_read;
   retn.context = context;
   
   return retn;
}

struct CliAuthIoStreamWriter
cliauth_io_mapper_stream_writer_interface(
   struct CliAuthIoMapperStreamWriter * context
) {
   struct CliAuthIoStreamWriter retn;

   retn.write = cliauth_io_mapper_stream_writer_write;
   retn.context = context;
   
   return retn;
}

