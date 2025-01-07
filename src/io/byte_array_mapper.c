/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/byte_array_mapper.c - Byte array I/O mapper layer implementations.  */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io/byte_array_mapper.h"

#include "io/io.h"
#include "memory/memory.h"

static struct CliAuthIoResult
cliauth_io_byte_array_mapper_reader_read(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
) {
   struct CliAuthIoResult result;
   struct CliAuthIoByteArrayMapperReader * reader;

   reader = (struct CliAuthIoByteArrayMapperReader *)context;

   cliauth_memory_copy(
      buffer,
      &reader->data[offset],
      bytes
   );

   result.status = CLIAUTH_IO_STATUS_SUCCESS;
   result.bytes = bytes;
   return result;
}

static struct CliAuthIoResult
cliauth_io_byte_array_mapper_writer_write(
   void * context,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
) {
   struct CliAuthIoResult result;
   struct CliAuthIoByteArrayMapperWriter * writer;

   writer = (struct CliAuthIoByteArrayMapperWriter *)context;

   cliauth_memory_copy(
      &writer->data[offset],
      data,
      bytes
   );

   result.status = CLIAUTH_IO_STATUS_SUCCESS;
   result.bytes = bytes;
   return result;
}

void
cliauth_io_byte_array_mapper_reader_initialize(
   struct CliAuthIoByteArrayMapperReader * context,
   const CliAuthUInt8 bytes []
) {
   context->data = bytes;

   return;
}

void
cliauth_io_byte_array_mapper_writer_initialize(
   struct CliAuthIoByteArrayMapperWriter * context,
   CliAuthUInt8 bytes []
) {
   context->data = bytes;

   return;
}

struct CliAuthIoMapperReader
cliauth_io_byte_array_mapper_reader_interface(
   struct CliAuthIoByteArrayMapperReader * context
) {
   struct CliAuthIoMapperReader retn;

   retn.read = cliauth_io_byte_array_mapper_reader_read;
   retn.context = context;

   return retn;
}

struct CliAuthIoMapperWriter
cliauth_io_byte_array_mapper_writer_interface(
   struct CliAuthIoByteArrayMapperWriter * context
) {
   struct CliAuthIoMapperWriter retn;

   retn.write = cliauth_io_byte_array_mapper_writer_write;
   retn.context = context;

   return retn;
}

