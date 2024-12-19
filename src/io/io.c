/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/io.c - Generic I/O interface implementations.                       */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io/io.h"

struct CliAuthIoResult
cliauth_io_stream_reader_read(
   const struct CliAuthIoStreamReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
) {
   return reader->read(
      reader->context,
      buffer,
      bytes
   );
}

struct CliAuthIoResult
cliauth_io_stream_writer_write(
   const struct CliAuthIoStreamWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
) {
   return writer->write(
      writer->context,
      data,
      bytes
   );
}

struct CliAuthIoResult
cliauth_io_mapper_reader_read(
   const struct CliAuthIoMapperReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
) {
   return reader->read(
      reader->context,
      buffer,
      bytes,
      offset
   );
}

struct CliAuthIoResult
cliauth_io_mapper_writer_write(
   const struct CliAuthIoMapperWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
) {
   return writer->write(
      writer->context,
      data,
      bytes,
      offset
   );
}

