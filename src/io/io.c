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
cliauth_io_stream_reader_read_all(
   const struct CliAuthIoStreamReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoResult result;
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt32 read_bytes;

   buffer_iter = buffer;
   read_bytes = CLIAUTH_LITERAL_UINT32(0u);

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      result = cliauth_io_stream_reader_read(
         reader,
         buffer_iter,
         bytes
      );
      read_bytes += result.bytes;

      if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
         result.bytes = read_bytes;
         return result;
      }

      buffer_iter += result.bytes;
      bytes -= result.bytes;
   }

   result.status = CLIAUTH_IO_STATUS_SUCCESS;
   result.bytes = read_bytes;
   return result;
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
cliauth_io_stream_writer_write_all(
   const struct CliAuthIoStreamWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoResult result;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 write_bytes;

   data_iter = data;
   write_bytes = CLIAUTH_LITERAL_UINT32(0u);

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      result = cliauth_io_stream_writer_write(
         writer,
         data_iter,
         bytes
      );
      write_bytes += result.bytes;

      if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
         result.bytes = write_bytes;
         return result;
      }

      data_iter += result.bytes;
      bytes -= result.bytes;
   }
   
   result.status = CLIAUTH_IO_STATUS_SUCCESS;
   result.bytes = write_bytes;
   return result;
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
cliauth_io_mapper_reader_read_all(
   const struct CliAuthIoMapperReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
) {
   struct CliAuthIoResult result;
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt32 read_bytes;

   buffer_iter = buffer;
   read_bytes = CLIAUTH_LITERAL_UINT32(0u);

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      result = cliauth_io_mapper_reader_read(
         reader,
         buffer_iter,
         bytes,
         offset
      );
      read_bytes += result.bytes;

      if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
         result.bytes = read_bytes;
         return result;
      }

      buffer_iter += result.bytes;
      bytes -= result.bytes;
      offset += result.bytes;
   }

   result.status = CLIAUTH_IO_STATUS_SUCCESS;
   result.bytes = read_bytes;
   return result;
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

struct CliAuthIoResult
cliauth_io_mapper_writer_write_all(
   const struct CliAuthIoMapperWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
) {
   struct CliAuthIoResult result;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 write_bytes;

   data_iter = data;
   write_bytes = CLIAUTH_LITERAL_UINT32(0u);

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      result = cliauth_io_mapper_writer_write(
         writer,
         data_iter,
         bytes,
         offset
      );
      write_bytes += result.bytes;

      if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
         result.bytes = write_bytes;
         return result;
      }

      data_iter += result.bytes;
      bytes -= result.bytes;
      offset += result.bytes;
   }
   
   result.status = CLIAUTH_IO_STATUS_SUCCESS;
   result.bytes = write_bytes;
   return result;
}

