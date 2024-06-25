/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io.c - Generic I/O interface implementations.                          */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io.h"

#include <string.h>
#include "endian.h"

struct CliAuthIoReadResult
cliauth_io_reader_read(
   const struct CliAuthIoReader * reader,
   void * buffer,
   CliAuthUInt32 bytes
) {
   return reader->reader(
      reader->context,
      buffer,
      bytes
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_all(
   const struct CliAuthIoReader * reader,
   void * buffer,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoReadResult read_result;
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt32 read_bytes;

   buffer_iter = (CliAuthUInt8 *)buffer;
   read_bytes = 0;

   while (bytes != 0) {
      read_result = cliauth_io_reader_read(
         reader,
         buffer_iter,
         bytes
      );
      read_bytes += read_result.bytes;

      if (read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
         read_result.bytes = read_bytes;
         return read_result;
      }

      buffer_iter += read_result.bytes;
      bytes -= read_result.bytes;
   }

   read_result.status = CLIAUTH_IO_READ_STATUS_SUCCESS;
   read_result.bytes = read_bytes;
   return read_result;
}

struct CliAuthIoReadResult
cliauth_io_reader_read_uint8(
   const struct CliAuthIoReader * reader,
   CliAuthUInt8 * output
) {
   return cliauth_io_reader_read_all(
      reader,
      output,
      sizeof(CliAuthUInt8)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_sint8(
   const struct CliAuthIoReader * reader,
   CliAuthSInt8 * output
) {
   return cliauth_io_reader_read_all(
      reader,
      output,
      sizeof(CliAuthSInt8)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_little(
   const struct CliAuthIoReader * reader,
   void * output,
   CliAuthUInt8 bytes
) {
   struct CliAuthIoReadResult read_result;

   read_result = cliauth_io_reader_read_all(
      reader,
      output,
      bytes
   );
   if (read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
      return read_result;
   }

   cliauth_endian_host_to_little_inplace(output, bytes);

   return read_result;
}

struct CliAuthIoReadResult
cliauth_io_reader_read_little_uint16(
   const struct CliAuthIoReader * reader,
   CliAuthUInt16 * output
) {
   return cliauth_io_reader_read_little(
      reader,
      output,
      sizeof(CliAuthUInt16)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_little_uint32(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output
) {
   return cliauth_io_reader_read_little(
      reader,
      output,
      sizeof(CliAuthUInt32)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_little_uint64(
   const struct CliAuthIoReader * reader,
   CliAuthUInt64 * output
) {
   return cliauth_io_reader_read_little(
      reader,
      output,
      sizeof(CliAuthUInt64)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_little_sint16(
   const struct CliAuthIoReader * reader,
   CliAuthSInt16 * output
) {
   return cliauth_io_reader_read_little(
      reader,
      output,
      sizeof(CliAuthSInt16)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_little_sint32(
   const struct CliAuthIoReader * reader,
   CliAuthSInt32 * output
) {
   return cliauth_io_reader_read_little(
      reader,
      output,
      sizeof(CliAuthSInt32)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_little_sint64(
   const struct CliAuthIoReader * reader,
   CliAuthSInt64 * output
) {
   return cliauth_io_reader_read_little(
      reader,
      output,
      sizeof(CliAuthSInt64)
   );
}

static struct CliAuthIoReadResult
cliauth_io_reader_read_big(
   const struct CliAuthIoReader * reader,
   void * output,
   CliAuthUInt8 bytes
) {
   struct CliAuthIoReadResult read_result;

   read_result = cliauth_io_reader_read_all(
      reader,
      output,
      bytes
   );
   if (read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
      return read_result;
   }

   cliauth_endian_host_to_big_inplace(output, bytes);

   return read_result;
}

struct CliAuthIoReadResult
cliauth_io_reader_read_big_uint16(
   const struct CliAuthIoReader * reader,
   CliAuthUInt16 * output
) {
   return cliauth_io_reader_read_big(
      reader,
      output,
      sizeof(CliAuthUInt16)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_big_uint32(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output
) {
   return cliauth_io_reader_read_big(
      reader,
      output,
      sizeof(CliAuthUInt32)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_big_uint64(
   const struct CliAuthIoReader * reader,
   CliAuthUInt64 * output
) {
   return cliauth_io_reader_read_big(
      reader,
      output,
      sizeof(CliAuthUInt64)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_big_sint16(
   const struct CliAuthIoReader * reader,
   CliAuthSInt16 * output
) {
   return cliauth_io_reader_read_big(
      reader,
      output,
      sizeof(CliAuthSInt16)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_big_sint32(
   const struct CliAuthIoReader * reader,
   CliAuthSInt32 * output
) {
   return cliauth_io_reader_read_big(
      reader,
      output,
      sizeof(CliAuthSInt32)
   );
}

struct CliAuthIoReadResult
cliauth_io_reader_read_big_sint64(
   const struct CliAuthIoReader * reader,
   CliAuthSInt64 * output
) {
   return cliauth_io_reader_read_big(
      reader,
      output,
      sizeof(CliAuthSInt64)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write(
   const struct CliAuthIoWriter * writer,
   const void * data,
   CliAuthUInt32 bytes
) {
   return writer->writer(
      writer->context,
      data,
      bytes
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_all(
   const struct CliAuthIoWriter * writer,
   const void * data,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoWriteResult write_result;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 write_bytes;

   data_iter = (const CliAuthUInt8 *)data;
   write_bytes = 0;

   while (bytes != 0) {
      write_result = cliauth_io_writer_write(
         writer,
         data_iter,
         bytes
      );
      write_bytes += write_result.bytes;

      if (write_result.status != CLIAUTH_IO_WRITE_STATUS_SUCCESS) {
         write_result.bytes = write_bytes;
         return write_result;
      }

      data_iter += write_result.bytes;
      bytes -= write_result.bytes;
   }
   
   write_result.status = CLIAUTH_IO_WRITE_STATUS_SUCCESS;
   write_result.bytes = write_bytes;
   return write_result;
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_uint8(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt8 value
) {
   return cliauth_io_writer_write_all(
      writer,
      &value,
      sizeof(CliAuthUInt8)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_sint8(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt8 value
) {
   return cliauth_io_writer_write_all(
      writer,
      &value,
      sizeof(CliAuthSInt8)
   );
}

static struct CliAuthIoWriteResult
cliauth_io_writer_write_little(
   const struct CliAuthIoWriter * writer,
   void * value,
   CliAuthUInt8 bytes
) {
   cliauth_endian_host_to_little_inplace(value, bytes);

   return cliauth_io_writer_write_all(
      writer,
      value,
      bytes
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_little_uint16(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt16 value
) {
   return cliauth_io_writer_write_little(
      writer,
      &value,
      sizeof(CliAuthUInt16)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_little_uint32(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 value
) {
   return cliauth_io_writer_write_little(
      writer,
      &value,
      sizeof(CliAuthUInt32)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_little_uint64(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt64 value
) {
   return cliauth_io_writer_write_little(
      writer,
      &value,
      sizeof(CliAuthUInt64)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_little_sint16(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt16 value
) {
   return cliauth_io_writer_write_little(
      writer,
      &value,
      sizeof(CliAuthSInt16)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_little_sint32(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt32 value
) {
   return cliauth_io_writer_write_little(
      writer,
      &value,
      sizeof(CliAuthSInt32)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_little_sint64(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt64 value
) {
   return cliauth_io_writer_write_little(
      writer,
      &value,
      sizeof(CliAuthSInt64)
   );
}

static struct CliAuthIoWriteResult
cliauth_io_writer_write_big(
   const struct CliAuthIoWriter * writer,
   void * value,
   CliAuthUInt8 bytes
) {
   cliauth_endian_host_to_big_inplace(value, bytes);

   return cliauth_io_writer_write_all(
      writer,
      value,
      bytes
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_big_uint16(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt16 value
) {
   return cliauth_io_writer_write_big(
      writer,
      &value,
      sizeof(CliAuthUInt16)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_big_uint32(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 value
) {
   return cliauth_io_writer_write_big(
      writer,
      &value,
      sizeof(CliAuthUInt32)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_big_uint64(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt64 value
) {
   return cliauth_io_writer_write_big(
      writer,
      &value,
      sizeof(CliAuthUInt64)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_big_sint16(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt16 value
) {
   return cliauth_io_writer_write_big(
      writer,
      &value,
      sizeof(CliAuthSInt16)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_big_sint32(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt32 value
) {
   return cliauth_io_writer_write_big(
      writer,
      &value,
      sizeof(CliAuthSInt32)
   );
}

struct CliAuthIoWriteResult
cliauth_io_writer_write_big_sint64(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt64 value
) {
   return cliauth_io_writer_write_big(
      writer,
      &value,
      sizeof(CliAuthSInt64)
   );
}

static struct CliAuthIoReadResult
cliauth_io_byte_stream_reader_read(
   void * context,
   void * buffer,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoReadResult read_result;
   struct CliAuthIoByteStreamReader * reader;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_read_count;
   const CliAuthUInt8 * bytes_read_ptr;

   reader = (struct CliAuthIoByteStreamReader *)context;

   bytes_remaining = reader->length - reader->position;

   if (bytes_remaining == 0) {
      read_result.status = CLIAUTH_IO_READ_STATUS_END_OF_STREAM;
      read_result.bytes = 0;
      return read_result;
   }

   if (bytes > bytes_remaining) {
      bytes_read_count = bytes_remaining;
   } else {
      bytes_read_count = bytes;
   }

   bytes_read_ptr = &reader->bytes[reader->position];

   (void)memcpy(buffer, bytes_read_ptr, bytes_read_count);
   reader->position += bytes_read_count;

   read_result.status = CLIAUTH_IO_READ_STATUS_SUCCESS;
   read_result.bytes = bytes_read_count;
   return read_result;
}

static struct CliAuthIoWriteResult
cliauth_io_byte_stream_writer_write(
   void * context,
   const void * data,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoWriteResult write_result;
   struct CliAuthIoByteStreamWriter * writer;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_write_count;
   CliAuthUInt8 * bytes_write_ptr;

   writer = (struct CliAuthIoByteStreamWriter *)context;

   bytes_remaining = writer->length - writer->position;

   if (bytes_remaining == 0) {
      write_result.status = CLIAUTH_IO_WRITE_STATUS_END_OF_STREAM;
      write_result.bytes = 0;
      return write_result;
   }

   if (bytes > bytes_remaining) {
      bytes_write_count = bytes_remaining;
   } else {
      bytes_write_count = bytes;
   }

   bytes_write_ptr = &writer->bytes[writer->position];

   (void)memcpy(bytes_write_ptr, data, bytes_write_count);
   writer->position += bytes_write_count;
   
   write_result.status = CLIAUTH_IO_WRITE_STATUS_SUCCESS;
   write_result.bytes = bytes_write_count;
   return write_result;
}

void
cliauth_io_byte_stream_reader_initialize(
   struct CliAuthIoByteStreamReader * context,
   const void * bytes,
   CliAuthUInt32 length
) {
   context->bytes = (const CliAuthUInt8 *)bytes;
   context->length = length;
   context->position = 0;

   return;
}

void
cliauth_io_byte_stream_writer_initialize(
   struct CliAuthIoByteStreamWriter * context,
   void * bytes,
   CliAuthUInt32 length
) {
   context->bytes = (CliAuthUInt8 *)bytes;
   context->length = length;
   context->position = 0;

   return;
}

struct CliAuthIoReader
cliauth_io_byte_stream_reader_interface(
   struct CliAuthIoByteStreamReader * context
) {
   struct CliAuthIoReader retn;

   retn.reader = cliauth_io_byte_stream_reader_read;
   retn.context = context;

   return retn;
}

struct CliAuthIoWriter
cliauth_io_byte_stream_writer_interface(
   struct CliAuthIoByteStreamWriter * context
) {
   struct CliAuthIoWriter retn;

   retn.writer = cliauth_io_byte_stream_writer_write;
   retn.context = context;

   return retn;
}

