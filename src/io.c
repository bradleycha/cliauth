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

enum CliAuthIoReadStatus
cliauth_io_reader_read(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output_read_bytes,
   void * buffer,
   CliAuthUInt32 bytes
) {
   return reader->reader(
      reader->context,
      output_read_bytes,
      buffer,
      bytes
   );
}

enum CliAuthIoReadStatus
cliauth_io_reader_read_all(
   const struct CliAuthIoReader * reader,
   void * buffer,
   CliAuthUInt32 bytes
) {
   enum CliAuthIoReadStatus read_status;
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt32 read_bytes;

   buffer_iter = (CliAuthUInt8 *)buffer;

   while (bytes != 0) {
      read_status = cliauth_io_reader_read(
         reader,
         &read_bytes,
         buffer_iter,
         bytes
      );
      if (read_status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
         return read_status;
      }

      buffer_iter += read_bytes;
      bytes -= read_bytes;
   }
   
   return CLIAUTH_IO_READ_STATUS_SUCCESS;
}

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

static enum CliAuthIoReadStatus
cliauth_io_reader_read_little(
   const struct CliAuthIoReader * reader,
   void * output,
   CliAuthUInt8 bytes
) {
   enum CliAuthIoReadStatus read_status;

   read_status = cliauth_io_reader_read_all(
      reader,
      output,
      bytes
   );
   if (read_status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
      return read_status;
   }

   cliauth_endian_host_to_little_inplace(output, bytes);

   return CLIAUTH_IO_READ_STATUS_SUCCESS;
}

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

static enum CliAuthIoReadStatus
cliauth_io_reader_read_big(
   const struct CliAuthIoReader * reader,
   void * output,
   CliAuthUInt8 bytes
) {
   enum CliAuthIoReadStatus read_status;

   read_status = cliauth_io_reader_read_all(
      reader,
      output,
      bytes
   );
   if (read_status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
      return read_status;
   }

   cliauth_endian_host_to_big_inplace(output, bytes);

   return CLIAUTH_IO_READ_STATUS_SUCCESS;
}

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoReadStatus
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

enum CliAuthIoWriteStatus
cliauth_io_writer_write(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 * output_write_bytes,
   const void * data,
   CliAuthUInt32 bytes
) {
   return writer->writer(
      writer->context,
      output_write_bytes,
      data,
      bytes
   );
}

enum CliAuthIoWriteStatus
cliauth_io_writer_write_all(
   const struct CliAuthIoWriter * writer,
   const void * data,
   CliAuthUInt32 bytes
) {
   enum CliAuthIoWriteStatus write_status;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 write_bytes;

   data_iter = (const CliAuthUInt8 *)data;

   while (bytes != 0) {
      write_status = cliauth_io_writer_write(
         writer,
         &write_bytes,
         data_iter,
         bytes
      );
      if (write_status != CLIAUTH_IO_WRITE_STATUS_SUCCESS) {
         return write_status;
      }

      data_iter += write_bytes;
      bytes -= write_bytes;
   }
   
   return CLIAUTH_IO_WRITE_STATUS_SUCCESS;
}

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

static enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

static enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

enum CliAuthIoWriteStatus
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

static enum CliAuthIoReadStatus
cliauth_io_byte_stream_reader_read(
   void * context,
   CliAuthUInt32 * output_read_bytes,
   void * buffer,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoByteStreamReader * reader;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_read_count;
   const CliAuthUInt8 * bytes_read_ptr;

   reader = (struct CliAuthIoByteStreamReader *)context;

   bytes_remaining = reader->length - reader->position;

   if (bytes_remaining == 0) {
      return CLIAUTH_IO_READ_STATUS_END_OF_STREAM;
   }

   if (bytes > bytes_remaining) {
      bytes_read_count = bytes_remaining;
   } else {
      bytes_read_count = bytes;
   }

   bytes_read_ptr = &reader->bytes[reader->position];

   (void)memcpy(buffer, bytes_read_ptr, bytes_read_count);
   reader->position += bytes_read_count;
   *output_read_bytes = bytes_read_count;

   return CLIAUTH_IO_READ_STATUS_SUCCESS;
}

static enum CliAuthIoWriteStatus
cliauth_io_byte_stream_writer_write(
   void * context,
   CliAuthUInt32 * output_write_bytes,
   const void * data,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoByteStreamWriter * writer;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_write_count;
   CliAuthUInt8 * bytes_write_ptr;

   writer = (struct CliAuthIoByteStreamWriter *)context;

   bytes_remaining = writer->length - writer->position;

   if (bytes_remaining == 0) {
      return CLIAUTH_IO_WRITE_STATUS_END_OF_STREAM;
   }

   if (bytes > bytes_remaining) {
      bytes_write_count = bytes_remaining;
   } else {
      bytes_write_count = bytes;
   }

   bytes_write_ptr = &writer->bytes[writer->position];

   (void)memcpy(bytes_write_ptr, data, bytes_write_count);
   writer->position += bytes_write_count;
   *output_write_bytes = bytes_write_count;
   
   return CLIAUTH_IO_WRITE_STATUS_SUCCESS;
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

