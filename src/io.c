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

#if CLIAUTH_CONFIG_IO_BUFFERING
/*----------------------------------------------------------------------------*/

static struct CliAuthIoReadResult
cliauth_io_buffered_reader_read(
   void * context,
   void * buffer,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoReadResult read_result;
   struct CliAuthIoBufferedReader * context_reader;
   CliAuthUInt8 * read_buffer_start;
   CliAuthUInt32 read_total;
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt32 buffer_bytes;
   CliAuthUInt32 residual_bytes;

   context_reader = (struct CliAuthIoBufferedReader *)context;

   /* calculate the start of the read buffer */
   read_buffer_start = &context_reader->buffer[context_reader->start];

   /* if we already have the required number of bytes in the buffer, simply */
   /* take them from the buffer */
   if (bytes < context_reader->length - context_reader->capacity) {
      (void)memcpy(
         buffer,
         read_buffer_start,
         bytes
      );

      context_reader->start += bytes;
      context_reader->capacity += bytes;

      read_result.status = CLIAUTH_IO_READ_STATUS_SUCCESS;
      read_result.bytes = bytes;

      return read_result;
   }

   /* initialize the total number of read bytes */
   read_total = 0;

   /* initialize the buffer iterator */
   buffer_iter = (CliAuthUInt8 *)buffer;

   /* calculate the number of bytes which need to be read after draining the */
   /* read buffer as well as drained from the read buffer */
   buffer_bytes = context_reader->length - context_reader->capacity;
   residual_bytes = bytes - buffer_bytes;

   /* drain the entire read buffer */
   (void)memcpy(
      buffer_iter,
      read_buffer_start,
      buffer_bytes
   );

   context_reader->start = 0;
   context_reader->capacity = context_reader->length;

   read_total += buffer_bytes;
   buffer_iter += buffer_bytes;

   /* read the rest of the remaining bytes */
   read_result = cliauth_io_reader_read_all(
      context_reader->backing_reader,
      buffer_iter,
      residual_bytes
   );
   read_total += read_result.bytes;

   if (read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
      read_result.bytes = read_total;
      return read_result;
   }

   /* buffer in a new block into the read buffer, ignoring errors and simply */
   /* accepting whatever number of bytes we were given */
   read_result = cliauth_io_reader_read_all(
      context_reader->backing_reader,
      context_reader->buffer,
      context_reader->length
   );
   context_reader->capacity -= read_result.bytes;
   
   /* lastly update to return the total bytes read, not including the new */
   /* read buffer block */
   read_result.status = CLIAUTH_IO_READ_STATUS_SUCCESS;
   read_result.bytes = read_total;
   return read_result;
}

static struct CliAuthIoWriteResult
cliauth_io_buffered_writer_write(
   void * context,
   const void * data,
   CliAuthUInt32 bytes
) {
   struct CliAuthIoWriteResult write_result;
   struct CliAuthIoBufferedWriter * context_writer;
   CliAuthUInt8 * buffer_free;
   CliAuthUInt32 write_total;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 fill_bytes;
   CliAuthUInt32 residual_bytes;
   CliAuthUInt32 block_bytes;

   context_writer = (struct CliAuthIoBufferedWriter *)context;

   /* calculate the pointer to the start of the write buffer free space */
   buffer_free = &context_writer->buffer[
      (
         context_writer->start + context_writer->length - context_writer->capacity
      ) % context_writer->length
   ];

   /* if the number of bytes we are writing is less than the remaining */
   /* buffer capacity, simply append the data into the buffer */
   if (bytes < context_writer->capacity) {
      (void)memcpy(buffer_free, data, bytes);

      context_writer->capacity -= bytes;

      write_result.status = CLIAUTH_IO_WRITE_STATUS_SUCCESS;
      write_result.bytes = bytes;

      return write_result;
   }

   /* initialize the total number of written bytes */
   write_total = 0;

   /* initialize the data iterator */
   data_iter = (const CliAuthUInt8 *)data;

   /* calculate the bytes for the fill bytes, aligned block, and residual bytes */
   fill_bytes = context_writer->capacity;
   residual_bytes = (bytes - fill_bytes) % context_writer->length;
   block_bytes = bytes - fill_bytes - residual_bytes;

   /* fill the write buffer, capacity will be updated upon writing */
   (void)memcpy(buffer_free, data_iter, fill_bytes);
   context_writer->capacity = 0;

   /* attempt to flush the write buffer */
   write_result = cliauth_io_buffered_writer_flush(context_writer);
   write_total += write_result.bytes;
   data_iter += write_result.bytes;

   if (write_result.status != CLIAUTH_IO_WRITE_STATUS_SUCCESS) {
      write_result.bytes = write_total;
      return write_result;
   }

   /* attempt to write out all the full-sized blocks at once */
   write_result = cliauth_io_writer_write_all(
      context_writer->backing_writer,
      data_iter,
      block_bytes
   );
   write_total += write_result.bytes;
   data_iter += write_result.bytes;

   if (write_result.status != CLIAUTH_IO_WRITE_STATUS_SUCCESS) {
      write_result.bytes = write_total;
      return write_result;
   }

   /* copy the remaining bytes into the write buffer */
   (void)memcpy(context_writer->buffer, data_iter, residual_bytes);
   context_writer->start = 0;
   context_writer->capacity = context_writer->length - residual_bytes;
   write_total += residual_bytes;

   /* lastly update to return the total bytes written */
   write_result.bytes = write_total;
   return write_result;
}

void
cliauth_io_buffered_reader_initialize(
   struct CliAuthIoBufferedReader * context,
   const struct CliAuthIoReader * backing_reader,
   void * buffer,
   CliAuthUInt32 length
) {
   context->backing_reader = backing_reader;
   context->buffer = (CliAuthUInt8 *)buffer;
   context->length = length;
   context->start = 0;
   context->capacity = length;

   return;
}

void
cliauth_io_buffered_writer_initialize(
   struct CliAuthIoBufferedWriter * context,
   const struct CliAuthIoWriter * backing_writer,
   void * buffer,
   CliAuthUInt32 length
) {
   context->backing_writer = backing_writer;
   context->buffer = (CliAuthUInt8 *)buffer;
   context->length = length;
   context->start = 0;
   context->capacity = length;

   return;
}

struct CliAuthIoReader
cliauth_io_buffered_reader_interface(
   struct CliAuthIoBufferedReader * context
) {
   struct CliAuthIoReader retn;

   retn.reader = cliauth_io_buffered_reader_read;
   retn.context = context;

   return retn;
}

struct CliAuthIoWriter
cliauth_io_buffered_writer_interface(
   struct CliAuthIoBufferedWriter * context
) {
   struct CliAuthIoWriter retn;

   retn.writer = cliauth_io_buffered_writer_write;
   retn.context = context;

   return retn;
}

static struct CliAuthIoWriteResult
cliauth_io_buffered_writer_flush_unified(
   struct CliAuthIoBufferedWriter * context
) {
   struct CliAuthIoWriteResult result;
   CliAuthUInt8 * data_ptr;
   CliAuthUInt32 data_bytes;

   /* calculate the buffer slice to flush */
   data_ptr    = &context->buffer[context->start];
   data_bytes  = context->length - context->capacity;

   /* attempt to write the buffer slice */
   result = cliauth_io_writer_write_all(
      context->backing_writer,
      data_ptr,
      data_bytes
   );

   /* remove the successfully written bytes from the buffer */
   context->start = (context->start + result.bytes) % context->length;
   context->capacity = context->capacity + result.bytes;

   /* IO errors can be safely handled by the caller */
   return result;
}

static struct CliAuthIoWriteResult
cliauth_io_buffered_writer_flush_fragmented(
   struct CliAuthIoBufferedWriter * context
) {
   struct CliAuthIoWriteResult result;
   CliAuthUInt8 * fill_ptr;
   CliAuthUInt32 fill_bytes;
   CliAuthUInt8 * remainder_ptr;
   CliAuthUInt32 remainder_bytes;

   /* calculate the buffer slices to flush */
   fill_ptr = &context->buffer[context->start];
   fill_bytes = context->length - context->start;
   remainder_ptr = context->buffer;
   remainder_bytes = context->start - context->capacity;

   /* attempt to write the 'fill' buffer slice */
   result = cliauth_io_writer_write_all(
      context->backing_writer,
      fill_ptr,
      fill_bytes
   );

   /* remove the successfully written bytes from the buffer */
   context->start = (context->start + result.bytes) % context->length;
   context->capacity = context->capacity + result.bytes;

   /* if the write resulted in an error, pass the result to the caller */
   if (result.status != CLIAUTH_IO_WRITE_STATUS_SUCCESS) {
      return result;
   }

   /* attempt to write the 'remainder' buffer slice */
   result = cliauth_io_writer_write_all(
      context->backing_writer,
      remainder_ptr,
      remainder_bytes
   );

   /* remove the successfully written bytes from the buffer */
   context->start = result.bytes;
   context->capacity = context->capacity + result.bytes;

   /* make sure to append the previously written bytes */
   result.bytes += fill_bytes;

   /* return the total number of written bytes and any IO error */
   return result;
}

struct CliAuthIoWriteResult
cliauth_io_buffered_writer_flush(
   struct CliAuthIoBufferedWriter * context
) {
   struct CliAuthIoWriteResult result;

   /* if the buffer is not fragmented, simply flush the entire buffer */
   /* otherwise we will need to flush each portion seperately */
   if (context->start > context->capacity) {
      result = cliauth_io_buffered_writer_flush_fragmented(context);
   } else {
      result = cliauth_io_buffered_writer_flush_unified(context);
   }

   return result;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_IO_BUFFERING */

