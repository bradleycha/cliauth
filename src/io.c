/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io.c - Generic I/O interface implementations.                          */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io.h"

#include "memory.h"
#include "endian.h"

struct CliAuthIoReadResult
cliauth_io_reader_read(
   const struct CliAuthIoReader * reader,
   CliAuthUInt8 buffer [],
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
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoReadResult read_result;
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt32 read_bytes;

   buffer_iter = buffer;
   read_bytes = CLIAUTH_LITERAL_UINT32(0u);

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
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

struct CliAuthIoWriteResult
cliauth_io_writer_write(
   const struct CliAuthIoWriter * writer,
   const CliAuthUInt8 data [],
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
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoWriteResult write_result;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 write_bytes;

   data_iter = data;
   write_bytes = CLIAUTH_LITERAL_UINT32(0u);

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
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

static struct CliAuthIoReadResult
cliauth_io_byte_stream_reader_read(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoReadResult read_result;
   struct CliAuthIoByteStreamReader * reader;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_read_count;
   const CliAuthUInt8 * bytes_read_ptr;

   reader = (struct CliAuthIoByteStreamReader *)context;

   bytes_remaining = reader->length - reader->position;

   if (bytes_remaining == CLIAUTH_LITERAL_UINT32(0u)) {
      read_result.status = CLIAUTH_IO_READ_STATUS_END_OF_STREAM;
      read_result.bytes = CLIAUTH_LITERAL_UINT32(0u);
      return read_result;
   }

   if (bytes > bytes_remaining) {
      bytes_read_count = bytes_remaining;
   } else {
      bytes_read_count = bytes;
   }

   bytes_read_ptr = &reader->bytes[reader->position];

   cliauth_memory_copy(
      buffer,
      bytes_read_ptr,
      bytes_read_count
   );
   reader->position += bytes_read_count;

   read_result.status = CLIAUTH_IO_READ_STATUS_SUCCESS;
   read_result.bytes = bytes_read_count;
   return read_result;
}

static struct CliAuthIoWriteResult
cliauth_io_byte_stream_writer_write(
   void * context,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoWriteResult write_result;
   struct CliAuthIoByteStreamWriter * writer;
   CliAuthUInt32 bytes_remaining;
   CliAuthUInt32 bytes_write_count;
   CliAuthUInt8 * bytes_write_ptr;

   writer = (struct CliAuthIoByteStreamWriter *)context;

   bytes_remaining = writer->length - writer->position;

   if (bytes_remaining == CLIAUTH_LITERAL_UINT32(0u)) {
      write_result.status = CLIAUTH_IO_WRITE_STATUS_END_OF_STREAM;
      write_result.bytes = CLIAUTH_LITERAL_UINT32(0u);
      return write_result;
   }

   if (bytes > bytes_remaining) {
      bytes_write_count = bytes_remaining;
   } else {
      bytes_write_count = bytes;
   }

   bytes_write_ptr = &writer->bytes[writer->position];

   cliauth_memory_copy(
      bytes_write_ptr,
      data,
      bytes_write_count
   );
   writer->position += bytes_write_count;
   
   write_result.status = CLIAUTH_IO_WRITE_STATUS_SUCCESS;
   write_result.bytes = bytes_write_count;
   return write_result;
}

void
cliauth_io_byte_stream_reader_initialize(
   struct CliAuthIoByteStreamReader * context,
   const CliAuthUInt8 bytes [],
   CliAuthUInt32 length
) {
   context->bytes = bytes;
   context->length = length;
   context->position = CLIAUTH_LITERAL_UINT32(0u);

   return;
}

void
cliauth_io_byte_stream_writer_initialize(
   struct CliAuthIoByteStreamWriter * context,
   CliAuthUInt8 bytes [],
   CliAuthUInt32 length
) {
   context->bytes = bytes;
   context->length = length;
   context->position = CLIAUTH_LITERAL_UINT32(0u);

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
   CliAuthUInt8 buffer [],
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
      cliauth_memory_copy(
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
   read_total = CLIAUTH_LITERAL_UINT32(0u);

   /* initialize the buffer iterator */
   buffer_iter = buffer;

   /* calculate the number of bytes which need to be read after draining the */
   /* read buffer as well as drained from the read buffer */
   buffer_bytes = context_reader->length - context_reader->capacity;
   residual_bytes = bytes - buffer_bytes;

   /* drain the entire read buffer */
   cliauth_memory_copy(
      buffer_iter,
      read_buffer_start,
      buffer_bytes
   );

   context_reader->start = CLIAUTH_LITERAL_UINT32(0u);
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
   const CliAuthUInt8 data [],
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
      cliauth_memory_copy(
         buffer_free,
         data,
         bytes
      );

      context_writer->capacity -= bytes;

      write_result.status = CLIAUTH_IO_WRITE_STATUS_SUCCESS;
      write_result.bytes = bytes;

      return write_result;
   }

   /* initialize the total number of written bytes */
   write_total = CLIAUTH_LITERAL_UINT32(0u);

   /* initialize the data iterator */
   data_iter = data;

   /* calculate the bytes for the fill bytes, aligned block, and residual bytes */
   fill_bytes = context_writer->capacity;
   residual_bytes = (bytes - fill_bytes) % context_writer->length;
   block_bytes = bytes - fill_bytes - residual_bytes;

   /* fill the write buffer, capacity will be updated upon writing */
   cliauth_memory_copy(
      buffer_free,
      data_iter,
      fill_bytes
   );
   context_writer->capacity = CLIAUTH_LITERAL_UINT32(0u);

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
   cliauth_memory_copy(
      context_writer->buffer,
      data_iter,
      residual_bytes
   );
   context_writer->start = CLIAUTH_LITERAL_UINT32(0u);
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
   CliAuthUInt8 buffer [],
   CliAuthUInt32 length
) {
   context->backing_reader = backing_reader;
   context->buffer = buffer;
   context->length = length;
   context->start = CLIAUTH_LITERAL_UINT32(0u);
   context->capacity = length;

   return;
}

void
cliauth_io_buffered_writer_initialize(
   struct CliAuthIoBufferedWriter * context,
   const struct CliAuthIoWriter * backing_writer,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 length
) {
   context->backing_writer = backing_writer;
   context->buffer = buffer;
   context->length = length;
   context->start = CLIAUTH_LITERAL_UINT32(0u);
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

