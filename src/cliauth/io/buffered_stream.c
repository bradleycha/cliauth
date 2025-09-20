/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/buffered_stream.c - Buffered I/O stream layer implementations.      */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/io/buffered_stream.h"

#include "cliauth/io/io.h"
#include "cliauth/memory/memory.h"

#if CLIAUTH_CONFIG_IO_BUFFERING
/*----------------------------------------------------------------------------*/

static struct CliAuthIoResult
cliauth_io_buffered_stream_reader_read(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoResult result;
   struct CliAuthIoBufferedStreamReader * context_reader;
   CliAuthUInt8 * read_buffer_start;
   CliAuthUInt32 read_total;
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt32 buffer_bytes;
   CliAuthUInt32 residual_bytes;

   context_reader = (struct CliAuthIoBufferedStreamReader *)context;

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

      result.status = CLIAUTH_IO_STATUS_SUCCESS;
      result.bytes = bytes;
      return result;
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
   result = cliauth_io_stream_reader_read(
      context_reader->backing_reader,
      buffer_iter,
      residual_bytes
   );
   read_total += result.bytes;

   if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
      result.bytes = read_total;
      return result;
   }

   /* buffer in a new block into the read buffer, ignoring errors and simply */
   /* accepting whatever number of bytes we were given */
   result = cliauth_io_stream_reader_read(
      context_reader->backing_reader,
      context_reader->buffer,
      context_reader->length
   );
   context_reader->capacity -= result.bytes;
   
   /* lastly update to return the total bytes read, not including the new */
   /* read buffer block */
   result.status = CLIAUTH_IO_STATUS_SUCCESS;
   result.bytes = read_total;
   return result;
}

static struct CliAuthIoResult
cliauth_io_buffered_stream_writer_write(
   void * context,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
) {
   struct CliAuthIoResult result;
   struct CliAuthIoBufferedStreamWriter * context_writer;
   CliAuthUInt8 * buffer_free;
   CliAuthUInt32 write_total;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 fill_bytes;
   CliAuthUInt32 residual_bytes;
   CliAuthUInt32 block_bytes;

   context_writer = (struct CliAuthIoBufferedStreamWriter *)context;

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

      result.status = CLIAUTH_IO_STATUS_SUCCESS;
      result.bytes = bytes;
      return result;
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
   result = cliauth_io_buffered_stream_writer_flush(context_writer);
   write_total += result.bytes;
   data_iter += result.bytes;

   if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
      result.bytes = write_total;
      return result;
   }

   /* attempt to write out all the full-sized blocks at once */
   result = cliauth_io_stream_writer_write(
      context_writer->backing_writer,
      data_iter,
      block_bytes
   );
   write_total += result.bytes;
   data_iter += result.bytes;

   if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
      result.bytes = write_total;
      return result;
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
   result.bytes = write_total;
   return result;
}

void
cliauth_io_buffered_stream_reader_initialize(
   struct CliAuthIoBufferedStreamReader * context,
   const struct CliAuthIoStreamReader * backing_reader,
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
cliauth_io_buffered_stream_writer_initialize(
   struct CliAuthIoBufferedStreamWriter * context,
   const struct CliAuthIoStreamWriter * backing_writer,
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

struct CliAuthIoStreamReader
cliauth_io_buffered_stream_reader_interface(
   struct CliAuthIoBufferedStreamReader * context
) {
   struct CliAuthIoStreamReader retn;

   retn.read = cliauth_io_buffered_stream_reader_read;
   retn.context = context;

   return retn;
}

struct CliAuthIoStreamWriter
cliauth_io_buffered_stream_writer_interface(
   struct CliAuthIoBufferedStreamWriter * context
) {
   struct CliAuthIoStreamWriter retn;

   retn.write = cliauth_io_buffered_stream_writer_write;
   retn.context = context;

   return retn;
}

static struct CliAuthIoResult
cliauth_io_buffered_stream_writer_flush_unified(
   struct CliAuthIoBufferedStreamWriter * context
) {
   struct CliAuthIoResult result;
   CliAuthUInt8 * data_ptr;
   CliAuthUInt32 data_bytes;

   /* calculate the buffer slice to flush */
   data_ptr    = &context->buffer[context->start];
   data_bytes  = context->length - context->capacity;

   /* attempt to write the buffer slice */
   result = cliauth_io_stream_writer_write(
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

static struct CliAuthIoResult
cliauth_io_buffered_stream_writer_flush_fragmented(
   struct CliAuthIoBufferedStreamWriter * context
) {
   struct CliAuthIoResult result;
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
   result = cliauth_io_stream_writer_write(
      context->backing_writer,
      fill_ptr,
      fill_bytes
   );

   /* remove the successfully written bytes from the buffer */
   context->start = (context->start + result.bytes) % context->length;
   context->capacity = context->capacity + result.bytes;

   /* if the write resulted in an error, pass the result to the caller */
   if (result.status != CLIAUTH_IO_STATUS_SUCCESS) {
      return result;
   }

   /* attempt to write the 'remainder' buffer slice */
   result = cliauth_io_stream_writer_write(
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

struct CliAuthIoResult
cliauth_io_buffered_stream_writer_flush(
   struct CliAuthIoBufferedStreamWriter * context
) {
   struct CliAuthIoResult result;

   /* if the buffer is not fragmented, simply flush the entire buffer */
   /* otherwise we will need to flush each portion seperately */
   if (context->start > context->capacity) {
      result = cliauth_io_buffered_stream_writer_flush_fragmented(context);
   } else {
      result = cliauth_io_buffered_stream_writer_flush_unified(context);
   }

   return result;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_IO_BUFFERING */

