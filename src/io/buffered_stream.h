/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/buffered_stream.h - Buffered I/O stream layer.                      */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_BUFFERED_STREAM_H
#define _CLIAUTH_IO_BUFFERED_STREAM_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io/io.h"

#if CLIAUTH_CONFIG_IO_BUFFERING
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/* A generic buffered stream reader implementation.                           */
/*----------------------------------------------------------------------------*/
struct CliAuthIoBufferedStreamReader {
   /* the backing reader interface */
   const struct CliAuthIoStreamReader * backing_reader;

   /* the buffer to read input blocks into */
   CliAuthUInt8 * buffer;

   /* the length of 'buffer' in bytes */
   CliAuthUInt32 length;
   
   /* the index which represents the start of the buffered bytes */
   CliAuthUInt32 start;

   /* the remaining unused bytes in the buffer */
   CliAuthUInt32 capacity;
};

/*----------------------------------------------------------------------------*/
/* A generic buffered stream writer implementation.                           */
/*----------------------------------------------------------------------------*/
struct CliAuthIoBufferedStreamWriter {
   /* the backing writer interface */
   const struct CliAuthIoStreamWriter * backing_writer;

   /* the buffer to write input blocks into */
   CliAuthUInt8 * buffer;

   /* the length of 'buffer' in bytes */
   CliAuthUInt32 length;
   
   /* the index which represents the start of the buffered bytes */
   CliAuthUInt32 start;

   /* the remaining unused bytes in the buffer */
   CliAuthUInt32 capacity;
};

/*----------------------------------------------------------------------------*/
/* Initializes the buffered stream reader.                                    */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The buffered stream reader to initialize.                               */
/*                                                                            */
/* backing_reader -                                                           */
/*    The backing stream reader interface to buffer.                          */
/*                                                                            */
/* buffer -                                                                   */
/*    A byte array which will store the buffered reads.                       */
/*                                                                            */
/* length -                                                                   */
/*    The length of 'buffer' in bytes.                                        */
/*----------------------------------------------------------------------------*/
void
cliauth_io_buffered_reader_initialize(
   struct CliAuthIoBufferedStreamReader * context,
   const struct CliAuthIoStreamReader * backing_reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 length
);

/*----------------------------------------------------------------------------*/
/* Initializes the buffered stream writer.                                    */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The buffered stream writer to initialize.                               */
/*                                                                            */
/* backing_writer -                                                           */
/*    The backing stream writer interface to buffer.                          */
/*                                                                            */
/* buffer -                                                                   */
/*    A byte array which will store the buffered writes.                      */
/*                                                                            */
/* length -                                                                   */
/*    The length of 'buffer' in bytes.                                        */
/*----------------------------------------------------------------------------*/
void
cliauth_io_buffered_writer_initialize(
   struct CliAuthIoBufferedStreamWriter * context,
   const struct CliAuthIoStreamWriter * backing_writer,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 length
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream reader interface from the buffered stream reader. */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The buffered stream reader to create a stream reader from.  The         */
/*    lifetime of the stream reader interface is the same as the buffered     */
/*    stream reader.                                                          */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A generic stream reader interface.                                      */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamReader
cliauth_io_buffered_stream_reader_interface(
   struct CliAuthIoBufferedStreamReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream writer interface from the buffered stream writer. */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The buffered stream writer to create a stream writer from.  The         */
/*    lifetime of the stream writer interface is the same as the buffered     */
/*    stream writer.                                                          */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A generic stream writer interface.                                      */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamWriter
cliauth_io_buffered_stream_writer_interface(
   struct CliAuthIoBufferedStreamWriter * context
);

/*----------------------------------------------------------------------------*/
/* Flushes any buffered bytes to the stream writer, emptying the write        */
/* buffer.                                                                    */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The buffered stream writer to flush.                                    */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    The result of flushing the stream write buffer.                         */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_buffered_stream_writer_flush(
   struct CliAuthIoBufferedStreamWriter * context
);

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_IO_BUFFERING */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_BUFFERED_STREAM_H */

