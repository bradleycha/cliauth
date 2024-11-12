/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io.h - Generic I/O interface header.                                   */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_H
#define _CLIAUTH_IO_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "endian.h"

/*----------------------------------------------------------------------------*/
/* A generic I/O read result status.                                          */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_READ_STATUS_SUCCESS - The reader function executed              */
/*                                  successfully.                             */
/*                                                                            */
/* CLIAUTH_IO_READ_STATUS_END_OF_STREAM - The end of the reader stream was    */
/*                                        reached.                            */
/*                                                                            */
/* CLIAUTH_IO_READ_STATUS_ERROR_UNKNOWN - An uncategorized, usually platform  */
/*                                        or implementation specific error.   */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_READ_STATUS_FIELD_COUNT 3u
enum CliAuthIoReadStatus {
   CLIAUTH_IO_READ_STATUS_SUCCESS,
   CLIAUTH_IO_READ_STATUS_END_OF_STREAM,
   CLIAUTH_IO_READ_STATUS_ERROR_UNKNOWN
};

/*----------------------------------------------------------------------------*/
/* The result of a generic I/O read operation.                                */
/*----------------------------------------------------------------------------*/
/* status - The status of the read operation.                                 */
/*                                                                            */
/* bytes - The number of bytes which were successfully read.                  */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult {
   enum CliAuthIoReadStatus status;
   CliAuthUInt32 bytes;
};

/*----------------------------------------------------------------------------*/
/* A generic I/O write result status.                                         */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_WRITE_STATUS_SUCCESS - The writer function executed             */
/*                                   successfully.                            */
/*                                                                            */
/* CLIAUTH_IO_WRITE_STATUS_END_OF_STREAM - The end of the writer stream was   */
/*                                         reached.                           */
/*                                                                            */
/* CLIAUTH_IO_WRITE_STATUS_ERROR_UNKNOWN - An uncategorized, usually platform */
/*                                         or implementation specific error.  */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_WRITE_STATUS_FIELD_COUNT 3u
enum CliAuthIoWriteStatus {
   CLIAUTH_IO_WRITE_STATUS_SUCCESS,
   CLIAUTH_IO_WRITE_STATUS_END_OF_STREAM,
   CLIAUTH_IO_WRITE_STATUS_ERROR_UNKNOWN
};

/*----------------------------------------------------------------------------*/
/* The result of a generic I/O write operation.                               */
/*----------------------------------------------------------------------------*/
/* status - The status of the write operation.                                */
/*                                                                            */
/* bytes - The number of bytes which were successfully written.               */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult {
   enum CliAuthIoWriteStatus status;
   CliAuthUInt32 bytes;
};

/*----------------------------------------------------------------------------*/
/* A function which implements the reader interface for a uni-directional.    */
/* stream.  For more information, see the documentation for                   */
/* cliauth_io_stream_reader_read().                                           */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoReadResult (*CliAuthIoStreamReaderFunction)(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A function which implements the writer interface for a uni-directional.    */
/* stream.  For more information, see the documentation for                   */
/* cliauth_io_stream_writer_write().                                          */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoWriteResult (*CliAuthIoStreamWriterFunction)(
   void * context,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A generic uni-directional stream reader interface.                         */
/*----------------------------------------------------------------------------*/
/* reader - The reader function for the instance's implementation.            */
/*                                                                            */
/* context - A pointer to an implementation-specific context struct.          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamReader {
   CliAuthIoStreamReaderFunction reader;
   void * context;
};

/*----------------------------------------------------------------------------*/
/* Attempts to read bytes into a buffer from a stream reader.                 */
/*----------------------------------------------------------------------------*/
/* reader - The stream reader interface to read from.                         */
/*                                                                            */
/* buffer - A byte buffer to store the read contents to.  The buffer will     */
/*          only be valid up to the number of bytes successfully read in the  */
/*          returned read result.                                             */
/*                                                                            */
/* bytes - The number of bytes to attempt to read.  The actual number of      */
/*         bytes read is output in the 'bytes' result field.                  */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of reading.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_io_stream_reader_read(
   const struct CliAuthIoStreamReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to read and completely fill a buffer from a stream reader.        */
/*----------------------------------------------------------------------------*/
/* reader - The stream reader interface to read from.                         */
/*                                                                            */
/* buffer - A byte buffer to store the read contents to.  The buffer will     */
/*          only be valid up to the number of bytes successfully read in the  */
/*          returned read result.                                             */
/*                                                                            */
/* bytes - The length of 'buffer' in bytes.                                   */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of reading.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_io_stream_reader_read_all(
   const struct CliAuthIoStreamReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A generic uni-directional stream writer interface.                         */
/*----------------------------------------------------------------------------*/
/* writer - The writer function for the instance's implementation.            */
/*                                                                            */
/* context - A pointer to the implementation-specific context struct.         */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamWriter {
   CliAuthIoStreamWriterFunction writer;
   void * context;
};

/*----------------------------------------------------------------------------*/
/* Attempts to write bytes into a buffer info a stream writer.                */
/*----------------------------------------------------------------------------*/
/* writer - The stream writer interface to write bytes into.                  */
/*                                                                            */
/* data - The bytes to write.  The number of bytes which are successfully     */
/*        written will be contained in the returned write result.             */
/*                                                                            */
/* bytes - The number of bytes to attempt to write.  The actual number of     */
/*         bytes written is output in the 'bytes' result field.               */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of writing.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_stream_writer_write(
   const struct CliAuthIoStreamWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to completely write a buffer into a stream writer.                */
/*----------------------------------------------------------------------------*/
/* writer - The stream writer interface to write bytes into.                  */
/*                                                                            */
/* data - The bytes to write.  The number of bytes which are successfully     */
/*        written will be contained in the returned write result.             */
/*                                                                            */
/* bytes - The length of 'data' in bytes.                                     */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of writing.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_stream_writer_write_all(
   const struct CliAuthIoStreamWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A stream reader implementation over a constant byte buffer.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteStreamReader {
   /* the backing byte array */
   const CliAuthUInt8 * bytes;

   /* the length of the byte array in bytes */
   CliAuthUInt32 length;

   /* the position for the next read operation */
   CliAuthUInt32 position;
};

/*----------------------------------------------------------------------------*/
/* A stream writer implementation over a mutable byte buffer.                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteStreamWriter {
   /* the backing byte array */
   CliAuthUInt8 * bytes;

   /* the length of the byte array in bytes */
   CliAuthUInt32 length;

   /* the position for the next write operation */
   CliAuthUInt32 position;
};

/*----------------------------------------------------------------------------*/
/* Initializes the byte stream reader.                                        */
/*----------------------------------------------------------------------------*/
/* context - The byte stream reader to initialize.                            */
/*                                                                            */
/* bytes - The backing byte array for the reader.                             */
/*                                                                            */
/* length - The length of 'bytes' in bytes.                                   */
/*----------------------------------------------------------------------------*/
void
cliauth_io_byte_stream_reader_initialize(
   struct CliAuthIoByteStreamReader * context,
   const CliAuthUInt8 bytes [],
   CliAuthUInt32 length
);

/*----------------------------------------------------------------------------*/
/* Initializes the byte stream writer.                                        */
/*----------------------------------------------------------------------------*/
/* context - The byte stream writer to initialize.                            */
/*                                                                            */
/* bytes - The backing byte array for the writer.                             */
/*                                                                            */
/* length - The length of 'bytes' in bytes.                                   */
/*----------------------------------------------------------------------------*/
void
cliauth_io_byte_stream_writer_initialize(
   struct CliAuthIoByteStreamWriter * context,
   CliAuthUInt8 bytes [],
   CliAuthUInt32 length
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream reader interface from the byte stream reader.     */
/*----------------------------------------------------------------------------*/
/* context - The byte stream reader to create a stream reader from.  The      */
/*           lifetime of the reader interface is the same as the byte stream  */
/*           reader.                                                          */
/*----------------------------------------------------------------------------*/
/* Return value - A generic stream reader interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamReader
cliauth_io_byte_stream_reader_interface(
   struct CliAuthIoByteStreamReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream writer interface from the byte stream writer.     */
/*----------------------------------------------------------------------------*/
/* context - The byte stream writer to create a stream writer from.  The      */
/*           lifetime of the writer interface is the same as the byte stream  */
/*           writer.                                                          */
/*----------------------------------------------------------------------------*/
/* Return value - A generic stream writer interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamWriter
cliauth_io_byte_stream_writer_interface(
   struct CliAuthIoByteStreamWriter * context
);

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
/* context - The buffered stream reader to initialize.                        */
/*                                                                            */
/* backing_reader - The backing stream reader interface to buffer.            */
/*                                                                            */
/* buffer - A byte array which will store the buffered reads.                 */
/*                                                                            */
/* length - The length of 'buffer' in bytes.                                  */
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
/* context - The buffered stream writer to initialize.                        */
/*                                                                            */
/* backing_writer - The backing stream writer interface to buffer.            */
/*                                                                            */
/* buffer - A byte array which will store the buffered writes.                */
/*                                                                            */
/* length - The length of 'buffer' in bytes.                                  */
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
/* context - The buffered stream reader to create a stream reader from.  The  */
/*           lifetime of the reader interface is the same as the buffered     */
/*           stream reader.                                                   */
/*----------------------------------------------------------------------------*/
/* Return value - A generic stream reader interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamReader
cliauth_io_buffered_stream_reader_interface(
   struct CliAuthIoBufferedStreamReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream writer interface from the buffered stream writer. */
/*----------------------------------------------------------------------------*/
/* context - The buffered stream writer to create a stream writer from.  The  */
/*           lifetime of the stream lwriter interface is the same as the      */
/*           buffered stream writer.                                          */
/*----------------------------------------------------------------------------*/
/* Return value - A generic stream writer interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamWriter
cliauth_io_buffered_stream_writer_interface(
   struct CliAuthIoBufferedStreamWriter * context
);

/*----------------------------------------------------------------------------*/
/* Flushes any buffered bytes to the stream writer, emptying the write        */
/* buffer.                                                                    */
/*----------------------------------------------------------------------------*/
/* context - The buffered stream writer to flush.                             */
/*----------------------------------------------------------------------------*/
/* Return value - The result of flushing the stream write buffer.             */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_buffered_stream_writer_flush(
   struct CliAuthIoBufferedStreamWriter * context
);

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_IO_BUFFERING */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_H */

