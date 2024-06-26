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
/* A function which implements the reader interface.  For more information,   */
/* see the documentation for cliauth_io_reader_read().                        */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoReadResult (*CliAuthIoReaderFunction)(
   void * context,
   void * buffer,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A function which implements the writer interface.  For more information,   */
/* see the documentation for cliauth_io_writer_write().                        */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoWriteResult (*CliAuthIoWriterFunction)(
   void * context,
   const void * data,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A generic reader interface.                                                */
/*----------------------------------------------------------------------------*/
/* reader - The reader function for the instance's implementation.            */
/*                                                                            */
/* context - A pointer to an implementation-specific context struct.          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReader {
   CliAuthIoReaderFunction reader;
   void * context;
};

/*----------------------------------------------------------------------------*/
/* Attempts to read bytes into a buffer from a reader.                        */
/*----------------------------------------------------------------------------*/
/* reader - The reader interface to read from.                                */
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
cliauth_io_reader_read(
   const struct CliAuthIoReader * reader,
   void * buffer,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to read and completely fill a buffer from a reader.               */
/*----------------------------------------------------------------------------*/
/* reader - The reader interface to read from.                                */
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
cliauth_io_reader_read_all(
   const struct CliAuthIoReader * reader,
   void * buffer,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Reads an integer and performs endianess conversion from a reader.          */
/*----------------------------------------------------------------------------*/
/* reader - The reader interface to read from.                                */
/*                                                                            */
/* output - A pointer to an integer which stores the read integer.  The data  */
/*          will only be valid if the function returns                        */
/*          the read result status 'CLIAUTH_IO_READ_STATUS_SUCCESS'.          */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of reading.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_io_reader_read_uint8(
   const struct CliAuthIoReader * reader,
   CliAuthUInt8 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_sint8(
   const struct CliAuthIoReader * reader,
   CliAuthSInt8 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_little_uint16(
   const struct CliAuthIoReader * reader,
   CliAuthUInt16 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_little_uint32(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_little_uint64(
   const struct CliAuthIoReader * reader,
   CliAuthUInt64 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_little_sint16(
   const struct CliAuthIoReader * reader,
   CliAuthSInt16 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_little_sint32(
   const struct CliAuthIoReader * reader,
   CliAuthSInt32 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_little_sint64(
   const struct CliAuthIoReader * reader,
   CliAuthSInt64 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_big_uint16(
   const struct CliAuthIoReader * reader,
   CliAuthUInt16 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_big_uint32(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_big_uint64(
   const struct CliAuthIoReader * reader,
   CliAuthUInt64 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_big_sint16(
   const struct CliAuthIoReader * reader,
   CliAuthSInt16 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_big_sint32(
   const struct CliAuthIoReader * reader,
   CliAuthSInt32 * output
);
struct CliAuthIoReadResult
cliauth_io_reader_read_big_sint64(
   const struct CliAuthIoReader * reader,
   CliAuthSInt64 * output
);

/*----------------------------------------------------------------------------*/
/* A generic writer interface.                                                */
/*----------------------------------------------------------------------------*/
/* writer - The writer function for the instance's implementation.            */
/*                                                                            */
/* context - A pointer to the implementation-specific context struct.         */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriter {
   CliAuthIoWriterFunction writer;
   void * context;
};

/*----------------------------------------------------------------------------*/
/* Attempts to write bytes into a buffer info a writer.                       */
/*----------------------------------------------------------------------------*/
/* writer - The writer interface to write bytes into.                         */
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
cliauth_io_writer_write(
   const struct CliAuthIoWriter * writer,
   const void * data,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to completely write a buffer into a writer.                       */
/*----------------------------------------------------------------------------*/
/* writer - The writer interface to write bytes into.                         */
/*                                                                            */
/* data - The bytes to write.  The number of bytes which are successfully     */
/*        written will be contained in the returned write result.             */
/*                                                                            */
/* bytes - The length of 'data' in bytes.                                     */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of writing.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_writer_write_all(
   const struct CliAuthIoWriter * writer,
   const void * data,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Writes an integer and performs endianess conversion to a writer.           */
/*----------------------------------------------------------------------------*/
/* writer - The writer interface to write to.                                 */
/*                                                                            */
/* value - The integer to write.                                              */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of writing.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_writer_write_uint8(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt8 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_sint8(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt8 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_little_uint16(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt16 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_little_uint32(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_little_uint64(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt64 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_little_sint16(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt16 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_little_sint32(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt32 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_little_sint64(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt64 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_big_uint16(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt16 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_big_uint32(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_big_uint64(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt64 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_big_sint16(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt16 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_big_sint32(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt32 value
);
struct CliAuthIoWriteResult
cliauth_io_writer_write_big_sint64(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt64 value
);

/*----------------------------------------------------------------------------*/
/* A reader implementation over a constant byte buffer.                       */
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
/* A writer implementation over a mutable byte buffer.                        */
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
   const void * bytes,
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
   void * bytes,
   CliAuthUInt32 length
);

/*----------------------------------------------------------------------------*/
/* Creates a generic reader interface from the byte stream reader.            */
/*----------------------------------------------------------------------------*/
/* context - The byte stream reader to create a reader from.  The lifetime    */
/*           of the reader interface is the same as the byte stream reader.   */
/*----------------------------------------------------------------------------*/
/* Return value - A generic reader interface.                                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReader
cliauth_io_byte_stream_reader_interface(
   struct CliAuthIoByteStreamReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic writer interface from the byte stream writer.            */
/*----------------------------------------------------------------------------*/
/* context - The byte stream writer to create a writer from.  The lifetime    */
/*           of the writer interface is the same as the byte stream writer.   */
/*----------------------------------------------------------------------------*/
/* Return value - A generic writer interface.                                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriter
cliauth_io_byte_stream_writer_interface(
   struct CliAuthIoByteStreamWriter * context
);

#if CLIAUTH_CONFIG_IO_BUFFERING
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/* A generic buffered reader implementation.                                  */
/*----------------------------------------------------------------------------*/
struct CliAuthIoBufferedReader {
   /* the backing reader interface */
   const struct CliAuthIoReader * backing_reader;

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
/* A generic buffered writer implementation.                                  */
/*----------------------------------------------------------------------------*/
struct CliAuthIoBufferedWriter {
   /* the backing writer interface */
   const struct CliAuthIoWriter * backing_writer;

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
/* Initializes the buffered reader.                                           */
/*----------------------------------------------------------------------------*/
/* context - The buffered reader to initialize.                               */
/*                                                                            */
/* backing_reader - The backing reader interface to buffer.                   */
/*                                                                            */
/* buffer - A byte array which will store the buffered reads.                 */
/*                                                                            */
/* length - The length of 'buffer' in bytes.                                  */
/*----------------------------------------------------------------------------*/
void
cliauth_io_buffered_reader_initialize(
   struct CliAuthIoBufferedReader * context,
   const struct CliAuthIoReader * backing_reader,
   void * buffer,
   CliAuthUInt32 length
);

/*----------------------------------------------------------------------------*/
/* Initializes the buffered writer.                                           */
/*----------------------------------------------------------------------------*/
/* context - The buffered writer to initialize.                               */
/*                                                                            */
/* backing_writer - The backing writer interface to buffer.                   */
/*                                                                            */
/* buffer - A byte array which will store the buffered writes.                */
/*                                                                            */
/* length - The length of 'buffer' in bytes.                                  */
/*----------------------------------------------------------------------------*/
void
cliauth_io_buffered_writer_initialize(
   struct CliAuthIoBufferedWriter * context,
   const struct CliAuthIoWriter * backing_writer,
   void * buffer,
   CliAuthUInt32 length
);

/*----------------------------------------------------------------------------*/
/* Creates a generic reader interface from the buffered reader.               */
/*----------------------------------------------------------------------------*/
/* context - The buffered reader to create a reader from.  The lifetime of    */
/*           the reader interface is the same as the buffered reader.         */
/*----------------------------------------------------------------------------*/
/* Return value - A generic reader interface.                                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReader
cliauth_io_buffered_reader_interface(
   struct CliAuthIoBufferedReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic writer interface from the buffered writer.               */
/*----------------------------------------------------------------------------*/
/* context - The buffered writer to create a writer from.  The lifetime of    */
/*           the writer interface is the same as the buffered writer.         */
/*----------------------------------------------------------------------------*/
/* Return value - A generic writer interface.                                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriter
cliauth_io_buffered_writer_interface(
   struct CliAuthIoBufferedWriter * context
);

/*----------------------------------------------------------------------------*/
/* Flushes any buffered bytes to the writer, emptying the write buffer.       */
/*----------------------------------------------------------------------------*/
/* context - The buffered writer to flush.                                    */
/*----------------------------------------------------------------------------*/
/* Return value - The result of flushing the write buffer.                    */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_buffered_writer_flush(
   struct CliAuthIoBufferedWriter * context
);

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_IO_BUFFERING */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_H */

