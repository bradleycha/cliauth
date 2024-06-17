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
/* A function which implements the reader interface.  For more information,   */
/* see the documentation for cliauth_io_reader_read().                        */
/*----------------------------------------------------------------------------*/
typedef enum CliAuthIoReadStatus (*CliAuthIoReaderFunction)(
   void * context,
   CliAuthUInt32 * output_read_bytes,
   void * buffer,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A function which implements the writer interface.  For more information,   */
/* see the documentation for cliauth_io_writer_write().                        */
/*----------------------------------------------------------------------------*/
typedef enum CliAuthIoWriteStatus (*CliAuthIoWriterFunction)(
   void * context,
   CliAuthUInt32 * output_write_bytes,
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
/* output_read_bytes - A pointer to an integer which stores the number of     */
/*                     bytes which were read into the buffer.  The data will  */
/*                     only be valid if the function returns                  */
/*                     'CLIAUTH_IO_READ_ERROR_SUCCESS'.                       */
/*                                                                            */
/* buffer - A byte buffer to store the read contents to.  The contents of     */
/*          this buffer will only be valid for 'output_read_bytes' bytes if   */
/*          if the function returns 'CLIAUTH_IO_READ_ERROR_SUCCESS'.          */
/*                                                                            */
/* bytes - The number of bytes to attempt to read.  The actual number of      */
/*         bytes read is output in 'output_read_bytes'.                       */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the result of reading.                 */
/*----------------------------------------------------------------------------*/
enum CliAuthIoReadStatus
cliauth_io_reader_read(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output_read_bytes,
   void * buffer,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to read and completely fill a buffer from a reader.               */
/*----------------------------------------------------------------------------*/
/* reader - The reader interface to read from.                                */
/*                                                                            */
/* buffer - The buffer to read bytes into.  The data in this buffer will only */
/*          be valid if the function returns 'CLIAUTH_IO_READ_ERROR_SUCCESS'. */
/*                                                                            */
/* bytes - The length of 'buffer' in bytes.                                   */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the result of reading.                 */
/*----------------------------------------------------------------------------*/
enum CliAuthIoReadStatus
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
/*          'CLIAUTH_IO_READ_STATUS_SUCCESS'.                                 */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the result of reading.                 */
/*----------------------------------------------------------------------------*/
enum CliAuthIoReadStatus
cliauth_io_reader_read_uint8(
   const struct CliAuthIoReader * reader,
   CliAuthUInt8 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_sint8(
   const struct CliAuthIoReader * reader,
   CliAuthSInt8 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_little_uint16(
   const struct CliAuthIoReader * reader,
   CliAuthUInt16 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_little_uint32(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_little_uint64(
   const struct CliAuthIoReader * reader,
   CliAuthUInt64 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_little_sint16(
   const struct CliAuthIoReader * reader,
   CliAuthSInt16 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_little_sint32(
   const struct CliAuthIoReader * reader,
   CliAuthSInt32 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_little_sint64(
   const struct CliAuthIoReader * reader,
   CliAuthSInt64 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_big_uint16(
   const struct CliAuthIoReader * reader,
   CliAuthUInt16 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_big_uint32(
   const struct CliAuthIoReader * reader,
   CliAuthUInt32 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_big_uint64(
   const struct CliAuthIoReader * reader,
   CliAuthUInt64 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_big_sint16(
   const struct CliAuthIoReader * reader,
   CliAuthSInt16 * output
);
enum CliAuthIoReadStatus
cliauth_io_reader_read_big_sint32(
   const struct CliAuthIoReader * reader,
   CliAuthSInt32 * output
);
enum CliAuthIoReadStatus
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
/* Attempts to write bytes from a buffer into a writer.                       */
/*----------------------------------------------------------------------------*/
/* writer - The writer interface to write bytes into.                         */
/*                                                                            */
/* output_write_bytes - A pointer to an integer which stores the number of    */
/*                      bytes which were written from the buffer.  The data   */
/*                      will only be valid if the function returns            */
/*                      'CLIAUTH_IO_WRITE_ERROR_SUCCESS'.                     */
/*                                                                            */
/* data - The bytes to write.                                                 */
/*                                                                            */
/* bytes - The number of bytes to attempt to write from 'data'.  The actual   */
/*         number of bytes written is output in 'output_write_bytes'.         */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the result of writing.                 */
/*----------------------------------------------------------------------------*/
enum CliAuthIoWriteStatus
cliauth_io_writer_write(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 * output_write_bytes,
   const void * data,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to completely write a buffer into a writer.                       */
/*----------------------------------------------------------------------------*/
/* writer - The writer interface to write bytes into.                         */
/*                                                                            */
/* data - The bytes to write.                                                 */
/*                                                                            */
/* bytes - The length of 'data' in bytes.                                     */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the result of writing.                 */
/*----------------------------------------------------------------------------*/
enum CliAuthIoWriteStatus
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
/* Return value - An enum representing the result of writing.                 */
/*----------------------------------------------------------------------------*/
enum CliAuthIoWriteStatus
cliauth_io_writer_write_uint8(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt8 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_sint8(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt8 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_little_uint16(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt16 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_little_uint32(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_little_uint64(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt64 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_little_sint16(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt16 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_little_sint32(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt32 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_little_sint64(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt64 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_big_uint16(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt16 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_big_uint32(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt32 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_big_uint64(
   const struct CliAuthIoWriter * writer,
   CliAuthUInt64 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_big_sint16(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt16 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_big_sint32(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt32 value
);
enum CliAuthIoWriteStatus
cliauth_io_writer_write_big_sint64(
   const struct CliAuthIoWriter * writer,
   CliAuthSInt64 value
);

/*----------------------------------------------------------------------------*/
/* A reader implementation over a constant byte buffer.                       */
/*----------------------------------------------------------------------------*/
/* bytes - A pointer to the byte buffer.  All data must be initialized up to  */
/*         index 'length - 1'.                                                */
/*                                                                            */
/* length - The length of 'bytes' in bytes.                                   */
/*                                                                            */
/* position - The current seek position in 'bytes'.                           */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteStreamReader {
   const CliAuthUInt8 * bytes;
   CliAuthUInt32 length;
   CliAuthUInt32 position;
};

/*----------------------------------------------------------------------------*/
/* A writer implementation over a mutable byte buffer.                        */
/*----------------------------------------------------------------------------*/
/* bytes - A pointer to the byte buffer.                                      */
/*                                                                            */
/* length - The length of 'bytes' in bytes.                                   */
/*                                                                            */
/* position - The current seek position in 'bytes'.                           */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteStreamWriter {
   CliAuthUInt8 * bytes;
   CliAuthUInt32 length;
   CliAuthUInt32 position;
};

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

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_H */

