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
/* A function which implements the reader interface for a uni-directional     */
/* stream.  For more information, see the documentation for                   */
/* cliauth_io_stream_reader_read().                                           */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoReadResult (*CliAuthIoStreamFunctionRead)(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A function which implements the writer interface for a uni-directional.    */
/* stream.  For more information, see the documentation for                   */
/* cliauth_io_stream_writer_write().                                          */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoWriteResult (*CliAuthIoStreamFunctionWrite)(
   void * context,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A generic uni-directional stream reader interface.                         */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamReader {
   CliAuthIoStreamFunctionRead read;
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
struct CliAuthIoStreamWriter {
   CliAuthIoStreamFunctionWrite write;
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
/* A function which implements the reader interface for a random-access       */
/* mapper.  For more information, see the documentation for                   */
/* cliauth_io_mapper_reader_read().                                           */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoReadResult (*CliAuthIoMapperFunctionRead)(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* A function which implements the writer interface for a random-access       */
/* mapper.  For more information, see the documentation for                   */
/* cliauth_io_mapper_writer_write().                                          */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoWriteResult (*CliAuthIoMapperFunctionWrite)(
   void * context,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* A generic random-access mapper reader interface.                           */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperReader {
   CliAuthIoMapperFunctionRead read;
   void * context;
};

/*----------------------------------------------------------------------------*/
/* Attempts to read bytes into a buffer from a mapper reader.                 */
/*----------------------------------------------------------------------------*/
/* reader - The mapper reader interface to read from.                         */
/*                                                                            */
/* buffer - A byte buffer to store the read contents to.  The buffer will     */
/*          only be valid up to the number of bytes successfully read in the  */
/*          returned read result.                                             */
/*                                                                            */
/* bytes - The number of bytes to attempt to read.  The actual number of      */
/*         bytes read is output in the 'bytes' result field.  It is undefined */
/*         behavior to have a byte read count such that reading will take     */
/*         place past the allocated region for the mapper.                    */
/*                                                                            */
/* offset - The position in the mapper to attempt to read bytes into.         */
/*          It is undefined behavior to have an offset such that reading will */
/*          take place past the allocated region for the mapper.              */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of reading.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_io_mapper_reader_read(
   const struct CliAuthIoMapperReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* Attempts to read and completely fill a buffer from a mapper reader.        */
/*----------------------------------------------------------------------------*/
/* reader - The mapper reader interface to read from.                         */
/*                                                                            */
/* buffer - A byte buffer to store the read contents to.  The buffer will     */
/*          only be valid up to the number of bytes successfully read in the  */
/*          returned read result.                                             */
/*                                                                            */
/* bytes - The number of bytes to attempt to read.  The actual number of      */
/*         bytes read is output in the 'bytes' result field.  It is undefined */
/*         behavior to have a byte read count such that reading will take     */
/*         place past the allocated region for the mapper.                    */
/*                                                                            */
/* offset - The position in the mapper to attempt to read bytes into.         */
/*          It is undefined behavior to have an offset such that reading will */
/*          take place past the allocated region for the mapper.              */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of reading.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_io_mapper_reader_read_all(
   const struct CliAuthIoMapperReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* A generic random-access mapper writer interface.                           */
/*----------------------------------------------------------------------------*/
/* writer - The writer function for the instance's implementation.            */
/*                                                                            */
/* context - A pointer to the implementation-specific context struct.         */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperWriter {
   CliAuthIoMapperFunctionWrite write;
   void * context;
};

/*----------------------------------------------------------------------------*/
/* Attempts to write bytes into a buffer info a mapper writer.                */
/*----------------------------------------------------------------------------*/
/* writer - The mapper writer interface to write bytes into.                  */
/*                                                                            */
/* data - The bytes to write.  The number of bytes which are successfully     */
/*        written will be contained in the returned write result.             */
/*                                                                            */
/* bytes - The number of bytes to attempt to write.  The actual number of     */
/*         bytes written is output in the 'bytes' result field.  It is        */
/*         undefined behavior to have a byte write count such that writing    */
/*         will take place past the allocated region for the mapper.          */
/*                                                                            */
/* offset - The position in the mapper to attempt to write bytes into.        */
/*          It is undefined behavior to have an offset such that writing will */
/*          take place past the allocated region for the mapper.              */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of writing.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_mapper_writer_write(
   const struct CliAuthIoMapperWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* Attempts to completely write a buffer into a mapper writer.                */
/*----------------------------------------------------------------------------*/
/* writer - The mapper writer interface to write bytes into.                  */
/*                                                                            */
/* data - The bytes to write.  The number of bytes which are successfully     */
/*        written will be contained in the returned write result.             */
/*                                                                            */
/* bytes - The number of bytes to attempt to write.  The actual number of     */
/*         bytes written is output in the 'bytes' result field.  It is        */
/*         undefined behavior to have a byte write count such that writing    */
/*         will take place past the allocated region for the mapper.          */
/*                                                                            */
/* offset - The position in the mapper to attempt to write bytes into.        */
/*          It is undefined behavior to have an offset such that writing will */
/*          take place past the allocated region for the mapper.              */
/*----------------------------------------------------------------------------*/
/* Return value - A struct representing the result of writing.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoWriteResult
cliauth_io_mapper_writer_write_all(
   const struct CliAuthIoMapperWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* A mapper reader implementation over a constant byte buffer.                */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteArrayMapperReader {
   const CliAuthUInt8 * data;
};

/*----------------------------------------------------------------------------*/
/* A mapper writer implementation over a mutable byte buffer.                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteArrayMapperWriter {
   CliAuthUInt8 * data;
};

/*----------------------------------------------------------------------------*/
/* Initializes the byte array mapper reader.                                  */
/*----------------------------------------------------------------------------*/
/* context - The byte array mapper reader to initialize.                      */
/*                                                                            */
/* bytes - The backing byte array for the reader.  The length of the          */
/*         allocated region for the reader will be the length of the backing  */
/*         byte array.                                                        */
/*----------------------------------------------------------------------------*/
void
cliauth_io_byte_array_mapper_reader_initialize(
   struct CliAuthIoByteArrayMapperReader * context,
   const CliAuthUInt8 bytes []
);

/*----------------------------------------------------------------------------*/
/* Initializes the byte array mapper writer.                                  */
/*----------------------------------------------------------------------------*/
/* context - The byte array mapper writer to initialize.                      */
/*                                                                            */
/* bytes - The backing byte array for the writer.  The length of the          */
/*         allocated region for the writer will be the length of the backing  */
/*         byte array.                                                        */
/*----------------------------------------------------------------------------*/
void
cliauth_io_byte_array_mapper_writer_initialize(
   struct CliAuthIoByteArrayMapperWriter * context,
   CliAuthUInt8 bytes []
);

/*----------------------------------------------------------------------------*/
/* Creates a generic mapper reader interface from the byte array mapper       */
/* reader.                                                                    */
/*----------------------------------------------------------------------------*/
/* context - The byte array mapper reader to create a mapper reader from.     */
/*           The lifetime of the reader interface is the same as the byte     */
/*           array mapper reader.                                             */
/*----------------------------------------------------------------------------*/
/* Return value - A generic mapper reader interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperReader
cliauth_io_byte_array_mapper_reader_interface(
   struct CliAuthIoByteArrayMapperReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic mapper writer interface from the byte array mapper       */
/* writer.                                                                    */
/*----------------------------------------------------------------------------*/
/* context - The byte array mapper writer to create a mapper writer from.     */
/*           The lifetime of the writer interface is the same as the byte     */
/*           array mapper writer.                                             */
/*----------------------------------------------------------------------------*/
/* Return value - A generic mapper writer interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperWriter
cliauth_io_byte_array_mapper_writer_interface(
   struct CliAuthIoByteArrayMapperWriter * context
);

/*----------------------------------------------------------------------------*/
/* Creates a uni-directional stream reader from a random-access mapper        */
/* reader.                                                                    */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperStreamReader {
   /* the backing mapper reader */
   const struct CliAuthIoMapperReader * backing_mapper_reader;

   /* the length of the backing mapper reader's allocation unit */
   CliAuthUInt32 length;

   /* the current position within the backing mapper reader */
   CliAuthUInt32 position;
};

/*----------------------------------------------------------------------------*/
/* Creates a uni-directional stream writer from a random-access mapper        */
/* writer.                                                                    */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperStreamWriter {
   /* the backing mapper writer */
   const struct CliAuthIoMapperWriter * backing_mapper_writer;

   /* the length of the backing mapper writer's allocation unit */
   CliAuthUInt32 length;

   /* the current position within the backing mapper writer */
   CliAuthUInt32 position;
};

/*----------------------------------------------------------------------------*/
/* Initializes the mapper stream reader.                                      */
/*----------------------------------------------------------------------------*/
/* context - The mapper stream reader to initialize.                          */
/*                                                                            */
/* backing_mapper_reader - The backing mapper reader to create a stream from. */
/*                                                                            */
/* length - The length of the backing mapper reader's allocated region in     */
/*          bytes.                                                            */
/*                                                                            */
/* offset - The offset within the backing mapper reader to position the start */
/*          of the stream at.  It is undefined behavior to specify a starting */
/*          offset past the allocated region for the backing mapper reader.   */
/*----------------------------------------------------------------------------*/
void
cliauth_io_mapper_stream_reader_initialize(
   struct CliAuthIoMapperStreamReader * context,
   const struct CliAuthIoMapperReader * backing_mapper_reader,
   CliAuthUInt32 length,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* Initializes the mapper stream writer.                                      */
/*----------------------------------------------------------------------------*/
/* context - The mapper stream writer to initialize.                          */
/*                                                                            */
/* backing_mapper_writer - The backing writer reader to create a stream from. */
/*                                                                            */
/* length - The length of the backing mapper writer's allocated region in     */
/*          bytes.                                                            */
/*                                                                            */
/* offset - The offset within the backing mapper writer to position the start */
/*          of the stream at.  It is undefined behavior to specify a starting */
/*          offset past the allocated region for the backing mapper writer.   */
/*----------------------------------------------------------------------------*/
void
cliauth_io_mapper_stream_writer_initialize(
   struct CliAuthIoMapperStreamWriter * context,
   const struct CliAuthIoMapperWriter * backing_mapper_writer,
   CliAuthUInt32 length,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream reader interface from the mapper stream reader.   */
/*----------------------------------------------------------------------------*/
/* context - The mapper stream reader to create a stream reader from.  The    */
/*           lifetime of the stream reader interface is the same as the       */
/*           mapper stream reader.                                            */
/*----------------------------------------------------------------------------*/
/* Return value - A generic stream reader interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamReader
cliauth_io_mapper_stream_reader_interface(
   struct CliAuthIoMapperStreamReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream writer interface from the mapper stream writer.   */
/*----------------------------------------------------------------------------*/
/* context - The mapper stream writer to create a stream writer from.  The    */
/*           lifetime of the stream writer interface is the same as the       */
/*           mapper stream writer.                                            */
/*----------------------------------------------------------------------------*/
/* Return value - A generic stream writer interface.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamWriter
cliauth_io_mapper_stream_writer_interface(
   struct CliAuthIoMapperStreamWriter * context
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
/*           lifetime of the stream writer interface is the same as the       */
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

