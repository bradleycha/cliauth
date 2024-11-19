/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/io.h - Generic I/O interfaces.                                      */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_H
#define _CLIAUTH_IO_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "endian.h"

/*----------------------------------------------------------------------------*/
/* A generic I/O result status.                                               */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_IO_STATUS_SUCCESS -                                                */
/*    The I/O function executed successfully.                                 */
/*                                                                            */
/* CLIAUTH_IO_STATUS_END_OF_STREAM -                                          */
/*    The end of the I/O stream was reached.                                  */
/*                                                                            */
/* CLIAUTH_IO_STATUS_ERROR_UNKNOWN -                                          */
/*    An unknown I/O error occurred.                                          */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_IO_STATUS_FIELD_COUNT 3u
enum CliAuthIoStatus {
   CLIAUTH_IO_STATUS_SUCCESS,
   CLIAUTH_IO_STATUS_END_OF_STREAM,
   CLIAUTH_IO_STATUS_ERROR_UNKNOWN
};

/*----------------------------------------------------------------------------*/
/* The result of a generic I/O operation.                                     */
/*----------------------------------------------------------------------------*/
/* status -                                                                   */
/*    The status of the I/O operation.                                        */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes which were successfully read.                       */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult {
   enum CliAuthIoStatus status;
   CliAuthUInt32 bytes;
};

/*----------------------------------------------------------------------------*/
/* A function which implements the reader interface for a uni-directional     */
/* stream.  For more information, see the documentation for                   */
/* cliauth_io_stream_reader_read().                                           */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoResult (*CliAuthIoStreamFunctionRead)(
   void * context,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* A function which implements the writer interface for a uni-directional.    */
/* stream.  For more information, see the documentation for                   */
/* cliauth_io_stream_writer_write().                                          */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoResult (*CliAuthIoStreamFunctionWrite)(
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
/* reader -                                                                   */
/*    The stream reader interface to read from.                               */
/*                                                                            */
/* buffer -                                                                   */
/*    A byte buffer to store the read contents to.  The buffer will only be   */
/*    valid up to the number of bytes successfully read in the returned read  */
/*    result.                                                                 */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to attempt to read.  The actual number of bytes     */
/*    read is output in the 'bytes' result field.                             */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of reading.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_stream_reader_read(
   const struct CliAuthIoStreamReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to read and completely fill a buffer from a stream reader.        */
/*----------------------------------------------------------------------------*/
/* reader -                                                                   */
/*    The stream reader interface to read from.                               */
/*                                                                            */
/* buffer -                                                                   */
/*    A byte buffer to store the read contents to.  The buffer will only be   */
/*    valid up to the number of bytes successfully read in the returned read  */
/*    result.                                                                 */
/*                                                                            */
/* bytes -                                                                    */
/*    The length of 'buffer' in bytes.                                        */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of reading.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
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
/* writer -                                                                   */
/*    The stream writer interface to write bytes into.                        */
/*                                                                            */
/* data -                                                                     */
/*    The bytes to write.  The number of bytes which are successfully written */
/*    will be contained in the returned write result.                         */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to attempt to write.  The actual number of bytes    */
/*    written is output in the 'bytes' result field.                          */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of writing.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_stream_writer_write(
   const struct CliAuthIoStreamWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Attempts to completely write a buffer into a stream writer.                */
/*----------------------------------------------------------------------------*/
/* writer -                                                                   */
/*    The stream writer interface to write bytes into.                        */
/*                                                                            */
/* data -                                                                     */
/*    The bytes to write.  The number of bytes which are successfully written */
/*    will be contained in the returned write result.                         */
/*                                                                            */
/* bytes -                                                                    */
/*    The length of 'data' in bytes.                                          */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of writing.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
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
typedef struct CliAuthIoResult (*CliAuthIoMapperFunctionRead)(
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
typedef struct CliAuthIoResult (*CliAuthIoMapperFunctionWrite)(
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
/* reader -                                                                   */
/*    The mapper reader interface to read from.                               */
/*                                                                            */
/* buffer -                                                                   */
/*    A byte buffer to store the read contents to.  The buffer will only be   */
/*    valid up to the number of bytes successfully read in the returned read  */
/*    result.                                                                 */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to attempt to read.  The actual number of bytes     */
/*    read is output in the 'bytes' result field.  It is undefined behavior   */
/*    to have a byte read count such that reading will take place past the    */
/*    allocated region for the mapper.                                        */
/*                                                                            */
/* offset -                                                                   */
/*    The position in the mapper to attempt to read bytes into.  It is        */
/*    undefined behavior to have an offset such that reading will take place  */
/*    past the allocated region for the mapper.                               */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of reading.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_mapper_reader_read(
   const struct CliAuthIoMapperReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* Attempts to read and completely fill a buffer from a mapper reader.        */
/*----------------------------------------------------------------------------*/
/* reader -                                                                   */
/*    The mapper reader interface to read from.                               */
/*                                                                            */
/* buffer -                                                                   */
/*    A byte buffer to store the read contents to.  The buffer will only be   */
/*    valid up to the number of bytes successfully read in the returned read  */
/*    result.                                                                 */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to attempt to read.  The actual number of bytes     */
/*    read is output in the 'bytes' result field.  It is undefined behavior   */
/*    to have a byte read count such that reading will take place past the    */
/*    allocated region for the mapper.                                        */
/*                                                                            */
/* offset -                                                                   */
/*    The position in the mapper to attempt to read bytes into.  It is        */
/*    undefined behavior to have an offset such that reading will take place  */
/*    past the allocated region for the mapper.                               */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of reading.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_mapper_reader_read_all(
   const struct CliAuthIoMapperReader * reader,
   CliAuthUInt8 buffer [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* A generic random-access mapper writer interface.                           */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperWriter {
   CliAuthIoMapperFunctionWrite write;
   void * context;
};

/*----------------------------------------------------------------------------*/
/* Attempts to write bytes into a buffer info a mapper writer.                */
/*----------------------------------------------------------------------------*/
/* writer -                                                                   */
/*    The mapper writer interface to write bytes into.                        */
/*                                                                            */
/* data -                                                                     */
/*    The bytes to write.  The number of bytes which are successfully written */
/*    will be contained in the returned write result.                         */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to attempt to write.  The actual number of bytes    */
/*    written is output in the 'bytes' result field.  It is undefined         */
/*    behavior to have a byte write count such that writing will take place   */
/*    past the allocated region for the mapper.                               */
/*                                                                            */
/* offset -                                                                   */
/*    The position in the mapper to attempt to write bytes into.  It is       */
/*    undefined behavior to have an offset such that writing will take place  */
/*    past the allocated region for the mapper.                               */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of writing.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_mapper_writer_write(
   const struct CliAuthIoMapperWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
/* Attempts to completely write a buffer into a mapper writer.                */
/*----------------------------------------------------------------------------*/
/* writer -                                                                   */
/*    The mapper writer interface to write bytes into.                        */
/*                                                                            */
/* data -                                                                     */
/*    The bytes to write.  The number of bytes which are successfully written */
/*    will be contained in the returned write result.                         */
/*                                                                            */
/* bytes -                                                                    */
/*    The number of bytes to attempt to write.  The actual number of bytes    */
/*    written is output in the 'bytes' result field.  It is undefined         */
/*    behavior to have a byte write count such that writing will take place   */
/*    past the allocated region for the mapper.                               */
/*                                                                            */
/* offset -                                                                   */
/*    The position in the mapper to attempt to write bytes into.  It is       */
/*    undefined behavior to have an offset such that writing will take place  */
/*    past the allocated region for the mapper.                               */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A struct representing the result of writing.                            */
/*----------------------------------------------------------------------------*/
struct CliAuthIoResult
cliauth_io_mapper_writer_write_all(
   const struct CliAuthIoMapperWriter * writer,
   const CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   CliAuthUInt32 offset
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_H */

