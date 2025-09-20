/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/mapper_stream.h - I/O stream over an I/O mapper.                    */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_MAPPER_STREAM_H
#define _CLIAUTH_IO_MAPPER_STREAM_H
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/io/io.h"

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
/* context -                                                                  */
/*    The mapper stream reader to initialize.                                 */
/*                                                                            */
/* backing_mapper_reader -                                                    */
/*    The backing mapper reader to create a stream from.                      */
/*                                                                            */
/* length -                                                                   */
/*    The length of the backing mapper reader's allocated region in bytes.    */
/*                                                                            */
/* offset -                                                                   */
/*    The offset within the backing mapper reader to position the start of    */
/*    the stream at.  It is undefined behavior to specify a starting offset   */
/*    past the allocated region for the backing mapper reader.                */
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
/* context -                                                                  */
/*    The mapper stream writer to initialize.                                 */
/*                                                                            */
/* backing_mapper_writer -                                                    */
/*    The backing writer reader to create a stream from.                      */
/*                                                                            */
/* length -                                                                   */
/*    The length of the backing mapper writer's allocated region in bytes.    */
/*                                                                            */
/* offset -                                                                   */
/*    The offset within the backing mapper writer to position the start of    */
/*    the stream at.  It is undefined behavior to specify a starting offset   */
/*    past the allocated region for the backing mapper writer.                */
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
/* context -                                                                  */
/*    The mapper stream reader to create a stream reader from.  The lifetime  */
/*    of the stream reader interface is the same as the mapper stream reader. */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A generic stream reader interface.                                      */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamReader
cliauth_io_mapper_stream_reader_interface(
   struct CliAuthIoMapperStreamReader * context
);

/*----------------------------------------------------------------------------*/
/* Creates a generic stream writer interface from the mapper stream writer.   */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The mapper stream writer to create a stream writer from.  The lifetime  */
/*    of the stream writer interface is the same as the mapper stream writer. */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A generic stream writer interface.                                      */
/*----------------------------------------------------------------------------*/
struct CliAuthIoStreamWriter
cliauth_io_mapper_stream_writer_interface(
   struct CliAuthIoMapperStreamWriter * context
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_MAPPER_STREAM_H */

