/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/byte_array_mapper.h - Byte array I/O mapper layer.                  */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IO_BYTE_ARRAY_MAPPER_H
#define _CLIAUTH_IO_BYTE_ARRAY_MAPPER_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "io/io.h"

/*----------------------------------------------------------------------------*/
/* A mapper reader implementation over a constant byte buffer.  Reads will    */
/* always return 'CLIAUTH_IO_STATUS_SUCCESS'.                                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteArrayMapperReader {
   const CliAuthUInt8 * data;
};

/*----------------------------------------------------------------------------*/
/* A mapper writer implementation over a mutable byte buffer.  Writes will    */
/* always return 'CLIAUTH_IO_STATUS_SUCCESS'.                                 */
/*----------------------------------------------------------------------------*/
struct CliAuthIoByteArrayMapperWriter {
   CliAuthUInt8 * data;
};

/*----------------------------------------------------------------------------*/
/* Initializes the byte array mapper reader.                                  */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The byte array mapper reader to initialize.                             */
/*                                                                            */
/* bytes -                                                                    */
/*    The backing byte array for the reader.  The length of the allocated     */
/*    region for the reader will be the length of the backing byte array.     */
/*----------------------------------------------------------------------------*/
void
cliauth_io_byte_array_mapper_reader_initialize(
   struct CliAuthIoByteArrayMapperReader * context,
   const CliAuthUInt8 bytes []
);

/*----------------------------------------------------------------------------*/
/* Initializes the byte array mapper writer.                                  */
/*----------------------------------------------------------------------------*/
/* context -                                                                  */
/*    The byte array mapper writer to initialize.                             */
/*                                                                            */
/* bytes -                                                                    */
/*    The backing byte array for the writer.  The length of the allocated     */
/*    region for the writer will be the length of the backing byte array.     */
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
/* context -                                                                  */
/*    The byte array mapper reader to create a mapper reader from.  The       */
/*    lifetime of the reader interface is the same as the byte array mapper   */
/*    reader.                                                                 */
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
/* context -                                                                  */
/*    The byte array mapper writer to create a mapper writer from.  The       */
/*    lifetime of the writer interface is the same as the byte array mapper   */
/*    writer.                                                                 */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    A generic mapper writer interface.                                      */
/*----------------------------------------------------------------------------*/
struct CliAuthIoMapperWriter
cliauth_io_byte_array_mapper_writer_interface(
   struct CliAuthIoByteArrayMapperWriter * context
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IO_BYTE_ARRAY_MAPPER_H */

