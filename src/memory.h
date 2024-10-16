/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/memory.h - Memory manipulation interfaces.                             */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_MEMORY_H
#define _CLIAUTH_MEMORY_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

/*----------------------------------------------------------------------------*/
/* Copies memory from one location to another.                                */
/*----------------------------------------------------------------------------*/
/* destination - The buffer to have data from 'source' copied into.  This     */
/*               buffer must be long enough to store 'bytes' number of bytes. */
/*                                                                            */
/* source - The data to copy into 'destination'.  This buffer must be long    */
/*          enough to store 'bytes' number of bytes.                          */
/*                                                                            */
/* bytes - The number of bytes to copy.                                       */
/*----------------------------------------------------------------------------*/
void
cliauth_memory_copy(
   void * destination,
   const void * source,
   CliAuthUInt32 bytes
);

/*----------------------------------------------------------------------------*/
/* Fills a buffer with a sentinel value.                                      */
/*----------------------------------------------------------------------------*/
/* buffer - The buffer to fill with the sentinel.  This buffer must be large  */
/*          enough to store 'elements' number of 'bytes_per_element'-length   */
/*          elements.  In other words, the amount of copied data may be       */
/*          calculated with the following formula:                            */
/*                                                                            */
/*          filled bytes = elements * bytes_per_element                       */
/*                                                                            */
/* sentinel - The sentinel data to fill the buffer with.  This buffer must be */
/*            large enough to store 'bytes_per_element' number of bytes.      */
/*                                                                            */
/* elements - The number of 'bytes_per_element'-byte elements to copy.        */
/*                                                                            */
/* bytes_per_element - The number of bytes per element.                       */
/*----------------------------------------------------------------------------*/
void
cliauth_memory_fill(
   void * buffer,
   const void * sentinel,
   CliAuthUInt32 elements,
   CliAuthUInt32 bytes_per_element
);

/*----------------------------------------------------------------------------*/
/* Compares an arbitrary number of bytes for equality.                        */
/*----------------------------------------------------------------------------*/
/* data_lhs - The left-hand side of the comparision.  This buffer must be     */
/*            'bytes_lhs' number of bytes.                                    */
/*                                                                            */
/* data_rhs - The right-hand side of the comparision.  This buffer must be    */
/*            'bytes_rhs' number of bytes.                                    */
/*                                                                            */
/* bytes_lhs - The number of bytes to compare from 'data_lhs'.                */
/*                                                                            */
/* bytes_rhs - The number of bytes to compare from 'data_rhs'.                */
/*----------------------------------------------------------------------------*/
/* Return value - Whether the memory buffers are equal or not.                */
/*----------------------------------------------------------------------------*/
CliAuthBoolean
cliauth_memory_compare(
   const void * data_lhs,
   const void * data_rhs,
   CliAuthUInt32 bytes_lhs,
   CliAuthUInt32 bytes_rhs
);

/*----------------------------------------------------------------------------*/
/* The status of finding a sentinel in memory.                                */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_MEMORY_FIND_STATUS_FOUND - The sentinel was successfully located.  */
/*                                                                            */
/* CLIAUTH_MEMORY_FIND_STATUS_MISSING - The sentinel was unable to be         */
/*                                      located.                              */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_MEMORY_FIND_STATUS_FIELD_COUNT 2u
enum CliAuthMemoryFindStatus {
   CLIAUTH_MEMORY_FIND_STATUS_FOUND,
   CLIAUTH_MEMORY_FIND_STATUS_MISSING
};

/*----------------------------------------------------------------------------*/
/* The result of finding a sentinel in memory.                                */
/*----------------------------------------------------------------------------*/
/* status - The status of finding the sentinel.                               */
/*                                                                            */
/* position - The byte offset into the data where the sentinel was located.   */
/*            This is only valid to access if 'status' is                     */
/*            'CLIAUTH_MEMORY_FIND_STATUS_FOUND'.                             */
/*----------------------------------------------------------------------------*/
struct CliAuthMemoryFindResult {
   enum CliAuthMemoryFindStatus status;
   CliAuthUInt32 position;
};

/*----------------------------------------------------------------------------*/
/* Attempts to locate the position of a sentinel in a buffer.                 */
/*----------------------------------------------------------------------------*/
/* data - The buffer to search for the sentinel within.  This buffer must be  */
/*        large enough to store 'elements' number of                          */
/*        'bytes_per_element'-length elements.  In other words, the amount of */
/*        copied data may be calculated with the following formula:           */
/*                                                                            */
/*        searched bytes = elements * bytes_per_element                       */
/*                                                                            */
/* sentinel - The sentinel data to serach for.  This buffer must be large     */
/*            enough to store 'bytes_per_element' number of bytes.            */
/*                                                                            */
/* elements - The number of 'bytes_per_element'-byte elements to search       */
/*            through.                                                        */
/*                                                                            */
/* bytes_per_element - The number of bytes per element.                       */
/*----------------------------------------------------------------------------*/
struct CliAuthMemoryFindResult
cliauth_memory_find(
   const void * data,
   const void * sentinel,
   CliAuthUInt32 elements,
   CliAuthUInt32 bytes_per_element
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_MEMORY_H */

