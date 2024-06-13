/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/endian.h - Header for endian swapping functions                        */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_ENDIAN_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include <string.h>

/*----------------------------------------------------------------------------*/
/* Swaps the endianess of an arbitrary amount of data in-place.               */
/*----------------------------------------------------------------------------*/
/* data - A pointer to the data to be swapped in-place.                       */
/*                                                                            */
/* bytes - The number of bytes in 'data' which should be swapped.             */
/*----------------------------------------------------------------------------*/
void
cliauth_endian_swap_inplace(void * data, CliAuthUInt32 bytes);

/*----------------------------------------------------------------------------*/
/* Swaps the endianess of an arbitrary amount of data from one buffer to      */
/* another.                                                                   */
/*----------------------------------------------------------------------------*/
/* dest - The destination buffer to store the swapped endian data to.  This   */
/*        buffer should be the same length or greater length than 'source'.   */
/*                                                                            */
/* source - The source data to be copied and swapped.                         */
/*                                                                            */
/* bytes - The number of bytes in 'source' which should be swapped.           */
/*----------------------------------------------------------------------------*/
void
cliauth_endian_swap_copy(void * dest, const void * source, CliAuthUInt32 bytes);

/*----------------------------------------------------------------------------*/
/* Swaps the endianess of various integer types.                              */
/*----------------------------------------------------------------------------*/
/* value - The integer value to have its endianess swapped.                   */
/*                                                                            */
/* Return value - The integer value with its endianess swapped.               */
/*----------------------------------------------------------------------------*/
CliAuthSInt16
cliauth_endian_swap_sint16(CliAuthSInt16 value);
CliAuthSInt32
cliauth_endian_swap_sint32(CliAuthSInt32 value);
CliAuthSInt64
cliauth_endian_swap_sint64(CliAuthSInt64 value);
CliAuthUInt16
cliauth_endian_swap_uint16(CliAuthUInt16 value);
CliAuthUInt32
cliauth_endian_swap_uint32(CliAuthUInt32 value);
CliAuthUInt64
cliauth_endian_swap_uint64(CliAuthUInt64 value);

/*----------------------------------------------------------------------------*/
/* Converts from the host platform's native endianess to the given endianess  */
/* for various types or arbitrary byte data.  If the host's endianess is the  */
/* same as the target endianess, no conversion will take place.  For more     */
/* information, see the documentation for cliauth_endian_swap() and           */
/* cliauth_endian_swap_*int*().                                               */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_ENDIAN_PLATFORM_IS_BE
   #define cliauth_endian_host_to_big_inplace(data, bytes)
   #define cliauth_endian_host_to_big_copy(dest, source, bytes)\
      (void)memcpy(dest, source, bytes)
   #define cliauth_endian_host_to_big_sint16(value) (value)
   #define cliauth_endian_host_to_big_sint32(value) (value)
   #define cliauth_endian_host_to_big_sint64(value) (value)
   #define cliauth_endian_host_to_big_uint16(value) (value)
   #define cliauth_endian_host_to_big_uint32(value) (value)
   #define cliauth_endian_host_to_big_uint64(value) (value)
   #define cliauth_endian_host_to_little_inplace(data, bytes)\
      cliauth_endian_swap_inplace(data, bytes)
   #define cliauth_endian_host_to_little_copy(dest, source, bytes)\
      cliauth_endian_swap_copy(dest, source, bytes)
   #define cliauth_endian_host_to_little_sint16(value)\
      cliauth_endian_swap_sint16(value)
   #define cliauth_endian_host_to_little_sint32(value)\
      cliauth_endian_swap_sint32(value)
   #define cliauth_endian_host_to_little_sint64(value)\
      cliauth_endian_swap_sint64(value)
   #define cliauth_endian_host_to_little_uint16(value)\
      cliauth_endian_swap_uint16(value)
   #define cliauth_endian_host_to_little_uint32(value)\
      cliauth_endian_swap_uint32(value)
   #define cliauth_endian_host_to_little_uint64(value)\
      cliauth_endian_swap_uint64(value)
#else /* CLIAUTH_CONFIG_ENDIAN_PLATFORM_IS_BE */
   #define cliauth_endian_host_to_big_inplace(data, bytes)\
      cliauth_endian_swap_inplace(data, bytes)
   #define cliauth_endian_host_to_big_copy(dest, source, bytes)\
      cliauth_endian_swap_copy(dest, source, bytes)
   #define cliauth_endian_host_to_big_sint16(value)\
      cliauth_endian_swap_sint16(value)
   #define cliauth_endian_host_to_big_sint32(value)\
      cliauth_endian_swap_sint32(value)
   #define cliauth_endian_host_to_big_sint64(value)\
      cliauth_endian_swap_sint64(value)
   #define cliauth_endian_host_to_big_uint16(value)\
      cliauth_endian_swap_uint16(value)
   #define cliauth_endian_host_to_big_uint32(value)\
      cliauth_endian_swap_uint32(value)
   #define cliauth_endian_host_to_big_uint64(value)\
      cliauth_endian_swap_uint64(value)
   #define cliauth_endian_host_to_little_inplace(data, bytes)
   #define cliauth_endian_host_to_little_copy(dest, source, bytes)\
      (void)memcpy(dest, source, bytes)
   #define cliauth_endian_host_to_little_sint16(value) (value)
   #define cliauth_endian_host_to_little_sint32(value) (value)
   #define cliauth_endian_host_to_little_sint64(value) (value)
   #define cliauth_endian_host_to_little_uint16(value) (value)
   #define cliauth_endian_host_to_little_uint32(value) (value)
   #define cliauth_endian_host_to_little_uint64(value) (value)
#endif /* CLIAUTH_CONFIG_ENDIAN_PLATFORM_IS_BE */

/*----------------------------------------------------------------------------*/
#define _CLIAUTH_ENDIAN_H
#endif /* _CLIAUTH_ENDIAN_H */

