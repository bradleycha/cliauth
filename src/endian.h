/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/endian.h - Header for endian swapping functions                        */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_ENDIAN_H
#define _CLIAUTH_ENDIAN_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

/*----------------------------------------------------------------------------*/
/* An endianess format.                                                       */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_ENDIAN_TARGET_LITTLE - Bytes will be ordered starting with least   */
/*                                significant first.                          */
/*                                                                            */
/* CLIAUTH_ENDIAN_TARGET_BIG - Bytes will be ordered starting with most       */
/*                             significant first.                             */
/*----------------------------------------------------------------------------*/
enum CliAuthEndianTarget {
   CLIAUTH_ENDIAN_TARGET_LITTLE = 0,
   CLIAUTH_ENDIAN_TARGET_BIG = 1
};

/*----------------------------------------------------------------------------*/
/* The native endianess of the target platform.                               */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE
   #define CLIAUTH_ENDIAN_TARGET_NATIVE CLIAUTH_ENDIAN_TARGET_BIG
#else /* CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE */
   #define CLIAUTH_ENDIAN_TARGET_NATIVE CLIAUTH_ENDIAN_TARGET_LITTLE
#endif /* CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE */

/*----------------------------------------------------------------------------*/
/* Converts the endianess of an arbitrary number of bytes between the host    */
/* platform's endianess and a known endianess, overwriting the result into    */
/* the source buffer.                                                         */
/*----------------------------------------------------------------------------*/
/* data - A pointer to the data to be converted in-place.                     */
/*                                                                            */
/* bytes - The number of bytes in 'data' which should be swapped.             */
/*                                                                            */
/* target - The target endianess to convert between.                          */
/*----------------------------------------------------------------------------*/
void
cliauth_endian_convert_inplace(
   void * data,
   CliAuthUInt32 bytes,
   enum CliAuthEndianTarget target
);

/*----------------------------------------------------------------------------*/
/* Converts the endianess of an arbitrary number of bytes between the host    */
/* platform's endianess and a known endianess, copying the result into a      */
/* seperate buffer.                                                           */
/*----------------------------------------------------------------------------*/
/* dest - The destination buffer to store the converted endian data to.  This */
/*        buffer should be the same length or greater length than 'source'.   */
/*                                                                            */
/* source - The source data to be copied and swapped.                         */
/*                                                                            */
/* bytes - The number of bytes in 'source' which should be swapped.           */
/*                                                                            */
/* target - The target endianess to convert between.                          */
/*----------------------------------------------------------------------------*/
void
cliauth_endian_convert_copy(
   void * dest,
   const void * source,
   CliAuthUInt32 bytes,
   enum CliAuthEndianTarget target
);

/*----------------------------------------------------------------------------*/
/* Converts the endianess of an integer between the host platform's native    */
/* endianess and a known endianess.                                           */
/*----------------------------------------------------------------------------*/
/* value - The integer value to have its endianess swapped.                   */
/*                                                                            */
/* target - The target endianess to convert between.                          */
/*----------------------------------------------------------------------------*/
/* Return value - The integer value with its endianess swapped.               */
/*----------------------------------------------------------------------------*/
CliAuthUInt16
cliauth_endian_convert_uint16(
   CliAuthUInt16 value,
   enum CliAuthEndianTarget target
);
CliAuthUInt32
cliauth_endian_convert_uint32(
   CliAuthUInt32 value,
   enum CliAuthEndianTarget target
);
CliAuthUInt64
cliauth_endian_convert_uint64(
   CliAuthUInt64 value,
   enum CliAuthEndianTarget target
);
CliAuthSInt16
cliauth_endian_convert_sint16(
   CliAuthSInt16 value,
   enum CliAuthEndianTarget target
);
CliAuthSInt32
cliauth_endian_convert_sint32(
   CliAuthSInt32 value,
   enum CliAuthEndianTarget target
);
CliAuthSInt64
cliauth_endian_convert_sint64(
   CliAuthSInt64 value,
   enum CliAuthEndianTarget target
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_ENDIAN_H */

