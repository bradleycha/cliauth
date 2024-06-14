/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/endian.c - Endian swapping function implementations.                   */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "endian.h"

#include <string.h>

void
cliauth_endian_swap_inplace(void * data, CliAuthUInt32 bytes) {
   CliAuthUInt8 * start;
   CliAuthUInt8 * end;
   CliAuthUInt8 temp;

   /* This is basically just a CS 101 in-place array reversal. */
   start = (CliAuthUInt8 *)data;
   end = start + bytes - 1;
   while (start < end) {
      temp = *start;
      *start = *end;
      *end = temp;

      start++;
      end--;
   }

   return;
}

void
cliauth_endian_swap_copy(void * dest, const void * source, CliAuthUInt32 bytes) {
   CliAuthUInt8 * dest_iter;
   CliAuthUInt8 * source_iter;

   dest_iter = (CliAuthUInt8 *)dest;
   source_iter = ((CliAuthUInt8 *)source) + bytes - 1;
   while (bytes != 0) {
      *dest_iter = *source_iter;

      dest_iter++;
      source_iter--;
      bytes--;
   }

   return;
}

CliAuthSInt16
cliauth_endian_swap_sint16(CliAuthSInt16 value) {
   CliAuthSInt16 swapped;

   swapped = value;
   cliauth_endian_swap_inplace(&swapped, sizeof(CliAuthSInt16));
   return swapped;
}

CliAuthSInt32
cliauth_endian_swap_sint32(CliAuthSInt32 value) {
   CliAuthSInt32 swapped;

   swapped = value;
   cliauth_endian_swap_inplace(&swapped, sizeof(CliAuthSInt32));
   return swapped;
}

CliAuthSInt64
cliauth_endian_swap_sint64(CliAuthSInt64 value) {
   CliAuthSInt64 swapped;

   swapped = value;
   cliauth_endian_swap_inplace(&swapped, sizeof(CliAuthSInt64));
   return swapped;
}

CliAuthUInt16
cliauth_endian_swap_uint16(CliAuthUInt16 value) {
   CliAuthUInt16 swapped;

   swapped = value;
   cliauth_endian_swap_inplace(&swapped, sizeof(CliAuthUInt16));
   return swapped;
}

CliAuthUInt32
cliauth_endian_swap_uint32(CliAuthUInt32 value) {
   CliAuthUInt32 swapped;

   swapped = value;
   cliauth_endian_swap_inplace(&swapped, sizeof(CliAuthUInt32));
   return swapped;
}

CliAuthUInt64
cliauth_endian_swap_uint64(CliAuthUInt64 value) {
   CliAuthUInt64 swapped;

   swapped = value;
   cliauth_endian_swap_inplace(&swapped, sizeof(CliAuthUInt64));
   return swapped;
}

void
cliauth_endian_host_to_big_inplace(void * data, CliAuthUInt32 bytes) {
#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   (void)data;
   (void)bytes;
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   cliauth_endian_swap_inplace(data, bytes);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return;
}

void
cliauth_endian_host_to_big_copy(void * dest, const void * source, CliAuthUInt32 bytes) {
#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   (void)memcpy(dest, source, bytes);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   cliauth_endian_swap_copy(dest, source, bytes);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return;
}

CliAuthSInt16
cliauth_endian_host_to_big_sint16(CliAuthSInt16 value) {
   CliAuthSInt16 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = value;
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = cliauth_endian_swap_sint16(value);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthSInt32
cliauth_endian_host_to_big_sint32(CliAuthSInt32 value) {
   CliAuthSInt32 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = value;
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = cliauth_endian_swap_sint32(value);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthSInt64
cliauth_endian_host_to_big_sint64(CliAuthSInt64 value) {
   CliAuthSInt64 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = value;
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = cliauth_endian_swap_sint64(value);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthUInt16
cliauth_endian_host_to_big_uint16(CliAuthUInt16 value) {
   CliAuthUInt16 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = value;
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = cliauth_endian_swap_uint16(value);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthUInt32
cliauth_endian_host_to_big_uint32(CliAuthUInt32 value) {
   CliAuthUInt32 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = value;
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = cliauth_endian_swap_uint32(value);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthUInt64
cliauth_endian_host_to_big_uint64(CliAuthUInt64 value) {
   CliAuthUInt64 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = value;
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = cliauth_endian_swap_uint64(value);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

void
cliauth_endian_host_to_little_inplace(void * data, CliAuthUInt32 bytes) {
#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   cliauth_endian_swap_inplace(data, bytes);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   (void)data;
   (void)bytes;
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return;
}

void
cliauth_endian_host_to_little_copy(void * dest, const void * source, CliAuthUInt32 bytes) {
#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   cliauth_endian_swap_copy(dest, source, bytes);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   (void)memcpy(dest, source, bytes);
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return;
}

CliAuthSInt16
cliauth_endian_host_to_little_sint16(CliAuthSInt16 value) {
   CliAuthSInt16 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = cliauth_endian_swap_sint16(value);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = value;
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthSInt32
cliauth_endian_host_to_little_sint32(CliAuthSInt32 value) {
   CliAuthSInt32 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = cliauth_endian_swap_sint32(value);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = value;
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthSInt64
cliauth_endian_host_to_little_sint64(CliAuthSInt64 value) {
   CliAuthSInt64 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = cliauth_endian_swap_sint64(value);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = value;
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthUInt16
cliauth_endian_host_to_little_uint16(CliAuthUInt16 value) {
   CliAuthUInt16 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = cliauth_endian_swap_uint16(value);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = value;
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthUInt32
cliauth_endian_host_to_little_uint32(CliAuthUInt32 value) {
   CliAuthUInt32 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = cliauth_endian_swap_uint32(value);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = value;
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

CliAuthUInt64
cliauth_endian_host_to_little_uint64(CliAuthUInt64 value) {
   CliAuthUInt64 retn;

#if CLIAUTH_CONFIG_PLATFORM_IS_BE
   retn = cliauth_endian_swap_uint64(value);
#else /* CLIAUTH_CONFIG_PLATFORM_IS_BE */
   retn = value;
#endif /* CLIAUTH_CONFIG_PLATFORM_IS_BE */

   return retn;
}

