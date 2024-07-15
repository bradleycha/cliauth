/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/endian.c - Endian swapping function implementations.                   */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "endian.h"

#include <string.h>

static void
cliauth_endian_swap_inplace(
   void * data,
   CliAuthUInt32 bytes
) {
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

static void
cliauth_endian_swap_copy(
   void * dest,
   const void * source,
   CliAuthUInt32 bytes
) {
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

void
cliauth_endian_convert_inplace(
   void * data,
   CliAuthUInt32 bytes,
   enum CliAuthEndianTarget target
) {
   if (target != CLIAUTH_ENDIAN_TARGET_NATIVE) {
      cliauth_endian_swap_inplace(data, bytes);
   }

   return;
}

void
cliauth_endian_convert_copy(
   void * dest,
   const void * source,
   CliAuthUInt32 bytes,
   enum CliAuthEndianTarget target
) {
   if (target != CLIAUTH_ENDIAN_TARGET_NATIVE) {
      cliauth_endian_swap_copy(dest, source, bytes);
   } else {
      (void)memcpy(dest, source, bytes);
   }

   return;
}

CliAuthUInt16
cliauth_endian_convert_uint16(
   CliAuthUInt16 value,
   enum CliAuthEndianTarget target
) {
   cliauth_endian_convert_inplace(
      &value,
      sizeof(value),
      target
   );

   return value;
}

CliAuthUInt32
cliauth_endian_convert_uint32(
   CliAuthUInt32 value,
   enum CliAuthEndianTarget target
) {
   cliauth_endian_convert_inplace(
      &value,
      sizeof(value),
      target
   );

   return value;
}

CliAuthUInt64
cliauth_endian_convert_uint64(
   CliAuthUInt64 value,
   enum CliAuthEndianTarget target
) {
   cliauth_endian_convert_inplace(
      &value,
      sizeof(value),
      target
   );

   return value;
}

CliAuthSInt16
cliauth_endian_convert_sint16(
   CliAuthSInt16 value,
   enum CliAuthEndianTarget target
) {
   cliauth_endian_convert_inplace(
      &value,
      sizeof(value),
      target
   );

   return value;
}

CliAuthSInt32
cliauth_endian_convert_sint32(
   CliAuthSInt32 value,
   enum CliAuthEndianTarget target
) {
   cliauth_endian_convert_inplace(
      &value,
      sizeof(value),
      target
   );

   return value;
}

CliAuthSInt64
cliauth_endian_convert_sint64(
   CliAuthSInt64 value,
   enum CliAuthEndianTarget target
) {
   cliauth_endian_convert_inplace(
      &value,
      sizeof(value),
      target
   );

   return value;
}

