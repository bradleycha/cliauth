/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/endian.c - Endian swapping function implementations.                   */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "endian.h"

#include "memory.h"

static void
cliauth_endian_swap_inplace(
   CliAuthUInt8 data [],
   CliAuthUInt32 bytes
) {
   CliAuthUInt8 * start;
   CliAuthUInt8 * end;
   CliAuthUInt8 temp;

   /* This is basically just a CS 101 in-place array reversal. */
   start = data;
   end = start + bytes - 1u;
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
   CliAuthUInt8 dest [],
   const CliAuthUInt8 source [],
   CliAuthUInt32 bytes
) {
   CliAuthUInt8 * dest_iter;
   const CliAuthUInt8 * source_iter;

   dest_iter = dest;
   source_iter = source + bytes - 1u;
   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      *dest_iter = *source_iter;

      dest_iter++;
      source_iter--;
      bytes--;
   }

   return;
}

void
cliauth_endian_convert_inplace(
   CliAuthUInt8 data [],
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
   CliAuthUInt8 dest [],
   const CliAuthUInt8 source [],
   CliAuthUInt32 bytes,
   enum CliAuthEndianTarget target
) {
   if (target != CLIAUTH_ENDIAN_TARGET_NATIVE) {
      cliauth_endian_swap_copy(dest, source, bytes);
   } else {
      cliauth_memory_copy(
         dest,
         source,
         bytes
      );
   }

   return;
}

CliAuthUInt16
cliauth_endian_convert_uint16(
   CliAuthUInt16 value,
   enum CliAuthEndianTarget target
) {
   union CliAuthInt16 value_generic;

   value_generic.uint = value;

   cliauth_endian_convert_inplace(
      value_generic.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(value)),
      target
   );

   return value_generic.uint;
}

CliAuthUInt32
cliauth_endian_convert_uint32(
   CliAuthUInt32 value,
   enum CliAuthEndianTarget target
) {
   union CliAuthInt32 value_generic;

   value_generic.uint = value;

   cliauth_endian_convert_inplace(
      value_generic.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(value)),
      target
   );

   return value_generic.uint;
}

CliAuthUInt64
cliauth_endian_convert_uint64(
   CliAuthUInt64 value,
   enum CliAuthEndianTarget target
) {
   union CliAuthInt64 value_generic;

   value_generic.uint = value;

   cliauth_endian_convert_inplace(
      value_generic.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(value)),
      target
   );

   return value_generic.uint;
}

CliAuthSInt16
cliauth_endian_convert_sint16(
   CliAuthSInt16 value,
   enum CliAuthEndianTarget target
) {
   union CliAuthInt16 value_generic;

   value_generic.sint = value;

   cliauth_endian_convert_inplace(
      value_generic.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(value)),
      target
   );

   return value_generic.sint;
}

CliAuthSInt32
cliauth_endian_convert_sint32(
   CliAuthSInt32 value,
   enum CliAuthEndianTarget target
) {
   union CliAuthInt32 value_generic;

   value_generic.sint = value;

   cliauth_endian_convert_inplace(
      value_generic.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(value)),
      target
   );

   return value_generic.sint;
}

CliAuthSInt64
cliauth_endian_convert_sint64(
   CliAuthSInt64 value,
   enum CliAuthEndianTarget target
) {
   union CliAuthInt64 value_generic;

   value_generic.sint = value;

   cliauth_endian_convert_inplace(
      value_generic.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(value)),
      target
   );

   return value_generic.sint;
}

