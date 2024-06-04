/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/endian.c - Endian swapping function implementations.                   */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "endian.h"

void
cliauth_endian_swap(void * data, CliAuthUInt32 bytes) {
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

CliAuthSInt16
cliauth_endian_swap_sint16(CliAuthSInt16 value) {
   CliAuthSInt16 swapped;

   swapped = value;
   cliauth_endian_swap(&swapped, sizeof(CliAuthSInt16));
   return swapped;
}

CliAuthSInt32
cliauth_endian_swap_sint32(CliAuthSInt32 value) {
   CliAuthSInt32 swapped;

   swapped = value;
   cliauth_endian_swap(&swapped, sizeof(CliAuthSInt32));
   return swapped;
}

CliAuthSInt64
cliauth_endian_swap_sint64(CliAuthSInt64 value) {
   CliAuthSInt64 swapped;

   swapped = value;
   cliauth_endian_swap(&swapped, sizeof(CliAuthSInt64));
   return swapped;
}

CliAuthUInt16
cliauth_endian_swap_uint16(CliAuthUInt16 value) {
   CliAuthUInt16 swapped;

   swapped = value;
   cliauth_endian_swap(&swapped, sizeof(CliAuthUInt16));
   return swapped;
}

CliAuthUInt32
cliauth_endian_swap_uint32(CliAuthUInt32 value) {
   CliAuthUInt32 swapped;

   swapped = value;
   cliauth_endian_swap(&swapped, sizeof(CliAuthUInt32));
   return swapped;
}

CliAuthUInt64
cliauth_endian_swap_uint64(CliAuthUInt64 value) {
   CliAuthUInt64 swapped;

   swapped = value;
   cliauth_endian_swap(&swapped, sizeof(CliAuthUInt64));
   return swapped;
}

