/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/memory/endian.c - Endian swapping function implementations.            */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/memory/endian.h"

#include "cliauth/arch/ia32/memory/endian.h"
#include "cliauth/arch/amd64/memory/endian.h"

#include "cliauth/memory/memory.h"

static void
cliauth_memory_endian_swap_inplace(
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
cliauth_memory_endian_swap_copy(
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

static union CliAuthInt16
cliauth_memory_endian_swap_int16(
   union CliAuthInt16 value
) {
   union CliAuthInt16 output;

   output.uint = value.uint;
   cliauth_memory_endian_swap_inplace(
      output.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(output))
   );

   return output;
}

static union CliAuthInt32
cliauth_memory_endian_swap_int32(
   union CliAuthInt32 value
) {
   union CliAuthInt32 output;

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32 && CLIAUTH_ARCH_IA32_MATH_ENDIAN_SWAP_INT32_IS_OPTIMIZED
   output = cliauth_arch_ia32_memory_endian_swap_int32(value);
#elif CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_AMD64 && CLIAUTH_ARCH_AMD64_MATH_ENDIAN_SWAP_INT32_IS_OPTIMIZED
   output = cliauth_arch_amd64_memory_endian_swap_int32(value);
#else
   output.uint = value.uint;
   cliauth_memory_endian_swap_inplace(
      output.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(output))
   );
#endif

   return output;
}

static union CliAuthInt64
cliauth_memory_endian_swap_int64(
   union CliAuthInt64 value
) {
   union CliAuthInt64 output;

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32 && CLIAUTH_ARCH_IA32_MATH_ENDIAN_SWAP_INT64_IS_OPTIMIZED
   output = cliauth_arch_ia32_memory_endian_swap_int64(value);
#elif CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_AMD64 && CLIAUTH_ARCH_AMD64_MATH_ENDIAN_SWAP_INT64_IS_OPTIMIZED
   output = cliauth_arch_amd64_memory_endian_swap_int64(value);
#else
   output.uint = value.uint;
   cliauth_memory_endian_swap_inplace(
      output.bytes,
      CLIAUTH_LITERAL_UINT32(sizeof(output))
   );
#endif

   return output;
}

static union CliAuthInt16
cliauth_memory_endian_convert_int16(
   union CliAuthInt16 value,
   enum CliAuthMemoryEndianTarget target
) {
   if (target == CLIAUTH_MEMORY_ENDIAN_TARGET_NATIVE) {
      return value;
   }

   return cliauth_memory_endian_swap_int16(value);
}

static union CliAuthInt32
cliauth_memory_endian_convert_int32(
   union CliAuthInt32 value,
   enum CliAuthMemoryEndianTarget target
) {
   if (target == CLIAUTH_MEMORY_ENDIAN_TARGET_NATIVE) {
      return value;
   }

   return cliauth_memory_endian_swap_int32(value);
}

static union CliAuthInt64
cliauth_memory_endian_convert_int64(
   union CliAuthInt64 value,
   enum CliAuthMemoryEndianTarget target
) {
   if (target == CLIAUTH_MEMORY_ENDIAN_TARGET_NATIVE) {
      return value;
   }

   return cliauth_memory_endian_swap_int64(value);
}

void
cliauth_memory_endian_convert_inplace(
   CliAuthUInt8 data [],
   CliAuthUInt32 bytes,
   enum CliAuthMemoryEndianTarget target
) {
   if (target != CLIAUTH_MEMORY_ENDIAN_TARGET_NATIVE) {
      cliauth_memory_endian_swap_inplace(data, bytes);
   }

   return;
}

void
cliauth_memory_endian_convert_copy(
   CliAuthUInt8 dest [],
   const CliAuthUInt8 source [],
   CliAuthUInt32 bytes,
   enum CliAuthMemoryEndianTarget target
) {
   if (target != CLIAUTH_MEMORY_ENDIAN_TARGET_NATIVE) {
      cliauth_memory_endian_swap_copy(dest, source, bytes);
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
cliauth_memory_endian_convert_uint16(
   CliAuthUInt16 value,
   enum CliAuthMemoryEndianTarget target
) {
   union CliAuthInt16 value_generic;
   union CliAuthInt16 output;

   value_generic.uint = value;

   output = cliauth_memory_endian_convert_int16(
      value_generic,
      target
   );

   return output.uint;
}

CliAuthUInt32
cliauth_memory_endian_convert_uint32(
   CliAuthUInt32 value,
   enum CliAuthMemoryEndianTarget target
) {
   union CliAuthInt32 value_generic;
   union CliAuthInt32 output;

   value_generic.uint = value;

   output = cliauth_memory_endian_convert_int32(
      value_generic,
      target
   );

   return output.uint;
}

CliAuthUInt64
cliauth_memory_endian_convert_uint64(
   CliAuthUInt64 value,
   enum CliAuthMemoryEndianTarget target
) {
   union CliAuthInt64 value_generic;
   union CliAuthInt64 output;

   value_generic.uint = value;

   output = cliauth_memory_endian_convert_int64(
      value_generic,
      target
   );

   return output.uint;
}

CliAuthSInt16
cliauth_memory_endian_convert_sint16(
   CliAuthSInt16 value,
   enum CliAuthMemoryEndianTarget target
) {
   union CliAuthInt16 value_generic;
   union CliAuthInt16 output;

   value_generic.sint = value;

   output = cliauth_memory_endian_convert_int16(
      value_generic,
      target
   );

   return output.sint;
}

CliAuthSInt32
cliauth_memory_endian_convert_sint32(
   CliAuthSInt32 value,
   enum CliAuthMemoryEndianTarget target
) {
   union CliAuthInt32 value_generic;
   union CliAuthInt32 output;

   value_generic.sint = value;

   output = cliauth_memory_endian_convert_int32(
      value_generic,
      target
   );

   return output.sint;
}

CliAuthSInt64
cliauth_memory_endian_convert_sint64(
   CliAuthSInt64 value,
   enum CliAuthMemoryEndianTarget target
) {
   union CliAuthInt64 value_generic;
   union CliAuthInt64 output;

   value_generic.sint = value;

   output = cliauth_memory_endian_convert_int64(
      value_generic,
      target
   );

   return output.sint;
}

