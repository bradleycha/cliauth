/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/arch/ia32/memory/endian.c - IA32-specific endian implementations.      */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "arch/ia32/memory/endian.h"

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32
/*----------------------------------------------------------------------------*/

#include "arch/ia32/instruction.h"

#if CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT32_IS_OPTIMIZED
union CliAuthInt32
cliauth_arch_ia32_memory_endian_swap_int32(
   union CliAuthInt32 value
) {
   return cliauth_arch_ia32_instruction_bswap_r32(value);
}
#endif /* CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT32_IS_OPTIMIZED */

#if CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT64_IS_OPTIMIZED
union CliAuthInt64
cliauth_arch_ia32_memory_endian_swap_int64(
   union CliAuthInt64 value
) {
   union CliAuthInt64 out;
   union CliAuthInt32 lo;
   union CliAuthInt32 hi;

   /* we only have the 32-bit instruction, so we need to work harder for this */
   /* micro-optimization.  more specifically, we byteswap the upper and lower */
   /* 32 bits using bswap, then manually swap the low and high 32-bits. */

   lo.uint = (CliAuthUInt32)(value.uint);
   hi.uint = (CliAuthUInt32)(value.uint >> CLIAUTH_LITERAL_UINT8(32u));

   lo = cliauth_arch_ia32_instruction_bswap_r32(lo);
   hi = cliauth_arch_ia32_instruction_bswap_r32(hi);

   out.uint = ((CliAuthUInt64)(hi.uint));
   out.uint |= (((CliAuthUInt64)(lo.uint)) << CLIAUTH_LITERAL_UINT8(32u));

   return out;
}
#endif /* CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT64_IS_OPTIMIZED */

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32 */

