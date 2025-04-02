/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/arch/amd64/instruction.c - AMD64 instruction wrappers.                 */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "arch/amd64/instruction.h"

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_AMD64
/*----------------------------------------------------------------------------*/

#if CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R32
union CliAuthInt32
cliauth_arch_amd64_instruction_bswap_r32(
   union CliAuthInt32 operand
) {
   union CliAuthInt32 output;

#if CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY_GNU
   output.uint = operand.uint;
   __asm__(
      "bswap %0"
      : "+r" (output.uint)
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY */
#if CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC
   output.uint = _byteswap_ulong(operand.uint);
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC */

   return output;
}
#endif /* CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R32 */

#if CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R64
union CliAuthInt64
cliauth_arch_amd64_instruction_bswap_r64(
   union CliAuthInt64 operand
) {
   union CliAuthInt64 output;

#if CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY_GNU
   output.uint = operand.uint;
   __asm__(
      "bswap %0"
      : "+r" (output.uint)
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY */
#if CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC
   output.uint = _byteswap_uint64(operand.uint);
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC */

   return output;
}
#endif /* CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R64 */

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_AMD64 */

