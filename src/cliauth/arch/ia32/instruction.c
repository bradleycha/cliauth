/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/arch/ia32/instruction.c - IA32 instruction wrappers.                   */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/arch/ia32/instruction.h"

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32
/*----------------------------------------------------------------------------*/

#if CLIAUTH_ARCH_IA32_INSTRUCTION_SUPPORTED_BSWAP_R32
union CliAuthInt32
cliauth_arch_ia32_instruction_bswap_r32(
   union CliAuthInt32 operand
) {
   union CliAuthInt32 output;

#if CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY_GNU
   output.uint = operand.uint;
   __asm__(
      "bswap %0"
      : "+r" (output.uint)
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY_GNU */
#if CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC
   output.uint = _byteswap_ulong(operand.uint);
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC */

   return output;
}
#endif /* CLIAUTH_ARCH_IA32_INSTRUCTION_SUPPORTED_BSWAP_R32 */

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32 */

