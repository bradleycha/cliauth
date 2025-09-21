/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/arch/ia32/instruction.h - IA32 instruction bindings.           */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_ARCH_IA32_INSTRUCTION_H
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/* Whether the bswap/r32 instruction is supported or not.                     */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ARCH_IA32_INSTRUCTION_SUPPORTED_BSWAP_R32\
   (\
      CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IA32_HAS_INSTRUCTION_BSWAP &&\
      (\
         CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY_GNU ||\
         CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC\
      )\
   )

/*----------------------------------------------------------------------------*/
/* Executes the bswap instruction, which swaps the byte ordering of the given */
/* value.                                                                     */
/*----------------------------------------------------------------------------*/
/* operand - The value to byte swap.                                          */
/*----------------------------------------------------------------------------*/
/* Return value - The input value after being byte swapped.                   */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_ARCH_IA32_INSTRUCTION_SUPPORTED_BSWAP_R32
union CliAuthInt32
cliauth_arch_ia32_instruction_bswap_r32(
   union CliAuthInt32 operand
);
#endif /* CLIAUTH_ARCH_IA32_INSTRUCTION_SUPPORTED_BSWAP_R32 */

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32 */

/*----------------------------------------------------------------------------*/
#define _CLIAUTH_ARCH_IA32_INSTRUCTION_H
#endif /* _CLIAUTH_ARCH_IA32_INSTRUCTION_H */

