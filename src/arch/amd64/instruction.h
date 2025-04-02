/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/arch/amd64/instruction.h - AMD64 instruction bindings.                 */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_ARCH_AMD64_INSTRUCTION_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_AMD64
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/* Whether the bswap/r32 instruction is supported or not.                     */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R32\
   (\
      CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY_GNU ||\
      CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC\
   )

/*----------------------------------------------------------------------------*/
/* Whether the bswap/r64 instruction is supported or not.                     */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R64\
   (\
      CLIAUTH_CONFIG_PLATFORM_COMPILER_SUPPORTS_INLINE_ASSEMBLY_GNU ||\
      CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC\
   )

/*----------------------------------------------------------------------------*/
/* Executes the bswap instruction, which swaps the byte ordering of the given */
/* value.                                                                     */
/*----------------------------------------------------------------------------*/
/* operand - The value to byte swap.                                          */
/*----------------------------------------------------------------------------*/
/* Return value - The input value after being byte swapped.                   */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R32
union CliAuthInt32
cliauth_arch_amd64_instruction_bswap_r32(
   union CliAuthInt32 operand
);
#endif /* CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R32 */
#if CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R64
union CliAuthInt64
cliauth_arch_amd64_instruction_bswap_r64(
   union CliAuthInt64 operand
);
#endif /* CLIAUTH_ARCH_AMD64_INSTRUCTION_SUPPORTED_BSWAP_R32 */

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_AMD64 */

/*----------------------------------------------------------------------------*/
#define _CLIAUTH_ARCH_AMD64_INSTRUCTION_H
#endif /* _CLIAUTH_ARCH_AMD64_INSTRUCTION_H */

