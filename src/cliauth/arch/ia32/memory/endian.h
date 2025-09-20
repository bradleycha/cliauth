/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/arch/ia32/memory/endian.h - IA32-specific endian declarations.         */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_H
#define _CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_H
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"

#if CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32
/*----------------------------------------------------------------------------*/

#include "cliauth/arch/ia32/instruction.h"

/*----------------------------------------------------------------------------*/
/* Whether optimized versions of the endian swap functions are available or   */
/* not.                                                                       */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT32_IS_OPTIMIZED\
   (\
      CLIAUTH_ARCH_IA32_INSTRUCTION_SUPPORTED_BSWAP_R32\
   )
#define CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT64_IS_OPTIMIZED\
   (\
      CLIAUTH_ARCH_IA32_INSTRUCTION_SUPPORTED_BSWAP_R32\
   )

/*----------------------------------------------------------------------------*/
/* Performs endian swapping, optimized for IA32.  See the documentation for   */
/* cliauth_memory_endian_convert_*() for more information.                    */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT32_IS_OPTIMIZED
union CliAuthInt32
cliauth_arch_ia32_memory_endian_swap_int32(
   union CliAuthInt32 value
);
#endif /* CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT32_IS_OPTIMIZED */
#if CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT64_IS_OPTIMIZED
union CliAuthInt64
cliauth_arch_ia32_memory_endian_swap_int64(
   union CliAuthInt64 value
);
#endif /* CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_SWAP_INT64_IS_OPTIMIZED */

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_PLATFORM_CPU_ARCHITECTURE_IS_IA32 */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_ARCH_IA32_MEMORY_ENDIAN_H */

