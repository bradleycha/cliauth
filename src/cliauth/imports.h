/*----------------------------------------------------------------------------*/
/*                     Copyright (c) CliAuth 2024 - 2026                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth/imports.h - Library import macro definitions.                  */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IMPORTS_H
#define _CLIAUTH_IMPORTS_H
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"

#define _CLIAUTH_IMPORTS_USE_OPTIONAL(expression)\
   (CLIAUTH_CONFIG_OPTIONAL_LIBRARY_IMPORTS && expression)

#define CLIAUTH_IMPORTS_USE_C_STRING_H\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(CLIAUTH_HAVE_STRING_H))
#define CLIAUTH_IMPORTS_USE_C_STDINT_H\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(CLIAUTH_HAVE_STDINT_H))
#define CLIAUTH_IMPORTS_USE_C_MEMCPY\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(CLIAUTH_HAVE_MEMCPY))
#define CLIAUTH_IMPORTS_USE_C_MEMSET\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(CLIAUTH_HAVE_MEMSET))
#define CLIAUTH_IMPORTS_USE_C_MEMCMP\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(CLIAUTH_HAVE_MEMCMP))

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IMPORTS_H */

