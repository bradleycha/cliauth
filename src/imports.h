/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/imports.h - Library import macro definitions.                          */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_IMPORTS_H
#define _CLIAUTH_IMPORTS_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

#define _CLIAUTH_IMPORTS_USE_OPTIONAL(expression)\
   (CLIAUTH_CONFIG_OPTIONAL_LIBRARY_IMPORTS && expression)

#define CLIAUTH_IMPORTS_USE_C_STRING_H\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(HAVE_STRING_H))
#define CLIAUTH_IMPORTS_USE_C_MEMCPY\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(HAVE_MEMCPY))
#define CLIAUTH_IMPORTS_USE_C_MEMSET\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(HAVE_MEMSET))
#define CLIAUTH_IMPORTS_USE_C_MEMCMP\
   (_CLIAUTH_IMPORTS_USE_OPTIONAL(HAVE_MEMCMP))

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_IMPORTS_H */

