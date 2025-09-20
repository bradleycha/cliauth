/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/io/log.c - Logging interface implementation.                           */
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"
#include "cliauth/io/log.h"

#include <stdarg.h>
#include <stdio.h>

void
cliauth_io_log(const char * format, ...) {
   va_list args;
   va_start(args, format);

   (void)vfprintf(stderr, format, args);

   va_end(args);
   return;
}

