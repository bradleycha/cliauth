/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/memory.c - Memory manipulation implementations.                        */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "memory.h"

void
cliauth_memory_copy(
   void * destination,
   const void * source,
   CliAuthUInt32 bytes
) {
   CliAuthUInt8 * destination_iter;
   const CliAuthUInt8 * source_iter;

   destination_iter = (CliAuthUInt8 *)destination;
   source_iter = (const CliAuthUInt8 *)source;

   while (bytes != 0) {
      *destination_iter = *source_iter;

      destination_iter++;
      source_iter++;
      bytes--;
   }

   return;
}

void
cliauth_memory_fill(
   void * buffer,
   const void * sentinel,
   CliAuthUInt32 elements,
   CliAuthUInt32 bytes_per_element
) {
   CliAuthUInt8 * buffer_iter;

   buffer_iter = (CliAuthUInt8 *)buffer;

   while (elements != 0) {
      cliauth_memory_copy(
         buffer_iter,
         sentinel,
         bytes_per_element
      );

      buffer_iter += bytes_per_element;
      elements--;
   }

   return;
}

CliAuthBoolean
cliauth_memory_compare(
   const void * data_lhs,
   const void * data_rhs,
   CliAuthUInt32 bytes
) {
   const CliAuthUInt8 * data_lhs_iter;
   const CliAuthUInt8 * data_rhs_iter;

   data_lhs_iter = (const CliAuthUInt8 *)data_lhs;
   data_rhs_iter = (const CliAuthUInt8 *)data_rhs;

   while (bytes != 0) {
      if (*data_lhs_iter != *data_rhs_iter) {
         return CLIAUTH_BOOLEAN_FALSE;
      }

      data_lhs_iter++;
      data_rhs_iter++;
      bytes--;
   }

   return CLIAUTH_BOOLEAN_TRUE;
}

struct CliAuthMemoryFindResult
cliauth_memory_find(
   const void * data,
   const void * sentinel,
   CliAuthUInt32 elements,
   CliAuthUInt32 bytes_per_element
) {
   struct CliAuthMemoryFindResult result;
   const CliAuthUInt8 * data_iter;
   CliAuthUInt32 position;

   data_iter = (const CliAuthUInt8 *)data;
   position = 0;

   while (elements != 0) {
      if (cliauth_memory_compare(
         data_iter,
         sentinel,
         bytes_per_element
      ) == CLIAUTH_BOOLEAN_TRUE) {
         result.status = CLIAUTH_MEMORY_FIND_STATUS_FOUND;
         result.position = position;
         return result;
      }

      data_iter += bytes_per_element;
      position += bytes_per_element;
      elements--;
   }

   result.status = CLIAUTH_MEMORY_FIND_STATUS_MISSING;
   return result;
}

