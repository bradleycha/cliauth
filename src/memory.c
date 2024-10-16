/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/memory.c - Memory manipulation implementations.                        */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "memory.h"

#if CLIAUTH_IMPORTS_USE_C_STRING_H
/*----------------------------------------------------------------------------*/

#include <string.h>

/* the max value of libc's size_t type */
#define CLIAUTH_MEMORY_LIBC_SIZE_T_MAX\
   (SIZE_MAX)

/* whether sizeof(size_t) is less than sizeof(CliAuthUInt32) */
#define CLIAUTH_MEMORY_LIBC_SIZE_T_IS_SMALL\
   (CLIAUTH_MEMORY_LIBC_SIZE_T_MAX < CLIAUTH_UINT32_MAX_LITERAL)

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_IMPORTS_USE_C_STRING_H */

static void
cliauth_memory_copy_fallback(
   void * destination,
   const void * source,
   CliAuthUInt32 bytes
) {
   CliAuthUInt8 * destination_iter;
   const CliAuthUInt8 * source_iter;

   destination_iter = (CliAuthUInt8 *)destination;
   source_iter = (const CliAuthUInt8 *)source;

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      *destination_iter = *source_iter;

      destination_iter++;
      source_iter++;
      bytes--;
   }

   return;
}

static void
cliauth_memory_copy_libc(
   void * destination,
   const void * source,
   CliAuthUInt32 bytes
) {
#if CLIAUTH_IMPORTS_USE_C_MEMCPY
   CliAuthUInt8 * destination_iter;
   const CliAuthUInt8 * source_iter;

   destination_iter = (CliAuthUInt8 *)destination;
   source_iter = (const CliAuthUInt8 *)source;

#if CLIAUTH_MEMORY_LIBC_SIZE_T_IS_SMALL
   while (bytes > CLIAUTH_LITERAL_UINT32(CLIAUTH_MEMORY_LIBC_SIZE_T_MAX)) {
      (void)memcpy(
         destination_iter,
         source_iter,
         CLIAUTH_MEMORY_LIBC_SIZE_T_MAX
      );

      destination_iter += CLIAUTH_MEMORY_LIBC_SIZE_T_MAX;
      source_iter += CLIAUTH_MEMORY_LIBC_SIZE_T_MAX;
      bytes -= CLIAUTH_LITERAL_UINT32(CLIAUTH_MEMORY_LIBC_SIZE_T_MAX);
   }
#endif /* CLIAUTH_MEMORY_LIBC_SIZE_T_IS_SMALL */

   (void)memcpy(
      destination_iter,
      source_iter,
      (size_t)bytes
   );
#else /* CLIAUTH_IMPORTS_USE_C_MEMCPY */
   (void)destination;
   (void)source;
   (void)bytes;
#endif /* CLIAUTH_IMPORTS_USE_C_MEMCPY */

   return;
}

void
cliauth_memory_copy(
   void * destination,
   const void * source,
   CliAuthUInt32 bytes
) {
#if CLIAUTH_IMPORTS_USE_C_MEMCPY
   (void)cliauth_memory_copy_fallback;
   cliauth_memory_copy_libc(destination, source, bytes);
#else /* CLIAUTH_IMPORTS_USE_C_MEMCPY */
   (void)cliauth_memory_copy_libc;
   cliauth_memory_copy_fallback(destination, source, bytes);
#endif /* CLIAUTH_IMPORTS_USE_C_MEMCPY */
   
   return;
}

static void
cliauth_memory_fill_fallback(
   void * buffer,
   const void * sentinel,
   CliAuthUInt32 elements,
   CliAuthUInt32 bytes_per_element
) {
   CliAuthUInt8 * buffer_iter;

   buffer_iter = (CliAuthUInt8 *)buffer;

   while (elements != CLIAUTH_LITERAL_UINT32(0u)) {
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

static void
cliauth_memory_fill_libc(
   void * buffer,
   const void * sentinel,
   CliAuthUInt32 elements,
   CliAuthUInt32 bytes_per_element
) {
#if CLIAUTH_IMPORTS_USE_C_MEMSET
   CliAuthUInt8 * buffer_iter;
   CliAuthUInt8 byte;

   if (bytes_per_element != CLIAUTH_LITERAL_UINT32(1u)) {
      cliauth_memory_fill_fallback(buffer, sentinel, elements, bytes_per_element);
      return;
   }

   buffer_iter = (CliAuthUInt8 *)buffer;
   byte = *((const CliAuthUInt8 *)(sentinel));

#if CLIAUTH_MEMORY_LIBC_SIZE_T_IS_SMALL
   while (elements > CLIAUTH_LITERAL_UINT32(CLIAUTH_MEMORY_LIBC_SIZE_T_MAX)) {
      (void)memset(
         buffer_iter,
         byte,
         CLIAUTH_MEMORY_LIBC_SIZE_T_MAX
      );

      buffer_iter += CLIAUTH_MEMORY_LIBC_SIZE_T_MAX;
      elements -= CLIAUTH_LITERAL_UINT32(CLIAUTH_MEMORY_LIBC_SIZE_T_MAX);
   }
#endif /* CLIAUTH_MEMORY_LIBC_SIZE_T_IS_SMALL */

   (void)memset(
      buffer_iter,
      byte,
      (size_t)elements
   );
#else /* CLIAUTH_IMPORTS_USE_C_MEMSET */
   (void)buffer;
   (void)sentinel;
   (void)elements;
   (void)bytes_per_element;
#endif /* CLIAUTH_IMPORTS_USE_C_MEMSET */

   return;
}

void
cliauth_memory_fill(
   void * buffer,
   const void * sentinel,
   CliAuthUInt32 elements,
   CliAuthUInt32 bytes_per_element
) {
#if CLIAUTH_IMPORTS_USE_C_MEMSET
   cliauth_memory_fill_libc(buffer, sentinel, elements, bytes_per_element);
#else /* CLIAUTH_IMPORTS_USE_C_MEMSET */
   (void)cliauth_memory_fill_libc;
   cliauth_memory_fill_fallback(buffer, sentinel, elements, bytes_per_element);
#endif /* CLIAUTH_IMPORTS_USE_C_MEMSET */

   return;
}

static CliAuthBoolean
cliauth_memory_compare_fallback(
   const void * data_lhs,
   const void * data_rhs,
   CliAuthUInt32 bytes
) {
   const CliAuthUInt8 * data_lhs_iter;
   const CliAuthUInt8 * data_rhs_iter;

   data_lhs_iter = (const CliAuthUInt8 *)data_lhs;
   data_rhs_iter = (const CliAuthUInt8 *)data_rhs;

   while (bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      if (*data_lhs_iter != *data_rhs_iter) {
         return CLIAUTH_BOOLEAN_FALSE;
      }

      data_lhs_iter++;
      data_rhs_iter++;
      bytes--;
   }

   return CLIAUTH_BOOLEAN_TRUE;
}

static CliAuthBoolean
cliauth_memory_compare_libc(
   const void * data_lhs,
   const void * data_rhs,
   CliAuthUInt32 bytes
) {
   CliAuthBoolean retn;

#if CLIAUTH_IMPORTS_USE_C_MEMCMP
   const CliAuthUInt8 * data_lhs_iter;
   const CliAuthUInt8 * data_rhs_iter;

   data_lhs_iter = (const CliAuthUInt8 *)data_lhs;
   data_rhs_iter = (const CliAuthUInt8 *)data_rhs;

#if CLIAUTH_MEMORY_LIBC_SIZE_T_IS_SMALL
   while (bytes > CLIAUTH_LITERAL_UINT32(CLIAUTH_MEMORY_LIBC_SIZE_T_MAX)) {
      if (memcmp(
         data_lhs_iter,
         data_rhs_iter,
         CLIAUTH_MEMORY_LIBC_SIZE_T_MAX
      ) != 0) {
         return CLIAUTH_BOOLEAN_FALSE;
      }

      data_lhs_iter += CLIAUTH_MEMORY_LIBC_SIZE_T_MAX;
      data_rhs_iter += CLIAUTH_MEMORY_LIBC_SIZE_T_MAX;
      bytes -= CLIAUTH_LITERAL_UINT32(CLIAUTH_MEMORY_LIBC_SIZE_T_MAX;
   }
#endif /* CLIAUTH_MEMORY_LIBC_SIZE_T_IS_SMALL */

   if (memcmp(
      data_lhs_iter,
      data_rhs_iter,
      (size_t)bytes
   ) != 0) {
      return CLIAUTH_BOOLEAN_FALSE;
   }

   retn = CLIAUTH_BOOLEAN_TRUE;
#else /* CLIAUTH_IMPORTS_USE_C_MEMCMP */
   (void)data_lhs;
   (void)data_rhs;
   (void)bytes;
   retn = CLIAUTH_BOOLEAN_FALSE;
#endif /* CLIAUTH_IMPORTS_USE_C_MEMCMP */

   return retn;
}

CliAuthBoolean
cliauth_memory_compare(
   const void * data_lhs,
   const void * data_rhs,
   CliAuthUInt32 bytes_lhs,
   CliAuthUInt32 bytes_rhs
) {
   CliAuthBoolean retn;

   if (bytes_lhs != bytes_rhs) {
      return CLIAUTH_BOOLEAN_FALSE;
   }

#if CLIAUTH_IMPORTS_USE_C_MEMCMP
   (void)cliauth_memory_compare_fallback;
   retn = cliauth_memory_compare_libc(data_lhs, data_rhs, bytes_lhs);
#else /* CLIAUTH_IMPORTS_USE_C_MEMCMP */
   (void)cliauth_memory_compare_libc;
   retn = cliauth_memory_compare_fallback(data_lhs, data_rhs, bytes_lhs);
#endif /* CLIAUTH_IMPORTS_USE_C_MEMCMP */

   return retn;
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
   position = CLIAUTH_LITERAL_UINT32(0u);

   while (elements != CLIAUTH_LITERAL_UINT32(0u)) {
      if (cliauth_memory_compare(
         data_iter,
         sentinel,
         bytes_per_element,
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

