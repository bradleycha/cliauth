/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/mac.c - Message authentication code (MAC) algorithm implementations.   */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "mac.h"

#include <string.h>
#include "hash.h"
#include "io.h"

#define CLIAUTH_MAC_HMAC_IPAD 0x36
#define CLIAUTH_MAC_HMAC_OPAD 0x5c

static void
cliauth_mac_hmac_calculate_k0_ipad_length_equal(
   const void * key,
   void * key_buffer,
   CliAuthUInt32 key_bytes
) {
   const CliAuthUInt8 * key_iter;
   CliAuthUInt8 * key_buffer_iter;

   key_iter = (const CliAuthUInt8 *)key;
   key_buffer_iter = (CliAuthUInt8 *)key_buffer;

   while (key_bytes != 0) {
      *key_buffer_iter = *key_iter ^ CLIAUTH_MAC_HMAC_IPAD;

      key_iter++;
      key_buffer_iter++;
      key_bytes--;
   }

   return;
}

static void
cliauth_mac_hmac_calculate_k0_ipad_length_smaller(
   const void * key,
   void * key_buffer,
   CliAuthUInt32 key_bytes,
   CliAuthUInt32 block_bytes
) {
   const CliAuthUInt8 * key_iter;
   CliAuthUInt8 * key_buffer_iter;
   CliAuthUInt32 pad_bytes;

   key_iter = (const CliAuthUInt8 *)key;
   key_buffer_iter = (CliAuthUInt8 *)key_buffer;
   pad_bytes = block_bytes - key_bytes;

   while (key_bytes != 0) {
      *key_buffer_iter = *key_iter ^ CLIAUTH_MAC_HMAC_IPAD;

      key_iter++;
      key_buffer_iter++;
      key_bytes--;
   }

   (void)memset(key_buffer_iter, CLIAUTH_MAC_HMAC_IPAD, pad_bytes);

   return;
}

static void
cliauth_mac_hmac_calculate_k0_ipad_length_larger(
   const void * key,
   void * key_buffer,
   CliAuthUInt32 key_bytes,
   CliAuthUInt32 block_bytes,
   CliAuthUInt32 digest_bytes,
   const struct CliAuthHashFunction * hash_function,
   void * hash_context
) {
   struct CliAuthIoByteStreamReader byte_stream_reader;
   struct CliAuthIoReader reader;
   CliAuthUInt32 remaining_bytes;
   void * hash_digest;
   CliAuthUInt8 * key_buffer_iter;
   CliAuthUInt32 pad_bytes;

   byte_stream_reader.bytes = key;
   byte_stream_reader.length = key_bytes;
   byte_stream_reader.position = 0;
   reader = cliauth_io_byte_stream_reader_interface(&byte_stream_reader);

   hash_function->initialize(hash_context);

   (void)hash_function->digest(
      hash_context,
      &remaining_bytes,
      &reader,
      key_bytes
   );

   hash_digest = hash_function->finalize(hash_context);
   (void)memcpy(key_buffer, hash_digest, digest_bytes);

   key_buffer_iter = (CliAuthUInt8 *)key_buffer;
   pad_bytes = block_bytes - digest_bytes;

   while (digest_bytes != 0) {
      *key_buffer_iter ^= CLIAUTH_MAC_HMAC_IPAD;

      key_buffer_iter++;
      digest_bytes--;
   }

   (void)memset(key_buffer_iter, CLIAUTH_MAC_HMAC_IPAD, pad_bytes);

   return;
}

static void
cliauth_mac_hmac_calculate_k0_opad_from_k0_ipad(
   void * key_buffer,
   CliAuthUInt32 block_bytes
) {
   CliAuthUInt8 * key_buffer_iter;

   key_buffer_iter = (CliAuthUInt8 *)key_buffer;

   while (block_bytes != 0) {
      /* additional xor to undo the previous ipad xor */
      *key_buffer_iter ^= (CLIAUTH_MAC_HMAC_IPAD ^ CLIAUTH_MAC_HMAC_OPAD);

      key_buffer_iter++;
      block_bytes--;
   }

   return;
}

void
cliauth_mac_hmac(
   const struct CliAuthHashFunction * hash_function,
   void * hash_context,
   const void * message,
   const void * key,
   void * digest,
   void * key_buffer,
   CliAuthUInt32 message_bytes,
   CliAuthUInt32 key_bytes,
   CliAuthUInt32 block_bytes,
   CliAuthUInt32 digest_bytes
) {
   struct CliAuthIoByteStreamReader byte_stream_reader;
   struct CliAuthIoReader reader;
   CliAuthUInt32 remaining_bytes;
   void * hash_digest;

   reader = cliauth_io_byte_stream_reader_interface(&byte_stream_reader);

   /* calculate K0 ^ ipad */
   if (key_bytes == block_bytes) {
      cliauth_mac_hmac_calculate_k0_ipad_length_equal(
         key,
         key_buffer,
         key_bytes
      );
   }
   if (key_bytes < block_bytes) {
      cliauth_mac_hmac_calculate_k0_ipad_length_smaller(
         key,
         key_buffer,
         key_bytes,
         block_bytes
      );
   }
   if (key_bytes > block_bytes) {
      cliauth_mac_hmac_calculate_k0_ipad_length_larger(
         key,
         key_buffer,
         key_bytes,
         block_bytes,
         digest_bytes,
         hash_function,
         hash_context
      );
   }

   /* calculate H((K0 ^ ipad) || message), store in 'digest' */ 
   hash_function->initialize(hash_context);

   byte_stream_reader.bytes = key_buffer;
   byte_stream_reader.length = block_bytes;
   byte_stream_reader.position = 0;
   (void)hash_function->digest(
      hash_context,
      &remaining_bytes,
      &reader,
      block_bytes
   );

   byte_stream_reader.bytes = message;
   byte_stream_reader.length = message_bytes;
   byte_stream_reader.position = 0;
   (void)hash_function->digest(
      hash_context,
      &remaining_bytes,
      &reader,
      message_bytes
   );

   hash_digest = hash_function->finalize(hash_context);
   (void)memcpy(digest, hash_digest, digest_bytes);

   /* calculate K0 ^ opad from K0 ^ ipad*/
   cliauth_mac_hmac_calculate_k0_opad_from_k0_ipad(
      key_buffer,
      block_bytes
   );

   /* calculate H((K0 ^ opad) || H((K0 ^ ipad) || text)) */
   /* store the final HMAC result in 'digest' */
   hash_function->initialize(hash_context);

   byte_stream_reader.bytes = key_buffer;
   byte_stream_reader.length = block_bytes;
   byte_stream_reader.position = 0;
   (void)hash_function->digest(
      hash_context,
      &remaining_bytes,
      &reader,
      block_bytes
   );

   byte_stream_reader.bytes = digest;
   byte_stream_reader.length = digest_bytes;
   byte_stream_reader.position = 0;
   (void)hash_function->digest(
      hash_context,
      &remaining_bytes,
      &reader,
      digest_bytes
   );

   hash_digest = hash_function->finalize(hash_context);
   (void)memcpy(digest, hash_digest, digest_bytes);
   
   return;
}

