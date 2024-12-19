/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/crypto/mac.c - Message authentication code (MAC) algorithm             */
/*                    implementations.                                        */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "crypto/mac.h"

#include "memory/memory.h"
#include "crypto/hash.h"
#include "io/io.h"
#include "io/byte_array_mapper.h"
#include "io/mapper_stream.h"

#define CLIAUTH_CRYPTO_MAC_HMAC_IPAD 0x36u
#define CLIAUTH_CRYPTO_MAC_HMAC_OPAD 0x5cu

void
cliauth_crypto_mac_hmac_initialize(
   struct CliAuthCryptoMacHmacContext * context,
   const struct CliAuthCryptoHashFunction * hash_function
) {
   context->hash_function = hash_function;
   context->k0_capacity = hash_function->input_block_length;
   context->k0_hash_initiated = CLIAUTH_BOOLEAN_FALSE;

   return;
}

static struct CliAuthIoResult
cliauth_crypto_mac_hmac_key_digest_hash(
   struct CliAuthCryptoMacHmacContext * context,
   const struct CliAuthIoStreamReader * key_reader,
   CliAuthUInt32 key_bytes
) {
   struct CliAuthIoResult read_result;

   read_result = context->hash_function->digest(
      &context->hash_context,
      key_reader,
      key_bytes
   );
   
   return read_result;
}

static struct CliAuthIoResult
cliauth_crypto_mac_hmac_key_digest_rollover(
   struct CliAuthCryptoMacHmacContext * context,
   const struct CliAuthIoStreamReader * key_reader,
   CliAuthUInt32 key_bytes
) {
   struct CliAuthIoResult read_result;
   CliAuthUInt8 * buffer_free;
   CliAuthUInt8 key_bytes_residual;
   struct CliAuthIoByteArrayMapperReader buffer_byte_array_mapper_reader;
   struct CliAuthIoMapperReader buffer_mapper_reader;
   struct CliAuthIoMapperStreamReader buffer_mapper_stream_reader;
   struct CliAuthIoStreamReader buffer_stream_reader;
   CliAuthUInt8 input_block_length;

   input_block_length = context->hash_function->input_block_length;

   buffer_free = &context->k0_buffer[input_block_length - context->k0_capacity];

   /* calculate the number of residual bytes to digest after filling the k0 */
   /* buffer */
   key_bytes_residual = key_bytes - context->k0_capacity;

   /* attempt to read enough bytes to fill the k0 buffer.  this is done */
   /* seperately in the case of an IO error */
   read_result = cliauth_io_stream_reader_read(
      key_reader,
      buffer_free,
      context->k0_capacity
   );
   context->k0_capacity -= read_result.bytes;
   
   if (read_result.status != CLIAUTH_IO_STATUS_SUCCESS) {
      return read_result;
   }

   /* initialize the hash context */
   context->hash_function->initialize(&context->hash_context);

   /* digest the k0 buffer into the hash function */
   buffer_mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &buffer_byte_array_mapper_reader
   );
   buffer_stream_reader = cliauth_io_mapper_stream_reader_interface(
      &buffer_mapper_stream_reader
   );

   cliauth_io_byte_array_mapper_reader_initialize(
      &buffer_byte_array_mapper_reader,
      context->k0_buffer
   );
   cliauth_io_mapper_stream_reader_initialize(
      &buffer_mapper_stream_reader,
      &buffer_mapper_reader,
      input_block_length,
      CLIAUTH_LITERAL_UINT32(0u)
   );

   /* always returns success, so we discard the read result */
   (void)context->hash_function->digest(
      &context->hash_context,
      &buffer_stream_reader,
      input_block_length
   );

   /* digest the rest of the key */
   read_result = context->hash_function->digest(
      &context->hash_context,
      key_reader,
      key_bytes_residual
   );

   /* if more than zero bytes were digested, mark hashing as initiated */
   /* this prevents a corner-case where we could fail to read the remainder */
   /* key bytes, and then the caller finalizes the key hash as-is. */
   /* without this, key length == block length but we initiated hashing. */
   if (read_result.bytes != CLIAUTH_LITERAL_UINT32(0u)) {
      context->k0_hash_initiated = CLIAUTH_BOOLEAN_TRUE;
   }

   /* make sure to include all of the digested key */
   read_result.bytes += (key_bytes - key_bytes_residual);
   
   /* any IO error can now be safely handled by the caller */
   return read_result;
}

static struct CliAuthIoResult
cliauth_crypto_mac_hmac_key_digest_append(
   struct CliAuthCryptoMacHmacContext * context,
   const struct CliAuthIoStreamReader * key_reader,
   CliAuthUInt32 key_bytes
) {
   struct CliAuthIoResult read_result;
   CliAuthUInt8 * buffer_free;
   CliAuthUInt8 input_block_length;

   input_block_length = context->hash_function->input_block_length;

   buffer_free = &context->k0_buffer[input_block_length - context->k0_capacity];

   read_result = cliauth_io_stream_reader_read(
      key_reader,
      buffer_free,
      key_bytes
   );

   context->k0_capacity -= read_result.bytes;
   
   return read_result;
}

struct CliAuthIoResult
cliauth_crypto_mac_hmac_key_digest(
   struct CliAuthCryptoMacHmacContext * context,
   const struct CliAuthIoStreamReader * key_reader,
   CliAuthUInt32 key_bytes
) {
   /* case 1: the key length already exceeded the maximum capacity of the  */
   /* k0 buffer */
   if (context->k0_hash_initiated == CLIAUTH_BOOLEAN_TRUE) {
      return cliauth_crypto_mac_hmac_key_digest_hash(
         context,
         key_reader,
         key_bytes
      );
   }

   /* case 2: the key will exceed the maximum capacity of the k0 buffer */
   /* after appending the current key bytes */
   if (key_bytes > context->k0_capacity) {
      return cliauth_crypto_mac_hmac_key_digest_rollover(
         context,
         key_reader,
         key_bytes
      );
   }

   /* case 3: the key will not exceed the maximum capacity of the k0 buffer */
   /* after appending the current key bytes */
   return cliauth_crypto_mac_hmac_key_digest_append(
      context,
      key_reader,
      key_bytes
   );
}

void
cliauth_crypto_mac_hmac_key_finalize(
   struct CliAuthCryptoMacHmacContext * context
) {
   CliAuthUInt8 * message_source;
   CliAuthUInt8 * message_dest;
   CliAuthUInt8 message_bytes;
   CliAuthUInt8 * pad_ptr;
   CliAuthUInt8 pad_bytes;
   struct CliAuthIoByteArrayMapperReader k0_byte_array_mapper_reader;
   struct CliAuthIoMapperReader k0_mapper_reader;
   struct CliAuthIoMapperStreamReader k0_mapper_stream_reader;
   struct CliAuthIoStreamReader k0_stream_reader;
   CliAuthUInt8 ipad_constant;
   CliAuthUInt8 input_block_length;
   CliAuthUInt8 digest_length;

   input_block_length = context->hash_function->input_block_length;
   digest_length = context->hash_function->digest_length;

   /* set the message source and pad pointers depending on if we hashed k0 or */
   /* not */
   if (context->k0_hash_initiated == CLIAUTH_BOOLEAN_TRUE) {
      message_source = context->hash_function->finalize(&context->hash_context);
      message_bytes = digest_length;

      pad_ptr = &context->k0_buffer[digest_length];
      pad_bytes = input_block_length - digest_length;
   } else {
      message_source = context->k0_buffer;
      message_bytes = input_block_length - context->k0_capacity;

      pad_ptr = &context->k0_buffer[input_block_length - context->k0_capacity];
      pad_bytes = context->k0_capacity;
   }

   /* copy and xor the message (non-padded) portion of k0 */
   message_dest = context->k0_buffer;
   while (message_bytes != CLIAUTH_LITERAL_UINT8(0u)) {
      *message_dest = *message_source ^ CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_MAC_HMAC_IPAD);

      message_source++;
      message_dest++;
      message_bytes--;
   }

   /* pad any remainder bytes with ipad */
   ipad_constant = CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_MAC_HMAC_IPAD);
   cliauth_memory_fill(
      pad_ptr,
      &ipad_constant,
      pad_bytes,
      CLIAUTH_LITERAL_UINT32(1u)
   );

   /* re-initialize the hash context and digest k0 ^ ipad to prepare for */
   /* digestion and appending of the message */
   context->hash_function->initialize(&context->hash_context);

   k0_mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &k0_byte_array_mapper_reader
   );
   k0_stream_reader = cliauth_io_mapper_stream_reader_interface(
      &k0_mapper_stream_reader
   );

   cliauth_io_byte_array_mapper_reader_initialize(
      &k0_byte_array_mapper_reader,
      context->k0_buffer
   );
   cliauth_io_mapper_stream_reader_initialize(
      &k0_mapper_stream_reader,
      &k0_mapper_reader,
      input_block_length,
      CLIAUTH_LITERAL_UINT32(0u)
   );

   /* always returns success, so we discard the read result */
   (void)context->hash_function->digest(
      &context->hash_context,
      &k0_stream_reader,
      input_block_length
   );

   return;
}

struct CliAuthIoResult
cliauth_crypto_mac_hmac_message_digest(
   struct CliAuthCryptoMacHmacContext * context,
   const struct CliAuthIoStreamReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   return context->hash_function->digest(
      &context->hash_context,
      message_reader,
      message_bytes
   );
}

CliAuthUInt8 *
cliauth_crypto_mac_hmac_finalize(
   struct CliAuthCryptoMacHmacContext * context
) {
   CliAuthUInt8 * digest;
   CliAuthUInt8 * k0_opad_iter;
   CliAuthUInt8 k0_opad_bytes;
   struct CliAuthIoByteArrayMapperReader byte_array_mapper_reader;
   struct CliAuthIoMapperReader mapper_reader;
   struct CliAuthIoMapperStreamReader mapper_stream_reader;
   struct CliAuthIoStreamReader stream_reader;
   CliAuthUInt8 input_block_length;
   CliAuthUInt8 digest_length;

   input_block_length = context->hash_function->input_block_length;
   digest_length = context->hash_function->digest_length;

   /* finalize the hash value H((K0 ^ ipad) || text) and store in the digest */
   /* buffer */
   digest = context->hash_function->finalize(&context->hash_context);
   cliauth_memory_copy(
      context->digest_buffer,
      digest,
      digest_length
   );

   /* calculate k0 ^ opad */
   k0_opad_iter = context->k0_buffer;
   k0_opad_bytes = input_block_length;
   while (k0_opad_bytes != CLIAUTH_LITERAL_UINT8(0u)) {
      /* combined xors to undo ipad's xor in a single load/store */
      *k0_opad_iter ^= CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_MAC_HMAC_OPAD ^ CLIAUTH_CRYPTO_MAC_HMAC_IPAD);

      k0_opad_iter++;
      k0_opad_bytes--;
   }

   /* calculate H((k0 ^ opad) || H((k0 ^ ipad) || message)) */
   context->hash_function->initialize(&context->hash_context);

   mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &byte_array_mapper_reader
   );
   stream_reader = cliauth_io_mapper_stream_reader_interface(
      &mapper_stream_reader
   );

   cliauth_io_byte_array_mapper_reader_initialize(
      &byte_array_mapper_reader,
      context->k0_buffer
   );
   cliauth_io_mapper_stream_reader_initialize(
      &mapper_stream_reader,
      &mapper_reader,
      input_block_length,
      CLIAUTH_LITERAL_UINT32(0u)
   );

   /* always returns success, so we discard the read result */
   (void)context->hash_function->digest(
      &context->hash_context,
      &stream_reader,
      input_block_length
   );

   cliauth_io_byte_array_mapper_reader_initialize(
      &byte_array_mapper_reader,
      context->digest_buffer
   );
   cliauth_io_mapper_stream_reader_initialize(
      &mapper_stream_reader,
      &mapper_reader,
      digest_length,
      CLIAUTH_LITERAL_UINT32(0u)
   );

   /* always returns success, so we discard the read result */
   (void)context->hash_function->digest(
      &context->hash_context,
      &stream_reader,
      digest_length
   );

   digest = context->hash_function->finalize(&context->hash_context);

   return digest;
}

