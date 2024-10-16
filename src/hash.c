/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/hash.c - Hash algorithm implementations                                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "hash.h"

#include "memory.h"
#include "endian.h"
#include "bitwise.h"
#include "io.h"

#if _CLIAUTH_HASH_SHA1_2
/*----------------------------------------------------------------------------*/

typedef void (*CliAuthHashSha12RingBufferDigestBlock)(
   struct CliAuthHashContext * hash_context,
   const CliAuthUInt8 block []
);

/* used to implement the ring buffer interface on a hash function at */
/* compile-time */
struct CliAuthHashSha12RingBufferImplementation {
   /* digests an input block when the ring buffer is filled */
   CliAuthHashSha12RingBufferDigestBlock digest;

   /* the size of the ring buffer and each input block in bytes */
   CliAuthUInt32 bytes;
};

/* initializes the state of the ring buffer */
static void
cliauth_hash_sha1_2_ring_buffer_initialize(
   const struct CliAuthHashSha12RingBufferImplementation * implementation,
   struct _CliAuthHashSha12RingBufferContext * context
) {
   context->capacity = implementation->bytes;
   context->total = CLIAUTH_LITERAL_UINT32(0u);

   return;
}

/* loads a message into the ring buffer, digesting if the ring buffer fills */
static struct CliAuthIoReadResult
cliauth_hash_sha1_2_ring_buffer_digest(
   const struct CliAuthHashSha12RingBufferImplementation * implementation,
   struct _CliAuthHashSha12RingBufferContext * context,
   struct CliAuthHashContext * hash_context,
   CliAuthUInt8 buffer [],
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   struct CliAuthIoReadResult read_result;
   CliAuthUInt8 * ring_buffer_free;
   CliAuthUInt32 digest_blocks;
   CliAuthUInt32 digest_bytes;
   CliAuthUInt32 remainder_bytes;

   /* calculate a pointer to the start of free space in the ring buffer */
   ring_buffer_free = buffer + (implementation->bytes - context->capacity);

   /* if the number of bytes to insert is less than the remaining capacity, */
   /* simply copy them in and return */
   if (message_bytes < context->capacity) {
      read_result = cliauth_io_reader_read_all(
         message_reader,
         ring_buffer_free,
         message_bytes
      );

      context->capacity -= read_result.bytes;
      context->total += read_result.bytes;

      /* read_result will be set to the final output since we only do a */
      /* single read operation in this case */
      return read_result;
   }
   
   /* initialize the number of digested bytes */
   digest_bytes = CLIAUTH_LITERAL_UINT32(0u);

   /* calculate the number of full blocks and residual bytes after filling */
   /* the ring buffer */
   digest_blocks = (message_bytes - context->capacity) / implementation->bytes;
   remainder_bytes = (message_bytes - context->capacity) % implementation->bytes;

   /* populate and digest the ring buffer */
   read_result = cliauth_io_reader_read_all(
      message_reader,
      ring_buffer_free,
      context->capacity
   );
   digest_bytes += read_result.bytes;
   context->total += read_result.bytes;

   if (read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
      context->capacity = implementation->bytes - read_result.bytes;
      read_result.bytes = digest_bytes;
      return read_result;
   }

   implementation->digest(hash_context, buffer);

   /* digest the full blocks, using the ring buffer as a read buffer */
   while (digest_blocks != 0) {
      read_result = cliauth_io_reader_read_all(
         message_reader,
         buffer,
         implementation->bytes
      );
      digest_bytes += read_result.bytes;
      context->total += read_result.bytes;

      if (read_result.status != CLIAUTH_IO_READ_STATUS_SUCCESS) {
         context->capacity = implementation->bytes - read_result.bytes;
         read_result.bytes = digest_bytes;
         return read_result;
      }

      digest_blocks--;
   }

   /* copy the remainder bytes into the ring buffer, note that we don't */
   /* update remaining_bytes because the function will never fail after this */
   /* final read. */
   read_result = cliauth_io_reader_read_all(
      message_reader,
      buffer,
      remainder_bytes
   );
   digest_bytes += read_result.bytes;
   context->total += read_result.bytes;

   /* since there's no additional work, we set these values no matter the */
   /* read status */
   context->capacity = implementation->bytes - read_result.bytes;
   read_result.bytes = digest_bytes;
   return read_result;
}

/* performs the SHA message padding step on remaining data and digests the */
/* resulting padded message.  this also invalidates the state of the ring */
/* buffer, which will require initialization to be used again. */
static void
cliauth_hash_sha1_2_ring_buffer_finalize(
   const struct CliAuthHashSha12RingBufferImplementation * implementation,
   struct _CliAuthHashSha12RingBufferContext * context,
   struct CliAuthHashContext * hash_context,
   CliAuthUInt8 buffer []
) {
   CliAuthUInt8 * ring_buffer_iter;
   CliAuthUInt8 zero_pad_bytes;
   CliAuthUInt64 message_length_bits_big_endian;
   CliAuthUInt8 zero_pad_sentinel;

   /* initialize the zero sentinel value used for padding */
   zero_pad_sentinel = 0x00;

   /* initialize iterator to the start of free space */
   ring_buffer_iter = buffer + (implementation->bytes - context->capacity);

   /* append the leading 1 bit.  this will always be valid since the ring */
   /* buffer can never be in a full state */
   *ring_buffer_iter = (1 << 7);
   ring_buffer_iter += 1;

   /* calculate the number of zeroes to pad with */
   zero_pad_bytes = (
      implementation->bytes
      - CLIAUTH_LITERAL_UINT32(1u)
      - CLIAUTH_LITERAL_UINT32(sizeof(message_length_bits_big_endian))
      + context->capacity
   ) % implementation->bytes;

   /* if the amount of pad bytes will require a new block, fill the ring */
   /* buffer and digest with as many zeroes as will fit and then fill the */
   /* next block with zeroes */
   if (zero_pad_bytes > context->capacity - CLIAUTH_LITERAL_UINT32(1u)) {
      cliauth_memory_fill(
         ring_buffer_iter,
         &zero_pad_sentinel,
         context->capacity - CLIAUTH_LITERAL_UINT32(1u),
         CLIAUTH_LITERAL_UINT32(1u)
      );
      ring_buffer_iter = buffer;
      zero_pad_bytes -= context->capacity - CLIAUTH_LITERAL_UINT32(1u);

      implementation->digest(hash_context, buffer);
   }

   /* write the remaining pad zeroes */
   cliauth_memory_fill(
      ring_buffer_iter,
      &zero_pad_sentinel,
      zero_pad_bytes,
      CLIAUTH_LITERAL_UINT32(1u)
   );
   ring_buffer_iter += zero_pad_bytes;

   /* calculate the message length in bits, convert to big endian, and append */
   /* to the end of the message */
   message_length_bits_big_endian = cliauth_endian_convert_uint64(
      context->total * CLIAUTH_LITERAL_UINT32(8u),
      CLIAUTH_ENDIAN_TARGET_BIG
   );
   cliauth_memory_copy(
      ring_buffer_iter,
      &message_length_bits_big_endian,
      CLIAUTH_LITERAL_UINT32(sizeof(message_length_bits_big_endian))
   );
   ring_buffer_iter += CLIAUTH_LITERAL_UINT32(sizeof(message_length_bits_big_endian));

   /* digest the final block */
   implementation->digest(hash_context, buffer);

   return;
}

static void
cliauth_hash_sha1_2_load_message_block_big(
   const CliAuthUInt8 block [],
   CliAuthUInt8 schedule [],
   CliAuthUInt8 block_bytes,
   CliAuthUInt8 schedule_bytes_per_word
) {
   (void)schedule_bytes_per_word;
   cliauth_memory_copy(
      schedule,
      block,
      block_bytes
   );

   return;
}

static void
cliauth_hash_sha1_2_load_message_block_little(
   const CliAuthUInt8 block [],
   CliAuthUInt8 schedule [],
   CliAuthUInt8 block_bytes,
   CliAuthUInt8 schedule_bytes_per_word
) {
   const CliAuthUInt8 * block_iter;
   CliAuthUInt8 * schedule_iter;

   block_iter = block;
   schedule_iter = schedule;
   while (block_bytes != CLIAUTH_LITERAL_UINT8(0u)) {
      cliauth_endian_convert_copy(
         schedule_iter,
         block_iter,
         schedule_bytes_per_word,
         CLIAUTH_ENDIAN_TARGET_BIG
      );

      block_iter += schedule_bytes_per_word;
      schedule_iter += schedule_bytes_per_word;
      block_bytes -= schedule_bytes_per_word;
   }

   return;
}

/* loads the initial part of the message schedule from the input block */
static void
cliauth_hash_sha1_2_load_message_block(
   const CliAuthUInt8 block [],
   CliAuthUInt8 schedule [],
   CliAuthUInt8 block_bytes,
   CliAuthUInt8 schedule_bytes_per_word
) {
#if CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE
   (void)cliauth_hash_sha1_2_load_message_block_little;
   cliauth_hash_sha1_2_load_message_block_big(
      block,
      schedule,
      block_bytes,
      schedule_bytes_per_word
   );
#else /* CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE */
   (void)cliauth_hash_sha1_2_load_message_block_big;
   cliauth_hash_sha1_2_load_message_block_little(
      block,
      schedule,
      block_bytes,
      schedule_bytes_per_word
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE */

   return;
}

static void
cliauth_hash_sha1_2_digest_endianess_finalize_big(
   CliAuthUInt8 digest [],
   CliAuthUInt8 digest_bytes_per_word,
   CliAuthUInt8 digest_words
) {
   (void)digest;
   (void)digest_bytes_per_word;
   (void)digest_words;
   return;
}

static void
cliauth_hash_sha1_2_digest_endianess_finalize_little(
   CliAuthUInt8 digest [],
   CliAuthUInt8 digest_bytes_per_word,
   CliAuthUInt8 digest_words
) {
   CliAuthUInt8 * digest_iter;

   digest_iter = digest;
   while (digest_words != CLIAUTH_LITERAL_UINT8(0u)) {
      cliauth_endian_convert_inplace(
         digest_iter,
         digest_bytes_per_word,
         CLIAUTH_ENDIAN_TARGET_BIG
      );
      
      digest_iter += digest_bytes_per_word;
      digest_words--;
   }

   return;
}

/* flips the endianess of a final digest to big-endian */
static void
cliauth_hash_sha1_2_digest_endianess_finalize(
   CliAuthUInt8 digest [],
   CliAuthUInt8 digest_bytes_per_word,
   CliAuthUInt8 digest_words
) {
#if CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE
   (void)cliauth_hash_sha1_2_digest_endianess_finalize_little;
   cliauth_hash_sha1_2_digest_endianess_finalize_big(
      digest,
      digest_bytes_per_word,
      digest_words
   );
#else /* CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE */
   (void)cliauth_hash_sha1_2_digest_endianess_finalize_big;
   cliauth_hash_sha1_2_digest_endianess_finalize_little(
      digest,
      digest_bytes_per_word,
      digest_words
   );
#endif /* CLIAUTH_CONFIG_PLATFORM_ENDIAN_IS_BE */

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA1_2 */

#if _CLIAUTH_HASH_SHA1_2_32
/*----------------------------------------------------------------------------*/

static CliAuthUInt32
cliauth_hash_sha1_2_32_ch(CliAuthUInt32 x, CliAuthUInt32 y, CliAuthUInt32 z) {
   return ((x & y) ^ ((~x) & z));
}

static CliAuthUInt32
cliauth_hash_sha1_2_32_maj(CliAuthUInt32 x, CliAuthUInt32 y, CliAuthUInt32 z) {
   return ((x & y) ^ (x & z) ^ (y & z));
}

static CliAuthUInt32
cliauth_hash_sha1_2_32_parity(CliAuthUInt32 x, CliAuthUInt32 y, CliAuthUInt32 z) {
   return (x ^ y ^ z);
}

static void
cliauth_hash_sha1_2_32_compute_intermediate_digest(
   const CliAuthUInt32 work [],
   CliAuthUInt32 digest [],
   CliAuthUInt8 digest_words_count
) {
   while (digest_words_count != CLIAUTH_LITERAL_UINT8(0u)) {
      *digest += *work;

      digest++;
      work++;
      digest_words_count--;
   }

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA1_2_32 */

#if CLIAUTH_CONFIG_HASH_SHA1
/*----------------------------------------------------------------------------*/

typedef CliAuthUInt32 (*CliAuthHashSha1Function)(CliAuthUInt32 x, CliAuthUInt32 y, CliAuthUInt32 z);

static const CliAuthHashSha1Function
cliauth_hash_sha1_constants_rounds_function [_CLIAUTH_HASH_SHA1_ROUNDS_CONSTANTS_LENGTH] = {
   cliauth_hash_sha1_2_32_ch,
   cliauth_hash_sha1_2_32_parity,
   cliauth_hash_sha1_2_32_maj,
   cliauth_hash_sha1_2_32_parity
};

static const CliAuthUInt32
cliauth_hash_sha1_constants_rounds_value [_CLIAUTH_HASH_SHA1_ROUNDS_CONSTANTS_LENGTH] = {
   CLIAUTH_LITERAL_UINT32(0x5a827999u),
   CLIAUTH_LITERAL_UINT32(0x6ed9eba1u),
   CLIAUTH_LITERAL_UINT32(0x8f1bbcdcu),
   CLIAUTH_LITERAL_UINT32(0xca62c1d6u)
};

static void
cliauth_hash_sha1_create_message_schedule(
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA1_BLOCK_LENGTH],
   union _CliAuthHashContextAlgorithmSha1Schedule * schedule
) {
   CliAuthUInt32 * schedule_iter;
   CliAuthUInt32 a, b, c, d, e;
   CliAuthUInt8 t;

   schedule_iter = schedule->words;

   /* 0 <= t <= 15 */
   cliauth_hash_sha1_2_load_message_block(
      block,
      schedule->bytes,
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA1_BLOCK_LENGTH),
      CLIAUTH_LITERAL_UINT8(sizeof(CliAuthUInt32))
   );
   schedule_iter +=  _CLIAUTH_HASH_SHA1_BLOCK_LENGTH / sizeof(CliAuthUInt32);

   /* 16 <= t <= 79 */
   t = CLIAUTH_LITERAL_UINT8(64u);
   while (t != CLIAUTH_LITERAL_UINT8(0u)) {
      a = schedule_iter[-3];
      b = schedule_iter[-8];
      c = schedule_iter[-14];
      d = schedule_iter[-16];
      e = a ^ b ^ c ^ d;

      *schedule_iter = cliauth_bitwise_rotate_left_uint32(e, CLIAUTH_LITERAL_UINT8(1u));

      schedule_iter++;
      t--;
   }

   return;
}

static void
cliauth_hash_sha1_perform_rounds_and_additions(
   CliAuthUInt32 work [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT],
   const CliAuthUInt32 schedule [_CLIAUTH_HASH_SHA1_MESSAGE_SCHEDULE_LENGTH]
) {
   CliAuthUInt8 t, i, j;
   CliAuthUInt32 a, b, c, d, e;
   CliAuthUInt32 t1;
   const CliAuthUInt32 * schedule_iter;
   const CliAuthHashSha1Function * constants_function_iter;
   const CliAuthUInt32 * constants_value_iter;
   CliAuthUInt32 * work_iter;

   t = CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA1_ROUNDS_COUNT);
   j = CLIAUTH_LITERAL_UINT8(
      _CLIAUTH_HASH_SHA1_ROUNDS_COUNT /
      _CLIAUTH_HASH_SHA1_ROUNDS_CONSTANTS_LENGTH
   );
   schedule_iter = schedule;
   constants_function_iter = cliauth_hash_sha1_constants_rounds_function;
   constants_value_iter = cliauth_hash_sha1_constants_rounds_value;

   while (t != CLIAUTH_LITERAL_UINT8(0u)) {
      if (j == CLIAUTH_LITERAL_UINT8(0u)) {
         j = CLIAUTH_LITERAL_UINT8(
            _CLIAUTH_HASH_SHA1_ROUNDS_COUNT /
            _CLIAUTH_HASH_SHA1_ROUNDS_CONSTANTS_LENGTH
         );
         constants_function_iter++;
         constants_value_iter++;
      }

      a = cliauth_bitwise_rotate_left_uint32(work[0], CLIAUTH_LITERAL_UINT8(5u));
      b = (*constants_function_iter)(work[1], work[2], work[3]);
      c = work[4];
      d = *constants_value_iter;
      e = *schedule_iter;
      t1 = a + b + c + d + e;

      i = CLIAUTH_LITERAL_UINT8(4u);
      work_iter = &work[4];
      while (i != CLIAUTH_LITERAL_UINT8(0u)) {
         *work_iter = work_iter[-1];

         work_iter--;
         i--;
      }

      work[2] = cliauth_bitwise_rotate_left_uint32(work[2], CLIAUTH_LITERAL_UINT8(30u));
      work[0] = t1;

      schedule_iter++;
      t--;
      j--;
   }

   return;
}

static void
cliauth_hash_sha1_digest_block(
   struct CliAuthHashContext * context,
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA1_BLOCK_LENGTH]
) {
   struct _CliAuthHashContextAlgorithmSha1 * context_sha;

   context_sha = &context->algorithm.sha1;

   cliauth_hash_sha1_create_message_schedule(
      block,
      &context_sha->schedule
   );

   cliauth_memory_copy(
      context_sha->work,
      context_sha->digest.words,
      CLIAUTH_LITERAL_UINT32(
         _CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT *
         sizeof(CliAuthUInt32)
      )
   );

   cliauth_hash_sha1_perform_rounds_and_additions(
      context_sha->work,
      context_sha->schedule.words
   );

   cliauth_hash_sha1_2_32_compute_intermediate_digest(
      context_sha->work,
      context_sha->digest.words,
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT)
   );

   return;
}

static const struct CliAuthHashSha12RingBufferImplementation
cliauth_hash_sha1_ring_buffer_implementation = {
   cliauth_hash_sha1_digest_block,
   CLIAUTH_LITERAL_UINT32(_CLIAUTH_HASH_SHA1_BLOCK_LENGTH)
};

static const CliAuthUInt32
cliauth_hash_sha1_constants_initialize [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT] = {
   CLIAUTH_LITERAL_UINT32(0x67452301u),
   CLIAUTH_LITERAL_UINT32(0xefcdab89u),
   CLIAUTH_LITERAL_UINT32(0x98badcfeu),
   CLIAUTH_LITERAL_UINT32(0x10325476u),
   CLIAUTH_LITERAL_UINT32(0xc3d2e1f0u)
};

static void
cliauth_hash_sha1_initialize(struct CliAuthHashContext * context) {
   struct _CliAuthHashContextAlgorithmSha1 * context_sha;

   context_sha = &context->algorithm.sha1;

   cliauth_memory_copy(
      &context_sha->digest,
      cliauth_hash_sha1_constants_initialize,
      CLIAUTH_LITERAL_UINT32(
         _CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT *
         sizeof(CliAuthUInt32)
      )
   );

   cliauth_hash_sha1_2_ring_buffer_initialize(
      &cliauth_hash_sha1_ring_buffer_implementation,
      &context_sha->ring_context
   );

   return;
}

static struct CliAuthIoReadResult
cliauth_hash_sha1_digest(
   struct CliAuthHashContext * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   struct _CliAuthHashContextAlgorithmSha1 * context_sha;

   context_sha = &context->algorithm.sha1;

   return cliauth_hash_sha1_2_ring_buffer_digest(
      &cliauth_hash_sha1_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer,
      message_reader,
      message_bytes
   );
}

static CliAuthUInt8 *
cliauth_hash_sha1_finalize(struct CliAuthHashContext * context) {
   struct _CliAuthHashContextAlgorithmSha1 * context_sha;

   context_sha = &context->algorithm.sha1;

   cliauth_hash_sha1_2_ring_buffer_finalize(
      &cliauth_hash_sha1_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer
   );

   cliauth_hash_sha1_2_digest_endianess_finalize(
      context_sha->digest.bytes,
      CLIAUTH_LITERAL_UINT8(sizeof(CliAuthUInt32)),
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT)
   );

   return context_sha->digest.bytes;
}

static const struct CliAuthHashFunction
cliauth_hash_sha1 = {
   cliauth_hash_sha1_initialize,
   cliauth_hash_sha1_digest,
   cliauth_hash_sha1_finalize,
   CLIAUTH_HASH_SHA1_IDENTIFIER,
   CLIAUTH_LITERAL_UINT32(sizeof(CLIAUTH_HASH_SHA1_IDENTIFIER) / sizeof(char)),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA1_INPUT_BLOCK_LENGTH),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA1_DIGEST_LENGTH)
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */

#if _CLIAUTH_HASH_SHA2_32
/*----------------------------------------------------------------------------*/

static const CliAuthUInt32
cliauth_hash_sha2_32_constants_rounds [_CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT] = {
   CLIAUTH_LITERAL_UINT32(0x428a2f98u),
   CLIAUTH_LITERAL_UINT32(0x71374491u),
   CLIAUTH_LITERAL_UINT32(0xb5c0fbcfu),
   CLIAUTH_LITERAL_UINT32(0xe9b5dba5u),
   CLIAUTH_LITERAL_UINT32(0x3956c25bu),
   CLIAUTH_LITERAL_UINT32(0x59f111f1u),
   CLIAUTH_LITERAL_UINT32(0x923f82a4u),
   CLIAUTH_LITERAL_UINT32(0xab1c5ed5u),
   CLIAUTH_LITERAL_UINT32(0xd807aa98u),
   CLIAUTH_LITERAL_UINT32(0x12835b01u),
   CLIAUTH_LITERAL_UINT32(0x243185beu),
   CLIAUTH_LITERAL_UINT32(0x550c7dc3u),
   CLIAUTH_LITERAL_UINT32(0x72be5d74u),
   CLIAUTH_LITERAL_UINT32(0x80deb1feu),
   CLIAUTH_LITERAL_UINT32(0x9bdc06a7u),
   CLIAUTH_LITERAL_UINT32(0xc19bf174u),
   CLIAUTH_LITERAL_UINT32(0xe49b69c1u),
   CLIAUTH_LITERAL_UINT32(0xefbe4786u),
   CLIAUTH_LITERAL_UINT32(0x0fc19dc6u),
   CLIAUTH_LITERAL_UINT32(0x240ca1ccu),
   CLIAUTH_LITERAL_UINT32(0x2de92c6fu),
   CLIAUTH_LITERAL_UINT32(0x4a7484aau),
   CLIAUTH_LITERAL_UINT32(0x5cb0a9dcu),
   CLIAUTH_LITERAL_UINT32(0x76f988dau),
   CLIAUTH_LITERAL_UINT32(0x983e5152u),
   CLIAUTH_LITERAL_UINT32(0xa831c66du),
   CLIAUTH_LITERAL_UINT32(0xb00327c8u),
   CLIAUTH_LITERAL_UINT32(0xbf597fc7u),
   CLIAUTH_LITERAL_UINT32(0xc6e00bf3u),
   CLIAUTH_LITERAL_UINT32(0xd5a79147u),
   CLIAUTH_LITERAL_UINT32(0x06ca6351u),
   CLIAUTH_LITERAL_UINT32(0x14292967u),
   CLIAUTH_LITERAL_UINT32(0x27b70a85u),
   CLIAUTH_LITERAL_UINT32(0x2e1b2138u),
   CLIAUTH_LITERAL_UINT32(0x4d2c6dfcu),
   CLIAUTH_LITERAL_UINT32(0x53380d13u),
   CLIAUTH_LITERAL_UINT32(0x650a7354u),
   CLIAUTH_LITERAL_UINT32(0x766a0abbu),
   CLIAUTH_LITERAL_UINT32(0x81c2c92eu),
   CLIAUTH_LITERAL_UINT32(0x92722c85u),
   CLIAUTH_LITERAL_UINT32(0xa2bfe8a1u),
   CLIAUTH_LITERAL_UINT32(0xa81a664bu),
   CLIAUTH_LITERAL_UINT32(0xc24b8b70u),
   CLIAUTH_LITERAL_UINT32(0xc76c51a3u),
   CLIAUTH_LITERAL_UINT32(0xd192e819u),
   CLIAUTH_LITERAL_UINT32(0xd6990624u),
   CLIAUTH_LITERAL_UINT32(0xf40e3585u),
   CLIAUTH_LITERAL_UINT32(0x106aa070u),
   CLIAUTH_LITERAL_UINT32(0x19a4c116u),
   CLIAUTH_LITERAL_UINT32(0x1e376c08u),
   CLIAUTH_LITERAL_UINT32(0x2748774cu),
   CLIAUTH_LITERAL_UINT32(0x34b0bcb5u),
   CLIAUTH_LITERAL_UINT32(0x391c0cb3u),
   CLIAUTH_LITERAL_UINT32(0x4ed8aa4au),
   CLIAUTH_LITERAL_UINT32(0x5b9cca4fu),
   CLIAUTH_LITERAL_UINT32(0x682e6ff3u),
   CLIAUTH_LITERAL_UINT32(0x748f82eeu),
   CLIAUTH_LITERAL_UINT32(0x78a5636fu),
   CLIAUTH_LITERAL_UINT32(0x84c87814u),
   CLIAUTH_LITERAL_UINT32(0x8cc70208u),
   CLIAUTH_LITERAL_UINT32(0x90befffau),
   CLIAUTH_LITERAL_UINT32(0xa4506cebu),
   CLIAUTH_LITERAL_UINT32(0xbef9a3f7u),
   CLIAUTH_LITERAL_UINT32(0xc67178f2u)
};

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_u0(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(2u));
   b = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(13u));
   c = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(22u));

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_u1(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(6u));
   b = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(11u));
   c = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(25u));

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_l0(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(7u));
   b = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(18u));
   c = (x >> CLIAUTH_LITERAL_UINT8(3u));

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_l1(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(17u));
   b = cliauth_bitwise_rotate_right_uint32(x, CLIAUTH_LITERAL_UINT8(19u));
   c = (x >> CLIAUTH_LITERAL_UINT8(10u));

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static void
cliauth_hash_sha2_32_create_message_schedule(
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH],
   union _CliAuthHashContextAlgorithmSha232Schedule * schedule
) {
   CliAuthUInt32 * schedule_iter;
   CliAuthUInt32 a, b, c, d;
   CliAuthUInt8 t;

   schedule_iter = schedule->words;

   /* 0 <= t <= 15 */
   cliauth_hash_sha1_2_load_message_block(
      block,
      schedule->bytes,
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH),
      CLIAUTH_LITERAL_UINT8(sizeof(CliAuthUInt32))
   );
   schedule_iter += _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH / sizeof(CliAuthUInt32);

   /* 16 <= t <= 63 */
   t = CLIAUTH_LITERAL_UINT8(48u);
   while (t != CLIAUTH_LITERAL_UINT8(0u)) {
      a = cliauth_hash_sha2_32_sigma_l1(schedule_iter[-2]);
      b = schedule_iter[-7];
      c = cliauth_hash_sha2_32_sigma_l0(schedule_iter[-15]);
      d = schedule_iter[-16];

      *schedule_iter = a + b + c + d;

      schedule_iter++;
      t--;
   }

   return;
}

static void
cliauth_hash_sha2_32_perform_rounds_and_additions(
   CliAuthUInt32 work [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT],
   const CliAuthUInt32 schedule [_CLIAUTH_HASH_SHA2_32_MESSAGE_SCHEDULE_LENGTH]
) {
   CliAuthUInt8 t, i;
   CliAuthUInt32 a, b, c, d, e, f, g;
   CliAuthUInt32 t1, t2;
   const CliAuthUInt32 * schedule_iter;
   const CliAuthUInt32 * constants_iter;
   CliAuthUInt32 * work_iter;

   t = CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT);
   schedule_iter = schedule;
   constants_iter = cliauth_hash_sha2_32_constants_rounds;

   while (t != CLIAUTH_LITERAL_UINT8(0u)) {
      a = work[7];
      b = cliauth_hash_sha2_32_sigma_u1(work[4]);
      c = cliauth_hash_sha1_2_32_ch(work[4], work[5], work[6]);
      d = *constants_iter;
      e = *schedule_iter;
      t1 = a + b + c + d + e;

      f = cliauth_hash_sha2_32_sigma_u0(work[0]);
      g = cliauth_hash_sha1_2_32_maj(work[0], work[1], work[2]);
      t2 = f + g;

      i = CLIAUTH_LITERAL_UINT8(7u);
      work_iter = &work[7];
      while (i != CLIAUTH_LITERAL_UINT8(0u)) {
         *work_iter = work_iter[-1];
         
         work_iter--;
         i--;
      }

      work[4] = work[4] + t1;
      work[0] = t1 + t2;

      schedule_iter++;
      constants_iter++;
      t--;
   }
   
   return;
}

static void
cliauth_hash_sha2_32_digest_block(
   struct CliAuthHashContext * context,
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH]
) {
   struct _CliAuthHashContextAlgorithmSha232 * context_sha;

   context_sha = &context->algorithm.sha2_32;

   /* create the message schedule */
   cliauth_hash_sha2_32_create_message_schedule(
      block,
      &context_sha->schedule
   );

   /* initialize the working variables */
   cliauth_memory_copy(
      context_sha->work,
      context_sha->digest.words,
      CLIAUTH_LITERAL_UINT32(
         _CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * 
         sizeof(CliAuthUInt32)
      )
   );

   /* perform the rounds and additions */
   cliauth_hash_sha2_32_perform_rounds_and_additions(
      context_sha->work,
      context_sha->schedule.words
   );

   /* compute the intermediate result */
   cliauth_hash_sha1_2_32_compute_intermediate_digest(
      context_sha->work,
      context_sha->digest.words,
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT)
   );
   
   return;
}

static const struct CliAuthHashSha12RingBufferImplementation
cliauth_hash_sha2_32_ring_buffer_implementation = {
   cliauth_hash_sha2_32_digest_block,  
   CLIAUTH_LITERAL_UINT32(_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH),
};

static void
cliauth_hash_sha2_32_initialize(
   struct CliAuthHashContext * context,
   const CliAuthUInt32 constants_initialize [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT]
) {
   struct _CliAuthHashContextAlgorithmSha232 * context_sha;

   context_sha = &context->algorithm.sha2_32;

   /* initialize the digest to H(0). */
   cliauth_memory_copy(
      &context_sha->digest,
      constants_initialize,
      CLIAUTH_LITERAL_UINT32(
         _CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT *
         sizeof(CliAuthUInt32)
      )
   );

   /* initialize the ring buffer */
   cliauth_hash_sha1_2_ring_buffer_initialize(
      &cliauth_hash_sha2_32_ring_buffer_implementation,
      &context_sha->ring_context
   );

   return;
}

static struct CliAuthIoReadResult
cliauth_hash_sha2_32_digest(
   struct CliAuthHashContext * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   struct _CliAuthHashContextAlgorithmSha232 * context_sha;

   context_sha = &context->algorithm.sha2_32;

   return cliauth_hash_sha1_2_ring_buffer_digest(
      &cliauth_hash_sha2_32_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer,
      message_reader,
      message_bytes
   );
}

static CliAuthUInt8 *
cliauth_hash_sha2_32_finalize(
   struct CliAuthHashContext * context
) {
   struct _CliAuthHashContextAlgorithmSha232 * context_sha;

   context_sha = &context->algorithm.sha2_32;

   /* pad the message and digest the final padded blocks */
   cliauth_hash_sha1_2_ring_buffer_finalize(
      &cliauth_hash_sha2_32_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer
   );

   /* flip the endianess to big-endian for each word */
   cliauth_hash_sha1_2_digest_endianess_finalize(
      context_sha->digest.bytes,
      CLIAUTH_LITERAL_UINT8(sizeof(CliAuthUInt32)),
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT)
   );

   return context_sha->digest.bytes;
}

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA2_32 */

#if _CLIAUTH_HASH_SHA2_64
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_64_constants_rounds [_CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT] = {
   CLIAUTH_LITERAL_UINT64(0x428a2f98u, 0xd728ae22u),
   CLIAUTH_LITERAL_UINT64(0x71374491u, 0x23ef65cdu),
   CLIAUTH_LITERAL_UINT64(0xb5c0fbcfu, 0xec4d3b2fu),
   CLIAUTH_LITERAL_UINT64(0xe9b5dba5u, 0x8189dbbcu),
   CLIAUTH_LITERAL_UINT64(0x3956c25bu, 0xf348b538u),
   CLIAUTH_LITERAL_UINT64(0x59f111f1u, 0xb605d019u),
   CLIAUTH_LITERAL_UINT64(0x923f82a4u, 0xaf194f9bu),
   CLIAUTH_LITERAL_UINT64(0xab1c5ed5u, 0xda6d8118u),
   CLIAUTH_LITERAL_UINT64(0xd807aa98u, 0xa3030242u),
   CLIAUTH_LITERAL_UINT64(0x12835b01u, 0x45706fbeu),
   CLIAUTH_LITERAL_UINT64(0x243185beu, 0x4ee4b28cu),
   CLIAUTH_LITERAL_UINT64(0x550c7dc3u, 0xd5ffb4e2u),
   CLIAUTH_LITERAL_UINT64(0x72be5d74u, 0xf27b896fu),
   CLIAUTH_LITERAL_UINT64(0x80deb1feu, 0x3b1696b1u),
   CLIAUTH_LITERAL_UINT64(0x9bdc06a7u, 0x25c71235u),
   CLIAUTH_LITERAL_UINT64(0xc19bf174u, 0xcf692694u),
   CLIAUTH_LITERAL_UINT64(0xe49b69c1u, 0x9ef14ad2u),
   CLIAUTH_LITERAL_UINT64(0xefbe4786u, 0x384f25e3u),
   CLIAUTH_LITERAL_UINT64(0x0fc19dc6u, 0x8b8cd5b5u),
   CLIAUTH_LITERAL_UINT64(0x240ca1ccu, 0x77ac9c65u),
   CLIAUTH_LITERAL_UINT64(0x2de92c6fu, 0x592b0275u),
   CLIAUTH_LITERAL_UINT64(0x4a7484aau, 0x6ea6e483u),
   CLIAUTH_LITERAL_UINT64(0x5cb0a9dcu, 0xbd41fbd4u),
   CLIAUTH_LITERAL_UINT64(0x76f988dau, 0x831153b5u),
   CLIAUTH_LITERAL_UINT64(0x983e5152u, 0xee66dfabu),
   CLIAUTH_LITERAL_UINT64(0xa831c66du, 0x2db43210u),
   CLIAUTH_LITERAL_UINT64(0xb00327c8u, 0x98fb213fu),
   CLIAUTH_LITERAL_UINT64(0xbf597fc7u, 0xbeef0ee4u),
   CLIAUTH_LITERAL_UINT64(0xc6e00bf3u, 0x3da88fc2u),
   CLIAUTH_LITERAL_UINT64(0xd5a79147u, 0x930aa725u),
   CLIAUTH_LITERAL_UINT64(0x06ca6351u, 0xe003826fu),
   CLIAUTH_LITERAL_UINT64(0x14292967u, 0x0a0e6e70u),
   CLIAUTH_LITERAL_UINT64(0x27b70a85u, 0x46d22ffcu),
   CLIAUTH_LITERAL_UINT64(0x2e1b2138u, 0x5c26c926u),
   CLIAUTH_LITERAL_UINT64(0x4d2c6dfcu, 0x5ac42aedu),
   CLIAUTH_LITERAL_UINT64(0x53380d13u, 0x9d95b3dfu),
   CLIAUTH_LITERAL_UINT64(0x650a7354u, 0x8baf63deu),
   CLIAUTH_LITERAL_UINT64(0x766a0abbu, 0x3c77b2a8u),
   CLIAUTH_LITERAL_UINT64(0x81c2c92eu, 0x47edaee6u),
   CLIAUTH_LITERAL_UINT64(0x92722c85u, 0x1482353bu),
   CLIAUTH_LITERAL_UINT64(0xa2bfe8a1u, 0x4cf10364u),
   CLIAUTH_LITERAL_UINT64(0xa81a664bu, 0xbc423001u),
   CLIAUTH_LITERAL_UINT64(0xc24b8b70u, 0xd0f89791u),
   CLIAUTH_LITERAL_UINT64(0xc76c51a3u, 0x0654be30u),
   CLIAUTH_LITERAL_UINT64(0xd192e819u, 0xd6ef5218u),
   CLIAUTH_LITERAL_UINT64(0xd6990624u, 0x5565a910u),
   CLIAUTH_LITERAL_UINT64(0xf40e3585u, 0x5771202au),
   CLIAUTH_LITERAL_UINT64(0x106aa070u, 0x32bbd1b8u),
   CLIAUTH_LITERAL_UINT64(0x19a4c116u, 0xb8d2d0c8u),
   CLIAUTH_LITERAL_UINT64(0x1e376c08u, 0x5141ab53u),
   CLIAUTH_LITERAL_UINT64(0x2748774cu, 0xdf8eeb99u),
   CLIAUTH_LITERAL_UINT64(0x34b0bcb5u, 0xe19b48a8u),
   CLIAUTH_LITERAL_UINT64(0x391c0cb3u, 0xc5c95a63u),
   CLIAUTH_LITERAL_UINT64(0x4ed8aa4au, 0xe3418acbu),
   CLIAUTH_LITERAL_UINT64(0x5b9cca4fu, 0x7763e373u),
   CLIAUTH_LITERAL_UINT64(0x682e6ff3u, 0xd6b2b8a3u),
   CLIAUTH_LITERAL_UINT64(0x748f82eeu, 0x5defb2fcu),
   CLIAUTH_LITERAL_UINT64(0x78a5636fu, 0x43172f60u),
   CLIAUTH_LITERAL_UINT64(0x84c87814u, 0xa1f0ab72u),
   CLIAUTH_LITERAL_UINT64(0x8cc70208u, 0x1a6439ecu),
   CLIAUTH_LITERAL_UINT64(0x90befffau, 0x23631e28u),
   CLIAUTH_LITERAL_UINT64(0xa4506cebu, 0xde82bde9u),
   CLIAUTH_LITERAL_UINT64(0xbef9a3f7u, 0xb2c67915u),
   CLIAUTH_LITERAL_UINT64(0xc67178f2u, 0xe372532bu),
   CLIAUTH_LITERAL_UINT64(0xca273eceu, 0xea26619cu),
   CLIAUTH_LITERAL_UINT64(0xd186b8c7u, 0x21c0c207u),
   CLIAUTH_LITERAL_UINT64(0xeada7dd6u, 0xcde0eb1eu),
   CLIAUTH_LITERAL_UINT64(0xf57d4f7fu, 0xee6ed178u),
   CLIAUTH_LITERAL_UINT64(0x06f067aau, 0x72176fbau),
   CLIAUTH_LITERAL_UINT64(0x0a637dc5u, 0xa2c898a6u),
   CLIAUTH_LITERAL_UINT64(0x113f9804u, 0xbef90daeu),
   CLIAUTH_LITERAL_UINT64(0x1b710b35u, 0x131c471bu),
   CLIAUTH_LITERAL_UINT64(0x28db77f5u, 0x23047d84u),
   CLIAUTH_LITERAL_UINT64(0x32caab7bu, 0x40c72493u),
   CLIAUTH_LITERAL_UINT64(0x3c9ebe0au, 0x15c9bebcu),
   CLIAUTH_LITERAL_UINT64(0x431d67c4u, 0x9c100d4cu),
   CLIAUTH_LITERAL_UINT64(0x4cc5d4beu, 0xcb3e42b6u),
   CLIAUTH_LITERAL_UINT64(0x597f299cu, 0xfc657e2au),
   CLIAUTH_LITERAL_UINT64(0x5fcb6fabu, 0x3ad6faecu),
   CLIAUTH_LITERAL_UINT64(0x6c44198cu, 0x4a475817u)
};

static CliAuthUInt64
cliauth_hash_sha2_64_ch(CliAuthUInt64 x, CliAuthUInt64 y, CliAuthUInt64 z) {
   return ((x & y) ^ ((~x) & z));
}

static CliAuthUInt64
cliauth_hash_sha2_64_maj(CliAuthUInt64 x, CliAuthUInt64 y, CliAuthUInt64 z) {
   return ((x & y) ^ (x & z) ^ (y & z));
}

static CliAuthUInt64
cliauth_hash_sha2_64_parity(CliAuthUInt64 x, CliAuthUInt64 y, CliAuthUInt64 z) {
   return (x ^ y ^ z);
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_u0(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(28u));
   b = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(34u));
   c = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(39u));

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_u1(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(14u));
   b = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(18u));
   c = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(41u));

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_l0(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(1u));
   b = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(8u));
   c = (x >> CLIAUTH_LITERAL_UINT8(7u));

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_l1(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(19u));
   b = cliauth_bitwise_rotate_right_uint64(x, CLIAUTH_LITERAL_UINT8(61u));
   c = (x >> CLIAUTH_LITERAL_UINT8(6u));

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static void
cliauth_hash_sha2_64_create_message_schedule(
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH],
   union _CliAuthHashContextAlgorithmSha264Schedule * schedule
) {
   CliAuthUInt64 * schedule_iter;
   CliAuthUInt64 a, b, c, d;
   CliAuthUInt8 t;

   schedule_iter = schedule->words;

   /* 0 <= t <= 15 */
   cliauth_hash_sha1_2_load_message_block(
      block,
      schedule->bytes,
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH),
      CLIAUTH_LITERAL_UINT8(sizeof(CliAuthUInt64))
   );
   schedule_iter += _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH / sizeof(CliAuthUInt64);

   /* 16 <= t <= 79 */
   t = CLIAUTH_LITERAL_UINT8(64u);
   while (t != CLIAUTH_LITERAL_UINT8(0u)) {
      a = cliauth_hash_sha2_64_sigma_l1(schedule_iter[-2]);
      b = schedule_iter[-7];
      c = cliauth_hash_sha2_64_sigma_l0(schedule_iter[-15]);
      d = schedule_iter[-16];

      *schedule_iter = a + b + c + d;

      schedule_iter++;
      t--;
   }

   return;
}

static void
cliauth_hash_sha2_64_perform_rounds_and_additions(
   CliAuthUInt64 work [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT],
   const CliAuthUInt64 schedule [_CLIAUTH_HASH_SHA2_64_MESSAGE_SCHEDULE_LENGTH]
) {
   CliAuthUInt8 t, i;
   CliAuthUInt64 a, b, c, d, e, f, g;
   CliAuthUInt64 t1, t2;
   const CliAuthUInt64 * schedule_iter;
   const CliAuthUInt64 * constants_iter;
   CliAuthUInt64 * work_iter;

   t = CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT);
   schedule_iter = schedule;
   constants_iter = cliauth_hash_sha2_64_constants_rounds;

   while (t != CLIAUTH_LITERAL_UINT8(0u)) {
      a = work[7];
      b = cliauth_hash_sha2_64_sigma_u1(work[4]);
      c = cliauth_hash_sha2_64_ch(work[4], work[5], work[6]);
      d = *constants_iter;
      e = *schedule_iter;
      t1 = a + b + c + d + e;

      f = cliauth_hash_sha2_64_sigma_u0(work[0]);
      g = cliauth_hash_sha2_64_maj(work[0], work[1], work[2]);
      t2 = f + g;

      i = CLIAUTH_LITERAL_UINT8(7u);
      work_iter = &work[7];
      while (i != CLIAUTH_LITERAL_UINT8(0u)) {
         *work_iter = work_iter[-1];
         
         work_iter--;
         i--;
      }

      work[4] = work[4] + t1;
      work[0] = t1 + t2;

      schedule_iter++;
      constants_iter++;
      t--;
   }
   
   return;
}

static void
cliauth_hash_sha2_64_compute_intermediate_digest(
   CliAuthUInt64 digest [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT],
   const CliAuthUInt64 work [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT]
) {
   CliAuthUInt8 t;
   CliAuthUInt64 * digest_iter;
   const CliAuthUInt64 * work_iter;

   t = CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT);
   digest_iter = digest;
   work_iter = work;

   while (t != CLIAUTH_LITERAL_UINT8(0u)) {
      *digest_iter += *work_iter;

      digest_iter++;
      work_iter++;
      t--;
   }

   return;
}

static void
cliauth_hash_sha2_64_digest_block(
   struct CliAuthHashContext * context,
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH]
) {
   struct _CliAuthHashContextAlgorithmSha264 * context_sha;

   context_sha = &context->algorithm.sha2_64;

   cliauth_hash_sha2_64_create_message_schedule(
      block,
      &context_sha->schedule
   );

   cliauth_memory_copy(
      context_sha->work,
      context_sha->digest.words,
      CLIAUTH_LITERAL_UINT32(
         _CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT *
         sizeof(CliAuthUInt64)
      )
   );

   cliauth_hash_sha2_64_perform_rounds_and_additions(
      context_sha->work,
      context_sha->schedule.words
   );

   cliauth_hash_sha2_64_compute_intermediate_digest(
      context_sha->digest.words,
      context_sha->work
   );
   
   return;
}

static const struct CliAuthHashSha12RingBufferImplementation
cliauth_hash_sha2_64_ring_buffer_implementation = {
   cliauth_hash_sha2_64_digest_block,  
   CLIAUTH_LITERAL_UINT32(_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH),
};

static void
cliauth_hash_sha2_64_initialize(
   struct CliAuthHashContext * context,
   const CliAuthUInt64 constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT]
) {
   struct _CliAuthHashContextAlgorithmSha264 * context_sha;

   context_sha = &context->algorithm.sha2_64;

   cliauth_memory_copy(
      &context_sha->digest,
      constants_initialize,
      CLIAUTH_LITERAL_UINT32(
         _CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT *
         sizeof(CliAuthUInt64)
      )
   );

   cliauth_hash_sha1_2_ring_buffer_initialize(
      &cliauth_hash_sha2_64_ring_buffer_implementation,
      &context_sha->ring_context
   );

   return;
}

static struct CliAuthIoReadResult
cliauth_hash_sha2_64_digest(
   struct CliAuthHashContext * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   struct _CliAuthHashContextAlgorithmSha264 * context_sha;

   context_sha = &context->algorithm.sha2_64;
   
   return cliauth_hash_sha1_2_ring_buffer_digest(
      &cliauth_hash_sha2_64_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer,
      message_reader,
      message_bytes
   );
}

static CliAuthUInt8 *
cliauth_hash_sha2_64_finalize(
   struct CliAuthHashContext * context
) {
   struct _CliAuthHashContextAlgorithmSha264 * context_sha;

   context_sha = &context->algorithm.sha2_64;

   cliauth_hash_sha1_2_ring_buffer_finalize(
      &cliauth_hash_sha2_64_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer
   );

   cliauth_hash_sha1_2_digest_endianess_finalize(
      context_sha->digest.bytes,
      CLIAUTH_LITERAL_UINT8(sizeof(CliAuthUInt64)),
      CLIAUTH_LITERAL_UINT8(_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT)
   );

   return context_sha->digest.bytes;
}

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA2_64 */

#if CLIAUTH_CONFIG_HASH_SHA2_224
/*----------------------------------------------------------------------------*/

static const CliAuthUInt32
cliauth_hash_sha2_224_constants_initialize [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT] = {
   CLIAUTH_LITERAL_UINT32(0xc1059ed8u),
   CLIAUTH_LITERAL_UINT32(0x367cd507u),
   CLIAUTH_LITERAL_UINT32(0x3070dd17u),
   CLIAUTH_LITERAL_UINT32(0xf70e5939u),
   CLIAUTH_LITERAL_UINT32(0xffc00b31u),
   CLIAUTH_LITERAL_UINT32(0x68581511u),
   CLIAUTH_LITERAL_UINT32(0x64f98fa7u),
   CLIAUTH_LITERAL_UINT32(0xbefa4fa4u)
};

static void
cliauth_hash_sha2_224_initialize(struct CliAuthHashContext * context) {
   cliauth_hash_sha2_32_initialize(context, cliauth_hash_sha2_224_constants_initialize);
   return;
}

static const struct CliAuthHashFunction
cliauth_hash_sha2_224 = {
   cliauth_hash_sha2_224_initialize,
   cliauth_hash_sha2_32_digest,
   cliauth_hash_sha2_32_finalize,
   CLIAUTH_HASH_SHA2_224_IDENTIFIER,
   CLIAUTH_LITERAL_UINT32(sizeof(CLIAUTH_HASH_SHA2_224_IDENTIFIER) / sizeof(char)),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_224_INPUT_BLOCK_LENGTH),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_224_DIGEST_LENGTH)
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_224 */

#if CLIAUTH_CONFIG_HASH_SHA2_256
/*----------------------------------------------------------------------------*/

static const CliAuthUInt32
cliauth_hash_sha2_256_constants_initialize [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT] = {
   CLIAUTH_LITERAL_UINT32(0x6a09e667u),
   CLIAUTH_LITERAL_UINT32(0xbb67ae85u),
   CLIAUTH_LITERAL_UINT32(0x3c6ef372u),
   CLIAUTH_LITERAL_UINT32(0xa54ff53au),
   CLIAUTH_LITERAL_UINT32(0x510e527fu),
   CLIAUTH_LITERAL_UINT32(0x9b05688cu),
   CLIAUTH_LITERAL_UINT32(0x1f83d9abu),
   CLIAUTH_LITERAL_UINT32(0x5be0cd19u)
};

static void
cliauth_hash_sha2_256_initialize(struct CliAuthHashContext * context) {
   cliauth_hash_sha2_32_initialize(context, cliauth_hash_sha2_256_constants_initialize);
   return;
}

static const struct CliAuthHashFunction
cliauth_hash_sha2_256 = {
   cliauth_hash_sha2_256_initialize,
   cliauth_hash_sha2_32_digest,
   cliauth_hash_sha2_32_finalize,
   CLIAUTH_HASH_SHA2_256_IDENTIFIER,
   CLIAUTH_LITERAL_UINT32(sizeof(CLIAUTH_HASH_SHA2_256_IDENTIFIER) / sizeof(char)),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_256_INPUT_BLOCK_LENGTH),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_256_DIGEST_LENGTH)
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_256 */

#if CLIAUTH_CONFIG_HASH_SHA2_384
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_384_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   CLIAUTH_LITERAL_UINT64(0xcbbb9d5du, 0xc1059ed8u),
   CLIAUTH_LITERAL_UINT64(0x629a292au, 0x367cd507u),
   CLIAUTH_LITERAL_UINT64(0x9159015au, 0x3070dd17u),
   CLIAUTH_LITERAL_UINT64(0x152fecd8u, 0xf70e5939u),
   CLIAUTH_LITERAL_UINT64(0x67332667u, 0xffc00b31u),
   CLIAUTH_LITERAL_UINT64(0x8eb44a87u, 0x68581511u),
   CLIAUTH_LITERAL_UINT64(0xdb0c2e0du, 0x64f98fa7u),
   CLIAUTH_LITERAL_UINT64(0x47b5481du, 0xbefa4fa4u)
};

static void
cliauth_hash_sha2_384_initialize(struct CliAuthHashContext * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_384_constants_initialize);
   return;
}

static const struct CliAuthHashFunction
cliauth_hash_sha2_384 = {
   cliauth_hash_sha2_384_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize,
   CLIAUTH_HASH_SHA2_384_IDENTIFIER,
   CLIAUTH_LITERAL_UINT32(sizeof(CLIAUTH_HASH_SHA2_384_IDENTIFIER) / sizeof(char)),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_384_INPUT_BLOCK_LENGTH),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_384_DIGEST_LENGTH)
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_384 */

#if CLIAUTH_CONFIG_HASH_SHA2_512
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_512_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   CLIAUTH_LITERAL_UINT64(0x6a09e667u, 0xf3bcc908u),
   CLIAUTH_LITERAL_UINT64(0xbb67ae85u, 0x84caa73bu),
   CLIAUTH_LITERAL_UINT64(0x3c6ef372u, 0xfe94f82bu),
   CLIAUTH_LITERAL_UINT64(0xa54ff53au, 0x5f1d36f1u),
   CLIAUTH_LITERAL_UINT64(0x510e527fu, 0xade682d1u),
   CLIAUTH_LITERAL_UINT64(0x9b05688cu, 0x2b3e6c1fu),
   CLIAUTH_LITERAL_UINT64(0x1f83d9abu, 0xfb41bd6bu),
   CLIAUTH_LITERAL_UINT64(0x5be0cd19u, 0x137e2179u)
};

static void
cliauth_hash_sha2_512_initialize(struct CliAuthHashContext * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_512_constants_initialize);
   return;
}

static const struct CliAuthHashFunction
cliauth_hash_sha2_512 = {
   cliauth_hash_sha2_512_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize,
   CLIAUTH_HASH_SHA2_512_IDENTIFIER,
   CLIAUTH_LITERAL_UINT32(sizeof(CLIAUTH_HASH_SHA2_512_IDENTIFIER) / sizeof(char)),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_512_INPUT_BLOCK_LENGTH),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_512_DIGEST_LENGTH)
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512 */

#if CLIAUTH_CONFIG_HASH_SHA2_512_224
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_512_224_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   CLIAUTH_LITERAL_UINT64(0x8c3d37c8u, 0x19544da2u),
   CLIAUTH_LITERAL_UINT64(0x73e19966u, 0x89dcd4d6u),
   CLIAUTH_LITERAL_UINT64(0x1dfab7aeu, 0x32ff9c82u),
   CLIAUTH_LITERAL_UINT64(0x679dd514u, 0x582f9fcfu),
   CLIAUTH_LITERAL_UINT64(0x0f6d2b69u, 0x7bd44da8u),
   CLIAUTH_LITERAL_UINT64(0x77e36f73u, 0x04c48942u),
   CLIAUTH_LITERAL_UINT64(0x3f9d85a8u, 0x6a1d36c8u),
   CLIAUTH_LITERAL_UINT64(0x1112e6adu, 0x91d692a1u)
};

static void
cliauth_hash_sha2_512_224_initialize(struct CliAuthHashContext * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_512_224_constants_initialize);
   return;
}

static const struct CliAuthHashFunction
cliauth_hash_sha2_512_224 = {
   cliauth_hash_sha2_512_224_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize,
   CLIAUTH_HASH_SHA2_512_224_IDENTIFIER,
   CLIAUTH_LITERAL_UINT32(sizeof(CLIAUTH_HASH_SHA2_512_224_IDENTIFIER) / sizeof(char)),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_512_224_INPUT_BLOCK_LENGTH),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_512_224_DIGEST_LENGTH)
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_224 */

#if CLIAUTH_CONFIG_HASH_SHA2_512_256
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_512_256_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   CLIAUTH_LITERAL_UINT64(0x22312194u, 0xfc2bf72cu),
   CLIAUTH_LITERAL_UINT64(0x9f555fa3u, 0xc84c64c2u),
   CLIAUTH_LITERAL_UINT64(0x2393b86bu, 0x6f53b151u),
   CLIAUTH_LITERAL_UINT64(0x96387719u, 0x5940eabdu),
   CLIAUTH_LITERAL_UINT64(0x96283ee2u, 0xa88effe3u),
   CLIAUTH_LITERAL_UINT64(0xbe5e1e25u, 0x53863992u),
   CLIAUTH_LITERAL_UINT64(0x2b0199fcu, 0x2c85b8aau),
   CLIAUTH_LITERAL_UINT64(0x0eb72ddcu, 0x81c52ca2u)
};

static void
cliauth_hash_sha2_512_256_initialize(struct CliAuthHashContext * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_512_256_constants_initialize);
   return;
}

static const struct CliAuthHashFunction
cliauth_hash_sha2_512_256 = {
   cliauth_hash_sha2_512_256_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize,
   CLIAUTH_HASH_SHA2_512_256_IDENTIFIER,
   CLIAUTH_LITERAL_UINT32(sizeof(CLIAUTH_HASH_SHA2_512_256_IDENTIFIER) / sizeof(char)),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_512_256_INPUT_BLOCK_LENGTH),
   CLIAUTH_LITERAL_UINT8(CLIAUTH_HASH_SHA2_512_256_DIGEST_LENGTH)
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_256 */

const struct CliAuthHashFunction
cliauth_hash [CLIAUTH_HASH_ENABLED_COUNT] = {
#if CLIAUTH_CONFIG_HASH_SHA1
   cliauth_hash_sha1,
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA2_224
   cliauth_hash_sha2_224,
#endif /* CLIAUTH_CONFIG_HASH_SHA2_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_256
   cliauth_hash_sha2_256,
#endif /* CLIAUTH_CONFIG_HASH_SHA2_256 */
#if CLIAUTH_CONFIG_HASH_SHA2_384
   cliauth_hash_sha2_384,
#endif /* CLIAUTH_CONFIG_HASH_SHA2_384 */
#if CLIAUTH_CONFIG_HASH_SHA2_512
   cliauth_hash_sha2_512,
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_224
   cliauth_hash_sha2_512_224,
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_256
   cliauth_hash_sha2_512_256,
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_256 */
};

