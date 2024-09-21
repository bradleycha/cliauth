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
   void * state,
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
   context->total = 0;

   return;
}

/* loads a message into the ring buffer, digesting if the ring buffer fills */
static struct CliAuthIoReadResult
cliauth_hash_sha1_2_ring_buffer_digest(
   const struct CliAuthHashSha12RingBufferImplementation * implementation,
   struct _CliAuthHashSha12RingBufferContext * context,
   void * state,
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
   digest_bytes = 0;

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

   implementation->digest(state, buffer);

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
   void * state,
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
      - 1
      - sizeof(message_length_bits_big_endian)
      + context->capacity
   ) % implementation->bytes;

   /* if the amount of pad bytes will require a new block, fill the ring */
   /* buffer and digest with as many zeroes as will fit and then fill the */
   /* next block with zeroes */
   if (zero_pad_bytes > context->capacity - 1) {
      cliauth_memory_fill(
         ring_buffer_iter,
         &zero_pad_sentinel,
         context->capacity - 1,
         1
      );
      ring_buffer_iter = buffer;
      zero_pad_bytes -= context->capacity - 1;

      implementation->digest(state, buffer);
   }

   /* write the remaining pad zeroes */
   cliauth_memory_fill(
      ring_buffer_iter,
      &zero_pad_sentinel,
      zero_pad_bytes,
      1
   );
   ring_buffer_iter += zero_pad_bytes;

   /* calculate the message length in bits, convert to big endian, and append */
   /* to the end of the message */
   message_length_bits_big_endian = cliauth_endian_convert_uint64(
      context->total * 8,
      CLIAUTH_ENDIAN_TARGET_BIG
   );
   cliauth_memory_copy(
      ring_buffer_iter,
      &message_length_bits_big_endian,
      sizeof(message_length_bits_big_endian)
   );
   ring_buffer_iter += sizeof(message_length_bits_big_endian);

   /* digest the final block */
   implementation->digest(state, buffer);

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
   while (block_bytes != 0) {
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
   while (digest_words != 0) {
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
   while (digest_words_count != 0) {
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
   0x5a827999,
   0x6ed9eba1,
   0x8f1bbcdc,
   0xca62c1d6
};

static void
cliauth_hash_sha1_create_message_schedule(
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA1_BLOCK_LENGTH],
   union _CliAuthHashContextSha1Schedule * schedule
) {
   CliAuthUInt32 * schedule_iter;
   CliAuthUInt32 a, b, c, d, e;
   CliAuthUInt8 t;

   schedule_iter = schedule->words;

   /* 0 <= t <= 15 */
   cliauth_hash_sha1_2_load_message_block(
      block,
      schedule->bytes,
      _CLIAUTH_HASH_SHA1_BLOCK_LENGTH,
      sizeof(CliAuthUInt32)
   );
   schedule_iter += _CLIAUTH_HASH_SHA1_BLOCK_LENGTH / sizeof(CliAuthUInt32);

   /* 16 <= t <= 79 */
   t = 64;
   while (t != 0) {
      a = schedule_iter[-3];
      b = schedule_iter[-8];
      c = schedule_iter[-14];
      d = schedule_iter[-16];
      e = a ^ b ^ c ^ d;

      *schedule_iter = cliauth_bitwise_rotate_left_uint32(e, 1);

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

   t = _CLIAUTH_HASH_SHA1_ROUNDS_COUNT;
   j = _CLIAUTH_HASH_SHA1_ROUNDS_COUNT / _CLIAUTH_HASH_SHA1_ROUNDS_CONSTANTS_LENGTH;
   schedule_iter = schedule;
   constants_function_iter = cliauth_hash_sha1_constants_rounds_function;
   constants_value_iter = cliauth_hash_sha1_constants_rounds_value;

   while (t != 0) {
      if (j == 0) {
         j = _CLIAUTH_HASH_SHA1_ROUNDS_COUNT / _CLIAUTH_HASH_SHA1_ROUNDS_CONSTANTS_LENGTH;
         constants_function_iter++;
         constants_value_iter++;
      }

      a = cliauth_bitwise_rotate_left_uint32(work[0], 5);
      b = (*constants_function_iter)(work[1], work[2], work[3]);
      c = work[4];
      d = *constants_value_iter;
      e = *schedule_iter;
      t1 = a + b + c + d + e;

      i = 4;
      work_iter = &work[4];
      while (i != 0) {
         *work_iter = work_iter[-1];

         work_iter--;
         i--;
      }

      work[2] = cliauth_bitwise_rotate_left_uint32(work[2], 30);
      work[0] = t1;

      schedule_iter++;
      t--;
      j--;
   }

   return;
}

static void
cliauth_hash_sha1_digest_block(
   void * context,
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA1_BLOCK_LENGTH]
) {
   struct CliAuthHashContextSha1 * context_sha;

   context_sha = (struct CliAuthHashContextSha1 *)context;

   cliauth_hash_sha1_create_message_schedule(
      block,
      &context_sha->schedule
   );

   cliauth_memory_copy(
      context_sha->work,
      context_sha->digest.words,
      _CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)
   );

   cliauth_hash_sha1_perform_rounds_and_additions(
      context_sha->work,
      context_sha->schedule.words
   );

   cliauth_hash_sha1_2_32_compute_intermediate_digest(
      context_sha->work,
      context_sha->digest.words,
      _CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT
   );

   return;
}

static const struct CliAuthHashSha12RingBufferImplementation
cliauth_hash_sha1_ring_buffer_implementation = {
   cliauth_hash_sha1_digest_block,
   _CLIAUTH_HASH_SHA1_BLOCK_LENGTH
};

static const CliAuthUInt32
cliauth_hash_sha1_constants_initialize [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT] = {
   0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

static void
cliauth_hash_sha1_initialize(void * context) {
   struct CliAuthHashContextSha1 * context_sha;

   context_sha = (struct CliAuthHashContextSha1 *)context;

   cliauth_memory_copy(
      &context_sha->digest,
      cliauth_hash_sha1_constants_initialize,
      _CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)
   );

   cliauth_hash_sha1_2_ring_buffer_initialize(
      &cliauth_hash_sha1_ring_buffer_implementation,
      &context_sha->ring_context
   );

   return;
}

static struct CliAuthIoReadResult
cliauth_hash_sha1_digest(
   void * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   struct CliAuthHashContextSha1 * context_sha;

   context_sha = (struct CliAuthHashContextSha1 *)context;

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
cliauth_hash_sha1_finalize(void * context) {
   struct CliAuthHashContextSha1 * context_sha;

   context_sha = (struct CliAuthHashContextSha1 *)context;

   cliauth_hash_sha1_2_ring_buffer_finalize(
      &cliauth_hash_sha1_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer
   );

   cliauth_hash_sha1_2_digest_endianess_finalize(
      context_sha->digest.bytes,
      sizeof(CliAuthUInt32),
      _CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT
   );

   return context_sha->digest.bytes;
}

const struct CliAuthHashFunction
cliauth_hash_sha1 = {
   cliauth_hash_sha1_initialize,
   cliauth_hash_sha1_digest,
   cliauth_hash_sha1_finalize
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */

#if _CLIAUTH_HASH_SHA2_32
/*----------------------------------------------------------------------------*/

static const CliAuthUInt32
cliauth_hash_sha2_32_constants_rounds [_CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_u0(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 2);
   b = cliauth_bitwise_rotate_right_uint32(x, 13);
   c = cliauth_bitwise_rotate_right_uint32(x, 22);

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_u1(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 6);
   b = cliauth_bitwise_rotate_right_uint32(x, 11);
   c = cliauth_bitwise_rotate_right_uint32(x, 25);

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_l0(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 7);
   b = cliauth_bitwise_rotate_right_uint32(x, 18);
   c = (x >> 3);

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_l1(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 17);
   b = cliauth_bitwise_rotate_right_uint32(x, 19);
   c = (x >> 10);

   return cliauth_hash_sha1_2_32_parity(a, b, c);
}

static void
cliauth_hash_sha2_32_create_message_schedule(
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH],
   union _CliAuthHashContextSha232Schedule * schedule
) {
   CliAuthUInt32 * schedule_iter;
   CliAuthUInt32 a, b, c, d;
   CliAuthUInt8 t;

   schedule_iter = schedule->words;

   /* 0 <= t <= 15 */
   cliauth_hash_sha1_2_load_message_block(
      block,
      schedule->bytes,
      _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH,
      sizeof(CliAuthUInt32)
   );
   schedule_iter += _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH / sizeof(CliAuthUInt32);

   /* 16 <= t <= 63 */
   t = 48;
   while (t != 0) {
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

   t = _CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT;
   schedule_iter = schedule;
   constants_iter = cliauth_hash_sha2_32_constants_rounds;

   while (t != 0) {
      a = work[7];
      b = cliauth_hash_sha2_32_sigma_u1(work[4]);
      c = cliauth_hash_sha1_2_32_ch(work[4], work[5], work[6]);
      d = *constants_iter;
      e = *schedule_iter;
      t1 = a + b + c + d + e;

      f = cliauth_hash_sha2_32_sigma_u0(work[0]);
      g = cliauth_hash_sha1_2_32_maj(work[0], work[1], work[2]);
      t2 = f + g;

      i = 7;
      work_iter = &work[7];
      while (i != 0) {
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
   void * context,
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH]
) {
   struct CliAuthHashContextSha232 * context_sha;

   context_sha = (struct CliAuthHashContextSha232 *)context;

   /* create the message schedule */
   cliauth_hash_sha2_32_create_message_schedule(
      block,
      &context_sha->schedule
   );

   /* initialize the working variables */
   cliauth_memory_copy(
      context_sha->work,
      context_sha->digest.words,
      _CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)
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
      _CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT
   );
   
   return;
}

static const struct CliAuthHashSha12RingBufferImplementation
cliauth_hash_sha2_32_ring_buffer_implementation = {
   cliauth_hash_sha2_32_digest_block,  
   _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH,
};

static void
cliauth_hash_sha2_32_initialize(
   void * context,
   const CliAuthUInt32 constants_initialize [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT]
) {
   struct CliAuthHashContextSha232 * context_sha;

   context_sha = (struct CliAuthHashContextSha232 *)context;

   /* initialize the digest to H(0). */
   cliauth_memory_copy(
      &context_sha->digest,
      constants_initialize,
      _CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)
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
   void * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   struct CliAuthHashContextSha232 * context_sha;

   context_sha = (struct CliAuthHashContextSha232 *)context;

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
   void * context
) {
   struct CliAuthHashContextSha232 * context_sha;

   context_sha = (struct CliAuthHashContextSha232 *)context;

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
      sizeof(CliAuthUInt32),
      _CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT
   );

   return context_sha->digest.bytes;
}

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA2_32 */

#if _CLIAUTH_HASH_SHA2_64
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_64_constants_rounds [_CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT] = {
   0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
   0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
   0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
   0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
   0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
   0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
   0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
   0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
   0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
   0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
   0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
   0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
   0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
   0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
   0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
   0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
   0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
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

   a = cliauth_bitwise_rotate_right_uint64(x, 28);
   b = cliauth_bitwise_rotate_right_uint64(x, 34);
   c = cliauth_bitwise_rotate_right_uint64(x, 39);

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_u1(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, 14);
   b = cliauth_bitwise_rotate_right_uint64(x, 18);
   c = cliauth_bitwise_rotate_right_uint64(x, 41);

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_l0(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, 1);
   b = cliauth_bitwise_rotate_right_uint64(x, 8);
   c = (x >> 7);

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_l1(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, 19);
   b = cliauth_bitwise_rotate_right_uint64(x, 61);
   c = (x >> 6);

   return cliauth_hash_sha2_64_parity(a, b, c);
}

static void
cliauth_hash_sha2_64_create_message_schedule(
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH],
   union _CliAuthHashContextSha264Schedule * schedule
) {
   CliAuthUInt64 * schedule_iter;
   CliAuthUInt64 a, b, c, d;
   CliAuthUInt8 t;

   schedule_iter = schedule->words;

   /* 0 <= t <= 15 */
   cliauth_hash_sha1_2_load_message_block(
      block,
      schedule->bytes,
      _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH,
      sizeof(CliAuthUInt64)
   );
   schedule_iter += _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH / sizeof(CliAuthUInt64);

   /* 16 <= t <= 79 */
   t = 64;
   while (t != 0) {
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

   t = _CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT;
   schedule_iter = schedule;
   constants_iter = cliauth_hash_sha2_64_constants_rounds;

   while (t != 0) {
      a = work[7];
      b = cliauth_hash_sha2_64_sigma_u1(work[4]);
      c = cliauth_hash_sha2_64_ch(work[4], work[5], work[6]);
      d = *constants_iter;
      e = *schedule_iter;
      t1 = a + b + c + d + e;

      f = cliauth_hash_sha2_64_sigma_u0(work[0]);
      g = cliauth_hash_sha2_64_maj(work[0], work[1], work[2]);
      t2 = f + g;

      i = 7;
      work_iter = &work[7];
      while (i != 0) {
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

   t = _CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT;
   digest_iter = digest;
   work_iter = work;

   while (t != 0) {
      *digest_iter += *work_iter;

      digest_iter++;
      work_iter++;
      t--;
   }

   return;
}

static void
cliauth_hash_sha2_64_digest_block(
   void * context,
   const CliAuthUInt8 block [_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH]
) {
   struct CliAuthHashContextSha264 * context_sha;

   context_sha = (struct CliAuthHashContextSha264 *)context;

   cliauth_hash_sha2_64_create_message_schedule(
      block,
      &context_sha->schedule
   );

   cliauth_memory_copy(
      context_sha->work,
      context_sha->digest.words,
      _CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)
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
   _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH,
};

static void
cliauth_hash_sha2_64_initialize(
   void * context,
   const CliAuthUInt64 constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT]
) {
   struct CliAuthHashContextSha264 * context_sha;

   context_sha = (struct CliAuthHashContextSha264 *)context;

   cliauth_memory_copy(
      &context_sha->digest,
      constants_initialize,
      _CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)
   );

   cliauth_hash_sha1_2_ring_buffer_initialize(
      &cliauth_hash_sha2_64_ring_buffer_implementation,
      &context_sha->ring_context
   );

   return;
}

static struct CliAuthIoReadResult
cliauth_hash_sha2_64_digest(
   void * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
) {
   struct CliAuthHashContextSha264 * context_sha;

   context_sha = (struct CliAuthHashContextSha264 *)context;
   
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
   void * context
) {
   struct CliAuthHashContextSha264 * context_sha;

   context_sha = (struct CliAuthHashContextSha264 *)context;

   cliauth_hash_sha1_2_ring_buffer_finalize(
      &cliauth_hash_sha2_64_ring_buffer_implementation,
      &context_sha->ring_context,
      context,
      context_sha->ring_buffer
   );

   cliauth_hash_sha1_2_digest_endianess_finalize(
      context_sha->digest.bytes,
      sizeof(CliAuthUInt64),
      _CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT
   );

   return context_sha->digest.bytes;
}

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA2_64 */

#if CLIAUTH_CONFIG_HASH_SHA2_224
/*----------------------------------------------------------------------------*/

static const CliAuthUInt32
cliauth_hash_sha2_224_constants_initialize [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT] = {
   0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
   0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static void
cliauth_hash_sha2_224_initialize(void * context) {
   cliauth_hash_sha2_32_initialize(context, cliauth_hash_sha2_224_constants_initialize);
   return;
}

const struct CliAuthHashFunction
cliauth_hash_sha2_224 = {
   cliauth_hash_sha2_224_initialize,
   cliauth_hash_sha2_32_digest,
   cliauth_hash_sha2_32_finalize
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_224 */

#if CLIAUTH_CONFIG_HASH_SHA2_256
/*----------------------------------------------------------------------------*/

static const CliAuthUInt32
cliauth_hash_sha2_256_constants_initialize [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT] = {
   0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static void
cliauth_hash_sha2_256_initialize(void * context) {
   cliauth_hash_sha2_32_initialize(context, cliauth_hash_sha2_256_constants_initialize);
   return;
}

const struct CliAuthHashFunction
cliauth_hash_sha2_256 = {
   cliauth_hash_sha2_256_initialize,
   cliauth_hash_sha2_32_digest,
   cliauth_hash_sha2_32_finalize
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_256 */

#if CLIAUTH_CONFIG_HASH_SHA2_384
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_384_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
   0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

static void
cliauth_hash_sha2_384_initialize(void * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_384_constants_initialize);
   return;
}

const struct CliAuthHashFunction
cliauth_hash_sha2_384 = {
   cliauth_hash_sha2_384_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_384 */

#if CLIAUTH_CONFIG_HASH_SHA2_512
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_512_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
   0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static void
cliauth_hash_sha2_512_initialize(void * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_512_constants_initialize);
   return;
}

const struct CliAuthHashFunction
cliauth_hash_sha2_512 = {
   cliauth_hash_sha2_512_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512 */

#if CLIAUTH_CONFIG_HASH_SHA2_512_224
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_512_224_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
   0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
};

static void
cliauth_hash_sha2_512_224_initialize(void * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_512_224_constants_initialize);
   return;
}

const struct CliAuthHashFunction
cliauth_hash_sha2_512_224 = {
   cliauth_hash_sha2_512_224_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_224 */

#if CLIAUTH_CONFIG_HASH_SHA2_512_256
/*----------------------------------------------------------------------------*/

static const CliAuthUInt64
cliauth_hash_sha2_512_256_constants_initialize [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
   0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
};

static void
cliauth_hash_sha2_512_256_initialize(void * context) {
   cliauth_hash_sha2_64_initialize(context, cliauth_hash_sha2_512_256_constants_initialize);
   return;
}

const struct CliAuthHashFunction
cliauth_hash_sha2_512_256 = {
   cliauth_hash_sha2_512_256_initialize,
   cliauth_hash_sha2_64_digest,
   cliauth_hash_sha2_64_finalize
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_256 */

