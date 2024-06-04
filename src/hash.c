/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/hash.c - Hash algorithm implementations                                */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "hash.h"

#include <string.h>
#include "endian.h"
#include "bitwise.h"

/* enable shared constants and functions for 32-bit SHA-2 hash functions */
#define CLIAUTH_HASH_SHA2_32\
   (\
      CLIAUTH_CONFIG_HASH_SHA224 ||\
      CLIAUTH_CONFIG_HASH_SHA256\
   )

/* enable shared constants and functions for 64-bit SHA-2 hash functions */
#define CLIAUTH_HASH_SHA2_64\
   (\
      CLIAUTH_HASH_CONFIG_SHA384 ||\
      CLIAUTH_CONFIG_HASH_SHA512 ||\
      CLIAUTH_CONFIG_HASH_SHA512_224 ||\
      CLIAUTH_CONFIG_HASH_SHA512_256\
   )

#if CLIAUTH_HASH_SHA2_32
/*----------------------------------------------------------------------------*/

#define CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH\
   64
#define CLIAUTH_HASH_SHA2_32_BLOCK_RESIDUAL_LENGTH\
   (CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH * 2)
#define CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT\
   8
#define CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT\
   64
#define CLIAUTH_HASH_SHA2_32_MESSAGE_SCHEDULE_LENGTH\
   CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT

static CliAuthUInt32
cliauth_hash_sha2_32_constants_rounds [CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT] = {
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
cliauth_hash_sha2_32_ch(CliAuthUInt32 x, CliAuthUInt32 y, CliAuthUInt32 z) {
   return ((x & y) ^ ((~x) & z));
}

static CliAuthUInt32
cliauth_hash_sha2_32_maj(CliAuthUInt32 x, CliAuthUInt32 y, CliAuthUInt32 z) {
   return ((x & y) ^ (x & z) ^ (y & z));
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_u0(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 2);
   b = cliauth_bitwise_rotate_right_uint32(x, 13);
   c = cliauth_bitwise_rotate_right_uint32(x, 22);

   return a ^ b ^ c;
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_u1(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 6);
   b = cliauth_bitwise_rotate_right_uint32(x, 11);
   c = cliauth_bitwise_rotate_right_uint32(x, 25);

   return a ^ b ^ c;
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_l0(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 7);
   b = cliauth_bitwise_rotate_right_uint32(x, 18);
   c = (x >> 3);

   return a ^ b ^ c;
}

static CliAuthUInt32
cliauth_hash_sha2_32_sigma_l1(CliAuthUInt32 x) {
   CliAuthUInt32 a, b, c;

   a = cliauth_bitwise_rotate_right_uint32(x, 17);
   b = cliauth_bitwise_rotate_right_uint32(x, 19);
   c = (x >> 10);

   return a ^ b ^ c;
}

static void
cliauth_hash_sha2_32_create_message_schedule(
   const CliAuthUInt8 block [CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH],
   CliAuthUInt32 schedule [CLIAUTH_HASH_SHA2_32_MESSAGE_SCHEDULE_LENGTH]
) {
   CliAuthUInt32 * schedule_iter;
   CliAuthUInt32 a, b, c, d;
   CliAuthUInt8 t;

   schedule_iter = schedule;

   /* 0 <= t <= 15 */
   /* memcpy and in-place endian flipness to avoid unaligned pointers */
   (void)memcpy(schedule_iter, block, CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH);
   t = 16;
   while (t != 0) {
      *schedule_iter = cliauth_endian_host_to_big_uint32(*schedule_iter);

      schedule_iter++;
      t--;
   }

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
   CliAuthUInt32 work [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT],
   const CliAuthUInt32 schedule [CLIAUTH_HASH_SHA2_32_MESSAGE_SCHEDULE_LENGTH]
) {
   CliAuthUInt8 t, i;
   CliAuthUInt32 a, b, c, d, e, f, g;
   CliAuthUInt32 t1, t2;
   const CliAuthUInt32 * schedule_iter;
   const CliAuthUInt32 * constants_iter;
   CliAuthUInt32 * work_iter;

   t = CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT;
   schedule_iter = schedule;
   constants_iter = cliauth_hash_sha2_32_constants_rounds;

   while (t != 0) {
      a = work[7];
      b = cliauth_hash_sha2_32_sigma_u1(work[4]);
      c = cliauth_hash_sha2_32_ch(work[4], work[5], work[6]);
      d = *constants_iter;
      e = *schedule_iter;
      t1 = a + b + c + d + e;

      f = cliauth_hash_sha2_32_sigma_u0(work[0]);
      g = cliauth_hash_sha2_32_maj(work[0], work[1], work[2]);
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
cliauth_hash_sha2_32_compute_intermediate_digest(
   CliAuthUInt32 digest [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT],
   const CliAuthUInt32 work [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT]
) {
   CliAuthUInt8 t;
   CliAuthUInt32 * digest_iter;
   const CliAuthUInt32 * work_iter;

   t = CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT;
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
cliauth_hash_sha2_32_digest_block(
   const CliAuthUInt8 block [CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH],
   CliAuthUInt32 digest [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT]
) {
   CliAuthUInt32 schedule [CLIAUTH_HASH_SHA2_32_MESSAGE_SCHEDULE_LENGTH];
   CliAuthUInt32 work [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];

   /* create the message schedule */
   cliauth_hash_sha2_32_create_message_schedule(block, schedule);

   /* initialize the working variables */
   (void)memcpy(work, digest, CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32));

   /* perform the rounds and additions */
   cliauth_hash_sha2_32_perform_rounds_and_additions(work, schedule);

   /* compute the intermediate result */
   cliauth_hash_sha2_32_compute_intermediate_digest(digest, work);
   
   return;
}

static CliAuthUInt8
cliauth_hash_sha2_32_pad_message(
   const CliAuthUInt8 residual [],
   CliAuthUInt32 residual_bytes,
   CliAuthUInt8 padded_message_buffer [CLIAUTH_HASH_SHA2_32_BLOCK_RESIDUAL_LENGTH],
   CliAuthUInt32 message_length
) {
   CliAuthUInt8 * padded_message_iter;
   CliAuthUInt32 fill_bytes;
   CliAuthUInt64 message_length_bits;
   CliAuthUInt8 blocks_count;

   padded_message_iter = padded_message_buffer;

   /* copy the residual message */
   (void)memcpy(padded_message_iter, residual, residual_bytes);
   padded_message_iter += residual_bytes;

   /* append the leading 1 bit */
   *padded_message_iter++ = (1 << 7);

   /* calculate the zero fill count and big-endian message bit length */
   /* message_length is promoted to 64-bit due to the edge case of the length */
   /* in bits overflowing a 32-bit integer. */
   fill_bytes = (CLIAUTH_HASH_SHA2_32_BLOCK_RESIDUAL_LENGTH - 1 - sizeof(CliAuthUInt64) - residual_bytes) % CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH;
   message_length_bits = cliauth_endian_host_to_big_uint64(((CliAuthUInt64)message_length) * 8);

   /* pad with zeroes to align to a block boundary */
   (void)memset(padded_message_iter, 0x00, fill_bytes);
   padded_message_iter += fill_bytes;

   /* append the message length (in bits) as a big-endian 64-bit integer */
   (void)memcpy(padded_message_iter, &message_length_bits, sizeof(CliAuthUInt64));
   padded_message_iter += sizeof(CliAuthUInt64);

   /* calculate the number of blocks storing the padded message */
   blocks_count = (padded_message_iter - padded_message_buffer) / CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH;

   return blocks_count;
}

static void
cliauth_hash_sha2_32_digest_finalize(
   CliAuthUInt32 digest [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT]
) {
   CliAuthUInt8 i;
   CliAuthUInt32 * digest_words_iter;

   i = CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT;
   digest_words_iter = digest;
   while (i != 0) {
      *digest_words_iter = cliauth_endian_host_to_big_uint32(*digest_words_iter);

      digest_words_iter++;
      i--;
   }

   return;
}

static void
cliauth_hash_sha2_32_digest(
   CliAuthUInt32 digest [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT],
   const CliAuthUInt8 message [],
   CliAuthUInt32 bytes
) {
   CliAuthUInt32 blocks_count, residual_bytes;
   CliAuthUInt8 padded_blocks_count;
   CliAuthUInt8 padded_message_buffer [CLIAUTH_HASH_SHA2_32_BLOCK_RESIDUAL_LENGTH];
   const CliAuthUInt8 * message_iter;

   /* digest should be initialized with H0 by the caller already */

   /* calculate the number of blocks and any residual bytes */
   blocks_count = bytes / CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH;
   residual_bytes = bytes % CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH;

   /* digest all the whole-sized blocks */
   message_iter = message;
   while (blocks_count != 0) {
      cliauth_hash_sha2_32_digest_block(message_iter, digest);

      message_iter += CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH;
      blocks_count--;
   }

   /* pad the message, storing the number of blocks used to pad the message */
   padded_blocks_count = cliauth_hash_sha2_32_pad_message(
      message_iter,
      residual_bytes,
      padded_message_buffer,
      bytes
   );

   /* digest the padded message blocks */
   message_iter = padded_message_buffer;
   while (padded_blocks_count != 0) {
      cliauth_hash_sha2_32_digest_block(message_iter, digest);

      message_iter += CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH;
      padded_blocks_count--;
   }

   /* finalize the digest, caller will copy into its context */
   cliauth_hash_sha2_32_digest_finalize(digest);
   
   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_HASH_SHA2_32 */

#if CLIAUTH_HASH_SHA2_64
/*----------------------------------------------------------------------------*/

#define CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH\
   128
#define CLIAUTH_HASH_SHA2_64_BLOCK_RESIDUAL_LENGTH\
   (CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH * 2)
#define CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT\
   8
#define CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT\
   80
#define CLIAUTH_HASH_SHA2_64_MESSAGE_SCHEDULE_LENGTH\
   CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT

static CliAuthUInt64
cliauth_hash_sha2_64_constants_rounds [CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT] = {
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
cliauth_hash_sha2_64_sigma_u0(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, 28);
   b = cliauth_bitwise_rotate_right_uint64(x, 34);
   c = cliauth_bitwise_rotate_right_uint64(x, 39);

   return a ^ b ^ c;
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_u1(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, 14);
   b = cliauth_bitwise_rotate_right_uint64(x, 18);
   c = cliauth_bitwise_rotate_right_uint64(x, 41);

   return a ^ b ^ c;
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_l0(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, 1);
   b = cliauth_bitwise_rotate_right_uint64(x, 8);
   c = (x >> 7);

   return a ^ b ^ c;
}

static CliAuthUInt64
cliauth_hash_sha2_64_sigma_l1(CliAuthUInt64 x) {
   CliAuthUInt64 a, b, c;

   a = cliauth_bitwise_rotate_right_uint64(x, 19);
   b = cliauth_bitwise_rotate_right_uint64(x, 61);
   c = (x >> 6);

   return a ^ b ^ c;
}

static void
cliauth_hash_sha2_64_create_message_schedule(
   const CliAuthUInt8 block [CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH],
   CliAuthUInt64 schedule [CLIAUTH_HASH_SHA2_64_MESSAGE_SCHEDULE_LENGTH]
) {
   CliAuthUInt64 * schedule_iter;
   CliAuthUInt64 a, b, c, d;
   CliAuthUInt8 t;

   schedule_iter = schedule;

   /* 0 <= t <= 15 */
   (void)memcpy(schedule_iter, block, CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH);
   t = 16;
   while (t != 0) {
      *schedule_iter = cliauth_endian_host_to_big_uint64(*schedule_iter);

      schedule_iter++;
      t--;
   }

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
   CliAuthUInt64 work [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT],
   const CliAuthUInt64 schedule [CLIAUTH_HASH_SHA2_64_MESSAGE_SCHEDULE_LENGTH]
) {
   CliAuthUInt8 t, i;
   CliAuthUInt64 a, b, c, d, e, f, g;
   CliAuthUInt64 t1, t2;
   const CliAuthUInt64 * schedule_iter;
   const CliAuthUInt64 * constants_iter;
   CliAuthUInt64 * work_iter;

   t = CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT;
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
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT],
   const CliAuthUInt64 work [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT]
) {
   CliAuthUInt8 t;
   CliAuthUInt64 * digest_iter;
   const CliAuthUInt64 * work_iter;

   t = CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT;
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
   const CliAuthUInt8 block [CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH],
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT]
) {
   CliAuthUInt64 schedule [CLIAUTH_HASH_SHA2_64_MESSAGE_SCHEDULE_LENGTH];
   CliAuthUInt64 work [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];

   cliauth_hash_sha2_64_create_message_schedule(block, schedule);

   (void)memcpy(work, digest, CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64));

   cliauth_hash_sha2_64_perform_rounds_and_additions(work, schedule);

   cliauth_hash_sha2_64_compute_intermediate_digest(digest, work);
   
   return;
}

static CliAuthUInt8
cliauth_hash_sha2_64_pad_message(
   const CliAuthUInt8 residual [],
   CliAuthUInt32 residual_bytes,
   CliAuthUInt8 padded_message_buffer [CLIAUTH_HASH_SHA2_64_BLOCK_RESIDUAL_LENGTH],
   CliAuthUInt32 message_length
) {
   CliAuthUInt8 * padded_message_iter;
   CliAuthUInt32 fill_bytes;
   CliAuthUInt64 message_length_bits;
   CliAuthUInt8 blocks_count;

   padded_message_iter = padded_message_buffer;

   (void)memcpy(padded_message_iter, residual, residual_bytes);
   padded_message_iter += residual_bytes;

   *padded_message_iter++ = (1 << 7);

   fill_bytes = (CLIAUTH_HASH_SHA2_64_BLOCK_RESIDUAL_LENGTH - 1 - sizeof(CliAuthUInt64) - residual_bytes) % CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH;
   message_length_bits = cliauth_endian_host_to_big_uint64(((CliAuthUInt64)message_length) * 8);

   (void)memset(padded_message_iter, 0x00, fill_bytes);
   padded_message_iter += fill_bytes;

   (void)memcpy(padded_message_iter, &message_length_bits, sizeof(CliAuthUInt64));
   padded_message_iter += sizeof(CliAuthUInt64);

   blocks_count = (padded_message_iter - padded_message_buffer) / CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH;

   return blocks_count;
}

static void
cliauth_hash_sha2_64_digest_finalize(
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT]
) {
   CliAuthUInt8 i;
   CliAuthUInt64 * digest_words_iter;

   i = CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT;
   digest_words_iter = digest;
   while (i != 0) {
      *digest_words_iter = cliauth_endian_host_to_big_uint64(*digest_words_iter);

      digest_words_iter++;
      i--;
   }

   return;
}

static void
cliauth_hash_sha2_64_digest(
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT],
   const CliAuthUInt8 message [],
   CliAuthUInt32 bytes
) {
   /* this is mostly just a modified version of the above sha2-256 */
   /* implementation.  comments will be provided where there are important */
   /* differences, but for most explanations, see the sha2-256 implementation. */
   
   CliAuthUInt32 blocks_count, residual_bytes;
   CliAuthUInt8 padded_blocks_count;
   CliAuthUInt8 padded_message_buffer [CLIAUTH_HASH_SHA2_64_BLOCK_RESIDUAL_LENGTH];
   const CliAuthUInt8 * message_iter;

   blocks_count = bytes / CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH;
   residual_bytes = bytes % CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH;

   message_iter = message;
   while (blocks_count != 0) {
      cliauth_hash_sha2_64_digest_block(message_iter, digest);

      message_iter += CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH;
      blocks_count--;
   }

   padded_blocks_count = cliauth_hash_sha2_64_pad_message(
      message_iter,
      residual_bytes,
      padded_message_buffer,
      bytes
   );

   message_iter = padded_message_buffer;
   while (padded_blocks_count != 0) {
      cliauth_hash_sha2_64_digest_block(message_iter, digest);

      message_iter += CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH;
      padded_blocks_count--;
   }

   cliauth_hash_sha2_64_digest_finalize(digest);

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_HASH_SHA2_64 */

#if CLIAUTH_CONFIG_HASH_SHA224
/*----------------------------------------------------------------------------*/

static CliAuthUInt32
cliauth_hash_sha224_constants_initialize [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT] = {
   0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
   0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

void
cliauth_hash_sha224(const struct CliAuthHashContext * context) {
   CliAuthUInt32 digest [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];

   (void)memcpy(
      digest,
      cliauth_hash_sha224_constants_initialize,
      CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)
   );

   cliauth_hash_sha2_32_digest(
      digest,
      (const CliAuthUInt8 *)context->message,
      context->bytes
   );

   (void)memcpy(context->digest, digest, CLIAUTH_HASH_SHA224_DIGEST_LENGTH);

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */

#if CLIAUTH_CONFIG_HASH_SHA256
/*----------------------------------------------------------------------------*/

static CliAuthUInt32
cliauth_hash_sha256_constants_initialize [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT] = {
   0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void
cliauth_hash_sha256(const struct CliAuthHashContext * context) {
   CliAuthUInt32 digest [CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];

   (void)memcpy(
      digest,
      cliauth_hash_sha256_constants_initialize,
      CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)
   );

   cliauth_hash_sha2_32_digest(
      digest,
      (const CliAuthUInt8 *)context->message,
      context->bytes
   );

   (void)memcpy(context->digest, digest, CLIAUTH_HASH_SHA256_DIGEST_LENGTH);

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */

#if CLIAUTH_CONFIG_HASH_SHA384
/*----------------------------------------------------------------------------*/

static CliAuthUInt64
cliauth_hash_sha384_constants_initialize [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
   0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

void
cliauth_hash_sha384(const struct CliAuthHashContext * context) {
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];

   (void)memcpy(
      digest,
      cliauth_hash_sha384_constants_initialize,
      CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)
   );

   cliauth_hash_sha2_64_digest(
      digest,
      (const CliAuthUInt8 *)context->message,
      context->bytes
   );

   (void)memcpy(context->digest, digest, CLIAUTH_HASH_SHA384_DIGEST_LENGTH);

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */

#if CLIAUTH_CONFIG_HASH_SHA512
/*----------------------------------------------------------------------------*/

static CliAuthUInt64
cliauth_hash_sha512_constants_initialize [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
   0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

void
cliauth_hash_sha512(const struct CliAuthHashContext * context) {
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];

   (void)memcpy(
      digest,
      cliauth_hash_sha512_constants_initialize,
      CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)
   );

   cliauth_hash_sha2_64_digest(
      digest,
      (const CliAuthUInt8 *)context->message,
      context->bytes
   );

   (void)memcpy(context->digest, digest, CLIAUTH_HASH_SHA512_DIGEST_LENGTH);

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */

#if CLIAUTH_CONFIG_HASH_SHA512_224
/*----------------------------------------------------------------------------*/

static CliAuthUInt64
cliauth_hash_sha512_224_constants_initialize [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
   0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
};

void
cliauth_hash_sha512_224(const struct CliAuthHashContext * context) {
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];

   (void)memcpy(
      digest,
      cliauth_hash_sha512_224_constants_initialize,
      CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)
   );

   cliauth_hash_sha2_64_digest(
      digest,
      (const CliAuthUInt8 *)context->message,
      context->bytes
   );

   (void)memcpy(context->digest, digest, CLIAUTH_HASH_SHA512_224_DIGEST_LENGTH);

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */

#if CLIAUTH_CONFIG_HASH_SHA512_256
/*----------------------------------------------------------------------------*/

static CliAuthUInt64
cliauth_hash_sha512_256_constants_initialize [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT] = {
   0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
   0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
};

void
cliauth_hash_sha512_256(const struct CliAuthHashContext * context) {
   CliAuthUInt64 digest [CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];

   (void)memcpy(
      digest,
      cliauth_hash_sha512_256_constants_initialize,
      CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)
   );

   cliauth_hash_sha2_64_digest(
      digest,
      (const CliAuthUInt8 *)context->message,
      context->bytes
   );

   (void)memcpy(context->digest, digest, CLIAUTH_HASH_SHA512_256_DIGEST_LENGTH);

   return;
}

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */

