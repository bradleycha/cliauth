/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/hash.h - Header for hashing algorithms                                 */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_HASH_H
#define _CLIAUTH_HASH_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

/*----------------------------------------------------------------------------*/
/* Stores the number of enabled hash algorithms, useful for storing buffer    */
/* lengths.                                                                   */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_HASH_ENABLED_COUNT (\
      CLIAUTH_CONFIG_HASH_SHA1 +\
      CLIAUTH_CONFIG_HASH_SHA224 +\
      CLIAUTH_CONFIG_HASH_SHA256 +\
      CLIAUTH_CONFIG_HASH_SHA384 +\
      CLIAUTH_CONFIG_HASH_SHA512 +\
      CLIAUTH_CONFIG_HASH_SHA512_224 +\
      CLIAUTH_CONFIG_HASH_SHA512_256\
   )

#if CLIAUTH_HASH_ENABLED_COUNT == 0
#error all hash algorithms are disabled.  please verify the build was configured correctly.
#endif

/* enable shared constants and functions for 32-bit SHA-2 hash functions */
#define _CLIAUTH_HASH_SHA2_32\
   (\
      CLIAUTH_CONFIG_HASH_SHA224 ||\
      CLIAUTH_CONFIG_HASH_SHA256\
   )

/* enable shared constants and functions for SHA1 and SHA2-32 functions */
#define _CLIAUTH_HASH_SHA1_2_32\
   (\
      CLIAUTH_CONFIG_HASH_SHA1 ||\
      _CLIAUTH_HASH_SHA2_32\
   )

/* enable shared constants and functions for 64-bit SHA-2 hash functions */
#define _CLIAUTH_HASH_SHA2_64\
   (\
      CLIAUTH_CONFIG_HASH_SHA384 ||\
      CLIAUTH_CONFIG_HASH_SHA512 ||\
      CLIAUTH_CONFIG_HASH_SHA512_224 ||\
      CLIAUTH_CONFIG_HASH_SHA512_256\
   )

/* enable shared constants and functions for all SHA-2 hash functions */
#define _CLIAUTH_HASH_SHA2\
   (\
      _CLIAUTH_HASH_SHA2_32 ||\
      _CLIAUTH_HASH_SHA2_64\
   )

/* enable shared constants and functions for all SHA1 and SHA2 function */
#define _CLIAUTH_HASH_SHA1_2\
   (\
      CLIAUTH_CONFIG_HASH_SHA1 ||\
      _CLIAUTH_HASH_SHA2\
   )

/*----------------------------------------------------------------------------*/
/* Generic hash function pointers.                                            */
/*----------------------------------------------------------------------------*/
/* context - Pointer to a function-specific context struct instance as        */
/*           defined in the function's documentation.  The internal state of  */
/*           the context should be considered private, and thus should not be */
/*           read or modified unless the function's documentation permits it. */
/*                                                                            */
/* message - Pointer to arbitrary byte data of length 'bytes' to be digested  */
/*           by the hash function.                                            */
/*                                                                            */
/* bytes - The number of bytes to digest from 'message'.                      */
/*                                                                            */
/* digest - A byte buffer to store the final hash value in.  The length of    */
/*          the buffer should be at least the size defined in the function's  */
/*          documentation.                                                    */
/*----------------------------------------------------------------------------*/
typedef void (*CliAuthHashFunctionInitialize)(void * context);
typedef void (*CliAuthHashFunctionDigest)(void * context, const void * message, CliAuthUInt32 bytes);
typedef void (*CliAuthHashFunctionFinalize)(void * context, void * digest);

/*----------------------------------------------------------------------------*/
/* A generic hash function represented by its function pointers.              */
/*----------------------------------------------------------------------------*/
/* initialize - Initializes the hash function's context, and makes it valid   */
/*              to call 'digest' using the context.                           */
/*                                                                            */
/* digest - Digests a given array of arbitrary data.                          */
/*                                                                            */
/* finalize - Finalizes the hash function and writes the digest, invalidating */
/*            the internal state.  To start a new hash, 'initialize' must be  */
/*            called again.                                                   */
/*----------------------------------------------------------------------------*/
struct CliAuthHashFunction {
   CliAuthHashFunctionInitialize initialize;
   CliAuthHashFunctionDigest     digest;
   CliAuthHashFunctionFinalize   finalize;
};

#if _CLIAUTH_HASH_SHA1_2
/*----------------------------------------------------------------------------*/

/* internal struct for storing the ring buffer context */
struct _CliAuthHashSha12RingBufferContext {
   /* stores the total number of bytes that have been digested */
   CliAuthUInt64 total;

   /* stores the current capacity of the ring buffer */
   CliAuthUInt8 capacity;
};

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA1_2 */

#if CLIAUTH_CONFIG_HASH_SHA1
/*----------------------------------------------------------------------------*/

/* constants for SHA1 */
#define _CLIAUTH_HASH_SHA1_BLOCK_LENGTH\
   64
#define _CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT\
   5
#define _CLIAUTH_HASH_SHA1_ROUNDS_COUNT\
   80
#define _CLIAUTH_HASH_SHA1_MESSAGE_SCHEDULE_LENGTH\
   _CLIAUTH_HASH_SHA1_ROUNDS_COUNT
#define _CLIAUTH_HASH_SHA1_ROUNDS_CONSTANTS_LENGTH\
   4

/*----------------------------------------------------------------------------*/
/* Context struct to be used with the SHA1 function.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthHashContextSha1 {
   CliAuthUInt32 digest [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT];
   CliAuthUInt32 work [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT];
   CliAuthUInt32 schedule [_CLIAUTH_HASH_SHA1_MESSAGE_SCHEDULE_LENGTH];
   CliAuthUInt8 ring_buffer [_CLIAUTH_HASH_SHA1_BLOCK_LENGTH];
   struct _CliAuthHashSha12RingBufferContext ring_context;
};

/*----------------------------------------------------------------------------*/
/* SHA1 function.                                                             */
/*----------------------------------------------------------------------------*/
/* The type of 'context' should be CliAuthHashContextSha1.                    */
/*                                                                            */
/* The length of 'digest' is CLIAUTH_HASH_SHA1_DIGEST_LENGTH.                 */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_HASH_SHA1_INPUT_BLOCK_LENGTH _CLIAUTH_HASH_SHA1_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA1_DIGEST_LENGTH 20
extern const struct CliAuthHashFunction
cliauth_hash_sha1;

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
   
#if _CLIAUTH_HASH_SHA2_32
/*----------------------------------------------------------------------------*/

/* constants for 32-bit SHA2 */
#define _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH\
   64
#define _CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT\
   8
#define _CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT\
   64
#define _CLIAUTH_HASH_SHA2_32_MESSAGE_SCHEDULE_LENGTH\
   _CLIAUTH_HASH_SHA2_32_ROUNDS_COUNT

/*----------------------------------------------------------------------------*/
/* Context struct to be used with SHA2-32 class functions.                    */
/*----------------------------------------------------------------------------*/
struct CliAuthHashContextSha232 {
   /* the current state of the hash digest */
   CliAuthUInt32 digest [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];

   /* used internally by the block digest function */
   CliAuthUInt32 work [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];

   /* used internally by the block digest function */
   CliAuthUInt32 schedule [_CLIAUTH_HASH_SHA2_32_MESSAGE_SCHEDULE_LENGTH];

   /* the ring buffer bytes */
   CliAuthUInt8 ring_buffer [_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH];

   /* the ring buffer context */
   struct _CliAuthHashSha12RingBufferContext ring_context;

};

/*----------------------------------------------------------------------------*/
/* SHA2-32 class functions.                                                   */
/*----------------------------------------------------------------------------*/
/* The type of 'context' should be CliAuthHashContextSha232.                  */
/*                                                                            */
/* The length of 'digest' is CLIAUTH_HASH_SHA224_DIGEST_LENGTH or             */
/* CLIAUTH_HASH_SHA256_DIGEST_LENGTH, depending on the specific algorithm.    */
/*----------------------------------------------------------------------------*/

#if CLIAUTH_CONFIG_HASH_SHA224
#define CLIAUTH_HASH_SHA224_INPUT_BLOCK_LENGTH _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA224_DIGEST_LENGTH 28
extern const struct CliAuthHashFunction
cliauth_hash_sha224;
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */

#if CLIAUTH_CONFIG_HASH_SHA256
#define CLIAUTH_HASH_SHA256_INPUT_BLOCK_LENGTH _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA256_DIGEST_LENGTH 32
extern const struct CliAuthHashFunction
cliauth_hash_sha256;
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA2_32 */

#if _CLIAUTH_HASH_SHA2_64
/*----------------------------------------------------------------------------*/

/* constants for 64-bit SHA2 */
#define _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH\
   128
#define _CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT\
   8
#define _CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT\
   80
#define _CLIAUTH_HASH_SHA2_64_MESSAGE_SCHEDULE_LENGTH\
   _CLIAUTH_HASH_SHA2_64_ROUNDS_COUNT

/*----------------------------------------------------------------------------*/
/* Context struct to be used with SHA2-64 class functions.                    */
/*----------------------------------------------------------------------------*/
struct CliAuthHashContextSha264 {
   CliAuthUInt64 digest [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];
   CliAuthUInt64 work [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];
   CliAuthUInt64 schedule [_CLIAUTH_HASH_SHA2_64_MESSAGE_SCHEDULE_LENGTH];
   CliAuthUInt8 ring_buffer [_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH];
   struct _CliAuthHashSha12RingBufferContext ring_context;
};

/*----------------------------------------------------------------------------*/
/* SHA2-64 class functions.                                                   */
/*----------------------------------------------------------------------------*/
/* The type of 'context' should be CliAuthHashContextSha264.                  */
/*                                                                            */
/* The length of 'digest' is CLIAUTH_HASH_SHA384_DIGEST_LENGTH,               */
/* CLIAUTH_HASH_SHA512_DIGEST_LENGTH, CLIAUTH_HASH_SHA512_224_DIGEST_LENGTH,  */
/* or CLIAUTH_HASH_SHA512_256_DIGEST_LENGTH, depending on the specific        */
/* algorithm.                                                                 */
/*----------------------------------------------------------------------------*/

#if CLIAUTH_CONFIG_HASH_SHA384
#define CLIAUTH_HASH_SHA384_INPUT_BLOCK_LENGTH _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA384_DIGEST_LENGTH 48
extern const struct CliAuthHashFunction
cliauth_hash_sha384;
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */

#if CLIAUTH_CONFIG_HASH_SHA512
#define CLIAUTH_HASH_SHA512_INPUT_BLOCK_LENGTH _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA512_DIGEST_LENGTH 64
extern const struct CliAuthHashFunction
cliauth_hash_sha512;
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */

#if CLIAUTH_CONFIG_HASH_SHA512_224
#define CLIAUTH_HASH_SHA512_224_INPUT_BLOCK_LENGTH _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA512_224_DIGEST_LENGTH 28
extern const struct CliAuthHashFunction
cliauth_hash_sha512_224;
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */

#if CLIAUTH_CONFIG_HASH_SHA512_256
#define CLIAUTH_HASH_SHA512_256_INPUT_BLOCK_LENGTH _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA512_256_DIGEST_LENGTH 32
extern const struct CliAuthHashFunction
cliauth_hash_sha512_256;
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA2_64 */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_H */

