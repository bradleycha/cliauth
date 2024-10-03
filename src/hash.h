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
#include "io.h"

/*----------------------------------------------------------------------------*/
/* Stores the number of enabled hash algorithms, useful for storing buffer    */
/* lengths.                                                                   */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_HASH_ENABLED_COUNT (\
      CLIAUTH_CONFIG_HASH_SHA1 +\
      CLIAUTH_CONFIG_HASH_SHA2_224 +\
      CLIAUTH_CONFIG_HASH_SHA2_256 +\
      CLIAUTH_CONFIG_HASH_SHA2_384 +\
      CLIAUTH_CONFIG_HASH_SHA2_512 +\
      CLIAUTH_CONFIG_HASH_SHA2_512_224 +\
      CLIAUTH_CONFIG_HASH_SHA2_512_256\
   )

#if CLIAUTH_HASH_ENABLED_COUNT == 0
#error all hash algorithms are disabled.  please verify the build was configured correctly.
#endif

/* enable shared constants and functions for 32-bit SHA2 hash functions */
#define _CLIAUTH_HASH_SHA2_32\
   (\
      CLIAUTH_CONFIG_HASH_SHA2_224 ||\
      CLIAUTH_CONFIG_HASH_SHA2_256\
   )

/* enable shared constants and functions for SHA1 and SHA2-32 functions */
#define _CLIAUTH_HASH_SHA1_2_32\
   (\
      CLIAUTH_CONFIG_HASH_SHA1 ||\
      _CLIAUTH_HASH_SHA2_32\
   )

/* enable shared constants and functions for 64-bit SHA2 hash functions */
#define _CLIAUTH_HASH_SHA2_64\
   (\
      CLIAUTH_CONFIG_HASH_SHA2_384 ||\
      CLIAUTH_CONFIG_HASH_SHA2_512 ||\
      CLIAUTH_CONFIG_HASH_SHA2_512_224 ||\
      CLIAUTH_CONFIG_HASH_SHA2_512_256\
   )

/* enable shared constants and functions for all SHA2 hash functions */
#define _CLIAUTH_HASH_SHA2\
   (\
      _CLIAUTH_HASH_SHA2_32 ||\
      _CLIAUTH_HASH_SHA2_64\
   )

/* enable shared constants and functions for all SHA1 and SHA2 functions */
#define _CLIAUTH_HASH_SHA1_2\
   (\
      CLIAUTH_CONFIG_HASH_SHA1 ||\
      _CLIAUTH_HASH_SHA2\
   )

/* forward declaration of context type required */
struct CliAuthHashContext;

/*----------------------------------------------------------------------------*/
/* Hash function to initialize a generic context.                             */
/*----------------------------------------------------------------------------*/
/* context - The hash function context to initialize.                         */
/*----------------------------------------------------------------------------*/
typedef void (*CliAuthHashFunctionInitialize)(
   struct CliAuthHashContext * context
);

/*----------------------------------------------------------------------------*/
/* Digest an arbitrary amount of data.                                        */
/*----------------------------------------------------------------------------*/
/* context - The hash function context to digest the message into.  The       */
/*           context must first be initialized.                               */
/*                                                                            */
/* message_reader - The reader for the data to digest.                        */
/*                                                                            */
/* message_bytes - The number of bytes to read from 'message_reader'.         */
/*----------------------------------------------------------------------------*/
/* Return value - The result of reading the message from 'message_reader'.    */
/*                If the returned read result status is not                   */
/*                'CLIAUTH_IO_READ_STATUS_SUCCESS', the number of digested    */
/*                bytes can be obtained from the 'bytes' field in the         */
/*                returned read result.                                       */
/*----------------------------------------------------------------------------*/
typedef struct CliAuthIoReadResult (*CliAuthHashFunctionDigest)(
   struct CliAuthHashContext * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
);

/*----------------------------------------------------------------------------*/
/* Finalizes a hash function and generates a digest value.                    */
/*----------------------------------------------------------------------------*/
/* context - The hash function context to finalize.  The context must first   */
/*           be initialized and optionally contain digested byte data.        */
/*           Calling this function requires the context to be re-initialized  */
/*           before digesting again.                                          */
/*----------------------------------------------------------------------------*/
/* Return value - A pointer to the final digest value.  This value will only  */
/*                be valid for the lifetime of the hash context and will be   */
/*                invalidated by re-initialization.  The length of the        */
/*                returned buffer containing the digest depends on the hash   */
/*                algorithm.  The byte length of the output digest value can  */
/*                be found from 'CLIAUTH_HASH_*_DIGEST_LENGTH'.               */
/*----------------------------------------------------------------------------*/
typedef CliAuthUInt8 * (*CliAuthHashFunctionFinalize)(
   struct CliAuthHashContext * context
);

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
/*                                                                            */
/* identifier - The string identifier for the hash algorithm.                 */
/*                                                                            */
/* identifier_characters - The length of 'identifier' in characters.          */
/*                                                                            */
/* input_block_length - The length of a single input block, in bytes.         */
/*                                                                            */
/* digest_length - The length of the output digest value, in bytes.           */
/*----------------------------------------------------------------------------*/
struct CliAuthHashFunction {
   CliAuthHashFunctionInitialize initialize;
   CliAuthHashFunctionDigest     digest;
   CliAuthHashFunctionFinalize   finalize;
   const char *                  identifier;
   CliAuthUInt32                 identifier_characters;
   CliAuthUInt8                  input_block_length;
   CliAuthUInt8                  digest_length;
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

union _CliAuthHashContextAlgorithmSha1Digest {
   CliAuthUInt8 bytes [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)];
   CliAuthUInt32 words [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT];
};
union _CliAuthHashContextAlgorithmSha1Schedule {
   CliAuthUInt8 bytes [_CLIAUTH_HASH_SHA1_MESSAGE_SCHEDULE_LENGTH * sizeof(CliAuthUInt32)];
   CliAuthUInt32 words [_CLIAUTH_HASH_SHA1_MESSAGE_SCHEDULE_LENGTH];
};

struct _CliAuthHashContextAlgorithmSha1 {
   union _CliAuthHashContextAlgorithmSha1Digest digest;
   union _CliAuthHashContextAlgorithmSha1Schedule schedule;
   CliAuthUInt32 work [_CLIAUTH_HASH_SHA1_DIGEST_WORDS_COUNT];
   CliAuthUInt8 ring_buffer [_CLIAUTH_HASH_SHA1_BLOCK_LENGTH];
   struct _CliAuthHashSha12RingBufferContext ring_context;
};

/*----------------------------------------------------------------------------*/
/* SHA1 function.                                                             */
/*----------------------------------------------------------------------------*/
/* The length of 'digest' is CLIAUTH_HASH_SHA1_DIGEST_LENGTH.                 */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_HASH_SHA1_INPUT_BLOCK_LENGTH\
   _CLIAUTH_HASH_SHA1_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA1_DIGEST_LENGTH\
   20
#define CLIAUTH_HASH_SHA1_IDENTIFIER\
   "sha1"
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


/* internal union to allow treating word arrays as byte arrays */
union _CliAuthHashContextAlgorithmSha232Digest {
   CliAuthUInt8 bytes [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)];
   CliAuthUInt32 words [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];
};
union _CliAuthHashContextAlgorithmSha232Schedule {
   CliAuthUInt8 bytes [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt32)];
   CliAuthUInt32 words [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];
};

struct _CliAuthHashContextAlgorithmSha232 {
   /* the current state of the hash digest */
   union _CliAuthHashContextAlgorithmSha232Digest digest;

   /* used internally by the block digest function */
   union _CliAuthHashContextAlgorithmSha232Schedule schedule;

   /* used internally by the block digest functionm */
   CliAuthUInt32 work [_CLIAUTH_HASH_SHA2_32_DIGEST_WORDS_COUNT];

   /* the ring buffer bytes */
   CliAuthUInt8 ring_buffer [_CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH];

   /* the ring buffer context */
   struct _CliAuthHashSha12RingBufferContext ring_context;

};

/*----------------------------------------------------------------------------*/
/* SHA2-32 class functions.                                                   */
/*----------------------------------------------------------------------------*/
/* The length of 'digest' is CLIAUTH_HASH_SHA2_224_DIGEST_LENGTH or           */
/* CLIAUTH_HASH_SHA2_256_DIGEST_LENGTH, depending on the specific algorithm.  */
/*----------------------------------------------------------------------------*/

#if CLIAUTH_CONFIG_HASH_SHA2_224
#define CLIAUTH_HASH_SHA2_224_INPUT_BLOCK_LENGTH\
   _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA2_224_DIGEST_LENGTH\
   28
#define CLIAUTH_HASH_SHA2_224_IDENTIFIER\
   "sha224"
extern const struct CliAuthHashFunction
cliauth_hash_sha2_224;
#endif /* CLIAUTH_CONFIG_HASH_SHA2_224 */

#if CLIAUTH_CONFIG_HASH_SHA2_256
#define CLIAUTH_HASH_SHA2_256_INPUT_BLOCK_LENGTH\
   _CLIAUTH_HASH_SHA2_32_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA2_256_DIGEST_LENGTH\
   32
#define CLIAUTH_HASH_SHA2_256_IDENTIFIER\
   "sha256"
extern const struct CliAuthHashFunction
cliauth_hash_sha2_256;
#endif /* CLIAUTH_CONFIG_HASH_SHA2_256 */

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

union _CliAuthHashContextAlgorithmSha264Digest {
   CliAuthUInt8 bytes [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)];
   CliAuthUInt64 words [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];
};
union _CliAuthHashContextAlgorithmSha264Schedule {
   CliAuthUInt8 bytes [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT * sizeof(CliAuthUInt64)];
   CliAuthUInt64 words [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];
};

struct _CliAuthHashContextAlgorithmSha264 {
   union _CliAuthHashContextAlgorithmSha264Digest digest;
   union _CliAuthHashContextAlgorithmSha264Schedule schedule;
   CliAuthUInt64 work [_CLIAUTH_HASH_SHA2_64_DIGEST_WORDS_COUNT];
   CliAuthUInt8 ring_buffer [_CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH];
   struct _CliAuthHashSha12RingBufferContext ring_context;
};

/*----------------------------------------------------------------------------*/
/* SHA2-64 class functions.                                                   */
/*----------------------------------------------------------------------------*/
/* The length of 'digest' is CLIAUTH_HASH_SHA2_384_DIGEST_LENGTH,             */
/* CLIAUTH_HASH_SHA2_512_DIGEST_LENGTH,                                       */
/* CLIAUTH_HASH_SHA2_512_224_DIGEST_LENGTH, or                                */
/* CLIAUTH_HASH_SHA2_512_256_DIGEST_LENGTH, depending on the specific         */
/* algorithm.                                                                 */
/*----------------------------------------------------------------------------*/

#if CLIAUTH_CONFIG_HASH_SHA2_384
#define CLIAUTH_HASH_SHA2_384_INPUT_BLOCK_LENGTH\
   _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA2_384_DIGEST_LENGTH\
   48
#define CLIAUTH_HASH_SHA2_384_IDENTIFIER\
   "sha384"
extern const struct CliAuthHashFunction
cliauth_hash_sha2_384;
#endif /* CLIAUTH_CONFIG_HASH_SHA2_384 */

#if CLIAUTH_CONFIG_HASH_SHA2_512
#define CLIAUTH_HASH_SHA2_512_INPUT_BLOCK_LENGTH\
   _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA2_512_DIGEST_LENGTH\
   64
#define CLIAUTH_HASH_SHA2_512_IDENTIFIER\
   "sha512"
extern const struct CliAuthHashFunction
cliauth_hash_sha2_512;
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512 */

#if CLIAUTH_CONFIG_HASH_SHA2_512_224
#define CLIAUTH_HASH_SHA2_512_224_INPUT_BLOCK_LENGTH\
   _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA2_512_224_DIGEST_LENGTH\
   28
#define CLIAUTH_HASH_SHA2_512_224_IDENTIFIER\
   "sha512/224"
extern const struct CliAuthHashFunction
cliauth_hash_sha2_512_224;
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_224 */

#if CLIAUTH_CONFIG_HASH_SHA2_512_256
#define CLIAUTH_HASH_SHA2_512_256_INPUT_BLOCK_LENGTH\
   _CLIAUTH_HASH_SHA2_64_BLOCK_LENGTH
#define CLIAUTH_HASH_SHA2_512_256_DIGEST_LENGTH\
   32
#define CLIAUTH_HASH_SHA2_512_256_IDENTIFIER\
   "sha512/256"
extern const struct CliAuthHashFunction
cliauth_hash_sha2_512_256;
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_256 */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_SHA2_64 */

union _CliAuthHashContextAlgorithm {
#if CLIAUTH_CONFIG_HASH_SHA1
   struct _CliAuthHashContextAlgorithmSha1 sha1;
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if _CLIAUTH_HASH_SHA2_32
   struct _CliAuthHashContextAlgorithmSha232 sha2_32;
#endif /* _CLIAUTH_HASH_SHA2_32 */
#if _CLIAUTH_HASH_SHA2_64
   struct _CliAuthHashContextAlgorithmSha264 sha2_64;
#endif /* _CLIAUTH_HASH_SHA2_64 */
};

/*----------------------------------------------------------------------------*/
/* Generic hash context data used internally to execute any hash algorithm.   */
/*----------------------------------------------------------------------------*/
struct CliAuthHashContext {
   union _CliAuthHashContextAlgorithm algorithm;
};

union _CliAuthHashMaximumInputBlockLength {
#if CLIAUTH_CONFIG_HASH_SHA1
   CliAuthUInt8 sha1 [CLIAUTH_HASH_SHA1_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA2_224
   CliAuthUInt8 sha2_224 [CLIAUTH_HASH_SHA2_224_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_256
   CliAuthUInt8 sha2_256 [CLIAUTH_HASH_SHA2_256_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_256 */
#if CLIAUTH_CONFIG_HASH_SHA2_384
   CliAuthUInt8 sha2_384 [CLIAUTH_HASH_SHA2_384_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_384 */
#if CLIAUTH_CONFIG_HASH_SHA2_512
   CliAuthUInt8 sha2_512 [CLIAUTH_HASH_SHA2_512_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_224
   CliAuthUInt8 sha2_512_224 [CLIAUTH_HASH_SHA2_512_224_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_256
   CliAuthUInt8 sha2_512_256 [CLIAUTH_HASH_SHA2_512_256_INPUT_BLOCK_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_256 */
};

/*----------------------------------------------------------------------------*/
/* The maximum possible length of any hash input block, in bytes.             */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_HASH_MAXIMUM_INPUT_BLOCK_LENGTH\
   (sizeof(union _CliAuthHashMaximumInputBlockLength))

union _CliAuthHashMaximumDigestLength {
#if CLIAUTH_CONFIG_HASH_SHA1
   CliAuthUInt8 sha1 [CLIAUTH_HASH_SHA1_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA1 */
#if CLIAUTH_CONFIG_HASH_SHA2_224
   CliAuthUInt8 sha2_224 [CLIAUTH_HASH_SHA2_224_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_256
   CliAuthUInt8 sha2_256 [CLIAUTH_HASH_SHA2_256_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_256 */
#if CLIAUTH_CONFIG_HASH_SHA2_384
   CliAuthUInt8 sha2_384 [CLIAUTH_HASH_SHA2_384_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_384 */
#if CLIAUTH_CONFIG_HASH_SHA2_512
   CliAuthUInt8 sha2_512 [CLIAUTH_HASH_SHA2_512_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_224
   CliAuthUInt8 sha2_512_224 [CLIAUTH_HASH_SHA2_512_224_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_224 */
#if CLIAUTH_CONFIG_HASH_SHA2_512_256
   CliAuthUInt8 sha2_512_256 [CLIAUTH_HASH_SHA2_512_256_DIGEST_LENGTH];
#endif /* CLIAUTH_CONFIG_HASH_SHA2_512_256 */
};

/*----------------------------------------------------------------------------*/
/* The maximum possible length of any hash digest value, in bytes.            */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_HASH_MAXIMUM_DIGEST_LENGTH\
   (sizeof(union _CliAuthHashMaximumDigestLength))

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_H */

