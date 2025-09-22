/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2025                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/test/crypto/i_hash.c - Hash function unit tests implementations.       */
/*----------------------------------------------------------------------------*/

#include "test/cliauth_test.h"
#include "test/crypto/i_hash.h"

#include "cliauth/cliauth.h"
#include "cliauth/io/log.h"
#include "cliauth/io/byte_array_mapper.h"
#include "cliauth/io/mapper_stream.h"
#include "cliauth/io/io.h"
#include "cliauth/crypto/hash.h"
#include "cliauth/memory/memory.h"

#include <inttypes.h>

static const CliAuthUInt8
cliauth_test_crypto_hash_message1 [] = {
   0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xf0, 0x0d
};

#define CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES \
   (sizeof(cliauth_test_crypto_hash_message1))

static const CliAuthUInt8
cliauth_test_crypto_hash_message2 [] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
   0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
   0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
   0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
   0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77
};

#define CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES \
   (sizeof(cliauth_test_crypto_hash_message2))

static const CliAuthUInt8
cliauth_test_crypto_hash_message3 [] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
   0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
   0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
   0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
   0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
   0xba, 0xad, 0xf0
};

#define CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES \
   (sizeof(cliauth_test_crypto_hash_message3))

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected,
   CliAuthUInt8 hash_index
) {
   const struct CliAuthCryptoHashFunction * hash_function;
   struct CliAuthIoByteArrayMapperReader message_byte_array_mapper_reader;
   struct CliAuthIoMapperReader message_mapper_reader;
   struct CliAuthIoMapperStreamReader message_mapper_stream_reader;
   struct CliAuthIoStreamReader message_stream_reader;
   struct CliAuthCryptoHashContext hash_context;
   CliAuthUInt32 message_bytes_remaining;
   struct CliAuthIoResult io_result;
   const CliAuthUInt8 * digest_calculated;

   hash_function = &cliauth_crypto_hash[hash_index];

   cliauth_io_byte_array_mapper_reader_initialize(
      &message_byte_array_mapper_reader,
      message
   );
   message_mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &message_byte_array_mapper_reader
   );
   cliauth_io_mapper_stream_reader_initialize(
      &message_mapper_stream_reader,
      &message_mapper_reader,
      message_bytes,
      CLIAUTH_LITERAL_UINT32(0u)
   );
   message_stream_reader = cliauth_io_mapper_stream_reader_interface(
      &message_mapper_stream_reader
   );

   hash_function->initialize(&hash_context);

   message_bytes_remaining = message_bytes;
   while (message_bytes_remaining != CLIAUTH_LITERAL_UINT32(0u)) {
      io_result = hash_function->digest(
         &hash_context,
         &message_stream_reader,
         message_bytes_remaining
      );
      message_bytes_remaining -= io_result.bytes;

      switch (io_result.status) {
         case CLIAUTH_IO_STATUS_SUCCESS:
         case CLIAUTH_IO_STATUS_BUSY:
            break;

         case CLIAUTH_IO_STATUS_END_OF_STREAM:
            cliauth_io_log(
               CLIAUTH_IO_LOG_ERROR("unexpectedly reached I/O end of stream with %" PRIu32 " undigested bytes"),
               message_bytes_remaining
            );
            return CLIAUTH_TEST_RUNNER_STATUS_FAILED;

         case CLIAUTH_IO_STATUS_ERROR_UNKNOWN:
            cliauth_io_log(
               CLIAUTH_IO_LOG_ERROR("unexpectedly encountered an unknown I/O error with %" PRIu32 " undigested bytes"),
               message_bytes_remaining
            );
            return CLIAUTH_TEST_RUNNER_STATUS_FAILED;

         default:
            CLIAUTH_UNREACHABLE;
      }
   }

   digest_calculated = hash_function->finalize(&hash_context);

   if (cliauth_memory_compare_with_equal_lengths(
      digest_expected,
      digest_calculated,
      hash_function->digest_length
   ) == CLIAUTH_BOOLEAN_FALSE) {
      cliauth_io_log(CLIAUTH_IO_LOG_ERROR("expected digest and calculated digest are not the same"));
      return CLIAUTH_TEST_RUNNER_STATUS_FAILED;
   }

   return CLIAUTH_TEST_RUNNER_STATUS_PASSED;
}

#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA1
/*----------------------------------------------------------------------------*/

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha1_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected
) {
   return cliauth_test_crypto_hash_runner(
      message,
      message_bytes,
      digest_expected,
      CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_HASH_INDEX_SHA1)
   );
}

static const CliAuthUInt8
cliauth_test_crypto_hash_sha1_digest_message1 [] = {
   0x46, 0x4c, 0xca, 0x64, 0xaa, 0xb5, 0x33, 0xf1,
   0xce, 0xf0, 0xfc, 0xed, 0xc8, 0xd8, 0x85, 0xc3,
   0xed, 0x71, 0x2f, 0xc4
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha1_digest_message2 [] = {
   0x82, 0x86, 0xaa, 0x9d, 0xf1, 0xd1, 0x57, 0xd7,
   0x0c, 0x47, 0x38, 0x25, 0xea, 0x72, 0x5f, 0x91,
   0x3e, 0xfd, 0x73, 0xac
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha1_digest_message3 [] = {
   0x1e, 0xc5, 0x66, 0x8c, 0xe8, 0xdb, 0x04, 0x11,
   0x0a, 0x29, 0x7d, 0x03, 0xd8, 0x76, 0x34, 0xa6,
   0x0e, 0x82, 0xe9, 0x0d
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha1_message1_runner(void) {
   return cliauth_test_crypto_hash_sha1_runner(
      cliauth_test_crypto_hash_message1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES),
      cliauth_test_crypto_hash_sha1_digest_message1
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha1_message2_runner(void) {
   return cliauth_test_crypto_hash_sha1_runner(
      cliauth_test_crypto_hash_message2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES),
      cliauth_test_crypto_hash_sha1_digest_message2
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha1_message3_runner(void) {
   return cliauth_test_crypto_hash_sha1_runner(
      cliauth_test_crypto_hash_message3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES),
      cliauth_test_crypto_hash_sha1_digest_message3
   );
}

#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE1_NODE_LABEL \
   "crypto/hash/sha1 (message 1)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha1_message1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha1_message1_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE2_NODE_LABEL \
   "crypto/hash/sha1 (message 2)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE2_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha1_message2_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha1_message2_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE3_NODE_LABEL \
   "crypto/hash/sha1 (message 3)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE3_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha1_message3_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA1_MESSAGE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha1_message3_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_NODE_LABEL \
   "crypto/hash/sha1"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_sha1_node_children [] = {
   &cliauth_test_crypto_hash_sha1_message1_node,
   &cliauth_test_crypto_hash_sha1_message2_node,
   &cliauth_test_crypto_hash_sha1_message3_node
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA1_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_sha1_node_children) / \
      sizeof(cliauth_test_crypto_hash_sha1_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA1_NODE_LABEL,
   cliauth_test_crypto_hash_sha1_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA1_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA1 */

#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_224
/*----------------------------------------------------------------------------*/

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_224_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected
) {
   return cliauth_test_crypto_hash_runner(
      message,
      message_bytes,
      digest_expected,
      CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_HASH_INDEX_SHA2_224)
   );
}

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_224_digest_message1 [] = {
   0xc7, 0xdc, 0x51, 0xde, 0xc4, 0x88, 0x1b, 0xf9,
   0x3d, 0x06, 0xda, 0x69, 0xd4, 0x7c, 0x66, 0x45,
   0xeb, 0x8d, 0x4c, 0x01, 0x2b, 0x95, 0xdc, 0xe7,
   0x07, 0x7f, 0x0e, 0xc5
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_224_digest_message2 [] = {
   0x37, 0x8b, 0xa8, 0x9b, 0xaa, 0xca, 0xeb, 0x26,
   0x1e, 0xc3, 0xb1, 0x86, 0x0f, 0xd2, 0xbc, 0x3a,
   0xf0, 0x08, 0x16, 0xa0, 0x6c, 0xdf, 0x13, 0xb6,
   0x8d, 0xa8, 0x7b, 0x46
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_224_digest_message3 [] = {
   0xe1, 0xca, 0x78, 0x7d, 0x92, 0x9f, 0xb0, 0x8a,
   0xda, 0xca, 0x11, 0xcb, 0x5c, 0x61, 0x8d, 0x37,
   0x0e, 0xc9, 0x47, 0xfc, 0xe1, 0xdd, 0x91, 0x17,
   0xf9, 0x64, 0x71, 0xea
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_224_message1_runner(void) {
   return cliauth_test_crypto_hash_sha2_224_runner(
      cliauth_test_crypto_hash_message1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES),
      cliauth_test_crypto_hash_sha2_224_digest_message1
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_224_message2_runner(void) {
   return cliauth_test_crypto_hash_sha2_224_runner(
      cliauth_test_crypto_hash_message2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES),
      cliauth_test_crypto_hash_sha2_224_digest_message2
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_224_message3_runner(void) {
   return cliauth_test_crypto_hash_sha2_224_runner(
      cliauth_test_crypto_hash_message3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES),
      cliauth_test_crypto_hash_sha2_224_digest_message3
   );
}

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE1_NODE_LABEL \
   "crypto/hash/sha2-224 (message 1)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_224_message1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_224_message1_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE2_NODE_LABEL \
   "crypto/hash/sha2-224 (message 2)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE2_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_224_message2_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_224_message2_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE3_NODE_LABEL \
   "crypto/hash/sha2-224 (message 3)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE3_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_224_message3_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_MESSAGE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_224_message3_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_NODE_LABEL \
   "crypto/hash/sha2-224"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_sha2_224_node_children [] = {
   &cliauth_test_crypto_hash_sha2_224_message1_node,
   &cliauth_test_crypto_hash_sha2_224_message2_node,
   &cliauth_test_crypto_hash_sha2_224_message3_node
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_sha2_224_node_children) / \
      sizeof(cliauth_test_crypto_hash_sha2_224_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_224_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_NODE_LABEL,
   cliauth_test_crypto_hash_sha2_224_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_224_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_224 */

#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_256
/*----------------------------------------------------------------------------*/

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_256_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected
) {
   return cliauth_test_crypto_hash_runner(
      message,
      message_bytes,
      digest_expected,
      CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_HASH_INDEX_SHA2_256)
   );
}

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_256_digest_message1 [] = {
   0x61, 0x69, 0x44, 0xca, 0x96, 0x91, 0x5f, 0x4a,
   0x82, 0xb0, 0x36, 0x16, 0xeb, 0xeb, 0x66, 0x33,
   0x14, 0xaa, 0xb4, 0x35, 0x92, 0x89, 0x1c, 0x03,
   0x7d, 0x98, 0xe6, 0xfd, 0xe5, 0x67, 0x20, 0x8b
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_256_digest_message2 [] = {
   0xca, 0xdd, 0x26, 0x36, 0x62, 0x2e, 0xb0, 0xd5,
   0x29, 0x6f, 0xba, 0x07, 0xbf, 0x04, 0xfd, 0x88,
   0x1c, 0xd6, 0x77, 0xac, 0x70, 0xad, 0xfc, 0x3d,
   0xda, 0x18, 0xd7, 0x37, 0x38, 0xde, 0xf7, 0x3f
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_256_digest_message3 [] = {
   0x32, 0x37, 0x08, 0x98, 0xc0, 0x72, 0x89, 0xba,
   0x80, 0x89, 0xe5, 0x6c, 0x92, 0x43, 0x03, 0xcf,
   0xa4, 0x89, 0x0d, 0x12, 0xba, 0xa9, 0x07, 0x07,
   0xa5, 0x2d, 0x4b, 0x10, 0x89, 0x9a, 0xad, 0xbc
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_256_message1_runner(void) {
   return cliauth_test_crypto_hash_sha2_256_runner(
      cliauth_test_crypto_hash_message1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES),
      cliauth_test_crypto_hash_sha2_256_digest_message1
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_256_message2_runner(void) {
   return cliauth_test_crypto_hash_sha2_256_runner(
      cliauth_test_crypto_hash_message2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES),
      cliauth_test_crypto_hash_sha2_256_digest_message2
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_256_message3_runner(void) {
   return cliauth_test_crypto_hash_sha2_256_runner(
      cliauth_test_crypto_hash_message3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES),
      cliauth_test_crypto_hash_sha2_256_digest_message3
   );
}

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE1_NODE_LABEL \
   "crypto/hash/sha2-256 (message 1)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_256_message1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_256_message1_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE2_NODE_LABEL \
   "crypto/hash/sha2-256 (message 2)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE2_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_256_message2_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_256_message2_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE3_NODE_LABEL \
   "crypto/hash/sha2-256 (message 3)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE3_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_256_message3_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_MESSAGE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_256_message3_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_NODE_LABEL \
   "crypto/hash/sha2-256"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_sha2_256_node_children [] = {
   &cliauth_test_crypto_hash_sha2_256_message1_node,
   &cliauth_test_crypto_hash_sha2_256_message2_node,
   &cliauth_test_crypto_hash_sha2_256_message3_node
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_sha2_256_node_children) / \
      sizeof(cliauth_test_crypto_hash_sha2_256_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_256_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_NODE_LABEL,
   cliauth_test_crypto_hash_sha2_256_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_256_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_256 */

#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_384
/*----------------------------------------------------------------------------*/

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_384_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected
) {
   return cliauth_test_crypto_hash_runner(
      message,
      message_bytes,
      digest_expected,
      CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_HASH_INDEX_SHA2_384)
   );
}

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_384_digest_message1 [] = {
   0xcd, 0x1d, 0xe4, 0x5a, 0xf3, 0x20, 0x98, 0xae,
   0xb6, 0x6f, 0xac, 0x39, 0x79, 0x1e, 0xfb, 0x2b,
   0x26, 0x30, 0xa4, 0x2b, 0x5a, 0x8f, 0xff, 0x6c,
   0xfa, 0x5f, 0xa8, 0xdc, 0x07, 0x31, 0x33, 0x9f,
   0xf6, 0xeb, 0xe9, 0x39, 0x58, 0xab, 0xcb, 0x78,
   0x1f, 0x8b, 0x4a, 0x74, 0x15, 0x9b, 0x2b, 0x54
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_384_digest_message2 [] = {
   0x7b, 0x0a, 0x39, 0x33, 0x16, 0xf6, 0x36, 0x6b,
   0x39, 0xe7, 0x7a, 0x4c, 0xd8, 0xf8, 0xa8, 0xfd,
   0xd7, 0x7c, 0x3f, 0x84, 0x1b, 0x22, 0xe4, 0xa4,
   0x8f, 0x3b, 0xc8, 0xf6, 0xd2, 0xdc, 0x2e, 0xe3,
   0x70, 0x99, 0x4b, 0x58, 0xc8, 0xfc, 0x3b, 0xfd,
   0xff, 0x31, 0x35, 0xfe, 0xf1, 0x1e, 0x2c, 0xd7
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_384_digest_message3 [] = {
   0x12, 0xc1, 0x88, 0x01, 0x49, 0x90, 0xee, 0xa5,
   0x0c, 0x12, 0x00, 0xa6, 0x54, 0x3c, 0x5f, 0x23,
   0x94, 0x8c, 0x05, 0xc4, 0x94, 0x5a, 0x09, 0xfa,
   0xa6, 0x46, 0x18, 0x22, 0xad, 0x71, 0xa2, 0xe5,
   0x02, 0x68, 0x90, 0x7d, 0xfb, 0x9a, 0x7a, 0x10,
   0xe5, 0x47, 0xad, 0x4b, 0xb4, 0x0e, 0x65, 0xbe
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_384_message1_runner(void) {
   return cliauth_test_crypto_hash_sha2_384_runner(
      cliauth_test_crypto_hash_message1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES),
      cliauth_test_crypto_hash_sha2_384_digest_message1
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_384_message2_runner(void) {
   return cliauth_test_crypto_hash_sha2_384_runner(
      cliauth_test_crypto_hash_message2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES),
      cliauth_test_crypto_hash_sha2_384_digest_message2
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_384_message3_runner(void) {
   return cliauth_test_crypto_hash_sha2_384_runner(
      cliauth_test_crypto_hash_message3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES),
      cliauth_test_crypto_hash_sha2_384_digest_message3
   );
}

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE1_NODE_LABEL \
   "crypto/hash/sha2-384 (message 1)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_384_message1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_384_message1_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE2_NODE_LABEL \
   "crypto/hash/sha2-384 (message 2)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE2_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_384_message2_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_384_message2_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE3_NODE_LABEL \
   "crypto/hash/sha2-384 (message 3)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE3_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_384_message3_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_MESSAGE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_384_message3_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_NODE_LABEL \
   "crypto/hash/sha2-384"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_sha2_384_node_children [] = {
   &cliauth_test_crypto_hash_sha2_384_message1_node,
   &cliauth_test_crypto_hash_sha2_384_message2_node,
   &cliauth_test_crypto_hash_sha2_384_message3_node
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_sha2_384_node_children) / \
      sizeof(cliauth_test_crypto_hash_sha2_384_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_384_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_NODE_LABEL,
   cliauth_test_crypto_hash_sha2_384_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_384_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_384 */

#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512
/*----------------------------------------------------------------------------*/

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected
) {
   return cliauth_test_crypto_hash_runner(
      message,
      message_bytes,
      digest_expected,
      CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_HASH_INDEX_SHA2_512)
   );
}

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_digest_message1 [] = {
   0x74, 0x9d, 0x8a, 0x30, 0xe2, 0xab, 0xd7, 0xd0,
   0x7e, 0x52, 0x7d, 0x8f, 0xe5, 0xea, 0xec, 0x4f,
   0x85, 0xe2, 0x3a, 0xa6, 0xa1, 0xee, 0x0e, 0x05,
   0x85, 0x18, 0xfc, 0xe3, 0x5c, 0x15, 0xab, 0x9a,
   0x3b, 0x0f, 0x72, 0xcc, 0xca, 0x0c, 0x3e, 0x18,
   0xd1, 0x55, 0xd9, 0x80, 0xd7, 0x05, 0xfd, 0x79,
   0x4d, 0x1b, 0xcb, 0x17, 0xf7, 0x5b, 0xbc, 0x94,
   0x99, 0x5a, 0x24, 0xd1, 0xc3, 0x9e, 0xde, 0x29
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_digest_message2 [] = {
   0x31, 0xb2, 0x35, 0xa0, 0xb0, 0x82, 0x7f, 0x45,
   0x5f, 0x3f, 0x07, 0x21, 0x1e, 0xfe, 0x44, 0xfd,
   0xfe, 0x8c, 0xff, 0x74, 0xeb, 0x1e, 0x2d, 0x78,
   0xdf, 0x73, 0x7d, 0x50, 0x0e, 0xd1, 0xbd, 0x5a,
   0xcd, 0x93, 0x77, 0xd9, 0x27, 0x4b, 0xdc, 0x7d,
   0x1f, 0xb5, 0x2a, 0xea, 0x5f, 0xf9, 0x59, 0x9e,
   0x5f, 0x12, 0xb8, 0x34, 0x93, 0xcc, 0x12, 0xff,
   0x7d, 0xf3, 0xac, 0x14, 0x3a, 0x1f, 0xfb, 0xad
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_digest_message3 [] = {
   0x88, 0x86, 0xc3, 0x67, 0x9e, 0x6a, 0x1b, 0x0e,
   0x5d, 0x8b, 0x37, 0x0d, 0x1e, 0xa0, 0x09, 0xca,
   0x8d, 0xc7, 0x91, 0x5f, 0xc3, 0x94, 0x24, 0x8b,
   0x6d, 0x61, 0x09, 0xb2, 0xb0, 0x61, 0xde, 0xa1,
   0xd5, 0x0d, 0xbd, 0xa3, 0xb2, 0xb4, 0x9a, 0xae,
   0x51, 0xdc, 0x49, 0x9f, 0x03, 0xaf, 0xe0, 0x7a,
   0xad, 0xc0, 0xeb, 0xf6, 0x39, 0x32, 0x74, 0x3c,
   0x24, 0x04, 0x6c, 0x18, 0xcd, 0x8f, 0x7c, 0x93
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_message1_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_runner(
      cliauth_test_crypto_hash_message1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES),
      cliauth_test_crypto_hash_sha2_512_digest_message1
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_message2_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_runner(
      cliauth_test_crypto_hash_message2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES),
      cliauth_test_crypto_hash_sha2_512_digest_message2
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_message3_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_runner(
      cliauth_test_crypto_hash_message3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES),
      cliauth_test_crypto_hash_sha2_512_digest_message3
   );
}

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE1_NODE_LABEL \
   "crypto/hash/sha2-512 (message 1)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_message1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_message1_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE2_NODE_LABEL \
   "crypto/hash/sha2-512 (message 2)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE2_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_message2_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_message2_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE3_NODE_LABEL \
   "crypto/hash/sha2-512 (message 3)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE3_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_message3_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_MESSAGE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_message3_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_NODE_LABEL \
   "crypto/hash/sha2-512"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_sha2_512_node_children [] = {
   &cliauth_test_crypto_hash_sha2_512_message1_node,
   &cliauth_test_crypto_hash_sha2_512_message2_node,
   &cliauth_test_crypto_hash_sha2_512_message3_node
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_sha2_512_node_children) / \
      sizeof(cliauth_test_crypto_hash_sha2_512_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_NODE_LABEL,
   cliauth_test_crypto_hash_sha2_512_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512 */

#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_224
/*----------------------------------------------------------------------------*/

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_224_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected
) {
   return cliauth_test_crypto_hash_runner(
      message,
      message_bytes,
      digest_expected,
      CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_HASH_INDEX_SHA2_512_224)
   );
}

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_224_digest_message1 [] = {
   0x2a, 0xe5, 0xd7, 0x1c, 0x34, 0xf9, 0xbd, 0x8c,
   0x1f, 0x27, 0xd1, 0x95, 0x89, 0x90, 0x86, 0x9d,
   0x9a, 0x30, 0xd9, 0x0c, 0xcc, 0x89, 0x90, 0x93,
   0x77, 0xed, 0xb1, 0x05
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_224_digest_message2 [] = {
   0xbc, 0x19, 0x06, 0xca, 0x44, 0x4d, 0xe2, 0x25,
   0x64, 0xb6, 0x98, 0x7b, 0xf4, 0x4f, 0x8c, 0x97,
   0xc8, 0xfd, 0x49, 0x08, 0x8b, 0x76, 0x12, 0x21,
   0x8b, 0xee, 0xa8, 0x03
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_224_digest_message3 [] = {
   0x53, 0x77, 0x1e, 0xe7, 0x05, 0x2d, 0x0f, 0xe3,
   0xed, 0xbc, 0x8c, 0xb3, 0xd8, 0x86, 0x5f, 0xbd,
   0x5b, 0x25, 0x34, 0x2f, 0x5b, 0xbc, 0x41, 0x1f,
   0x89, 0xa9, 0x51, 0xb5
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_224_message1_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_224_runner(
      cliauth_test_crypto_hash_message1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES),
      cliauth_test_crypto_hash_sha2_512_224_digest_message1
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_224_message2_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_224_runner(
      cliauth_test_crypto_hash_message2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES),
      cliauth_test_crypto_hash_sha2_512_224_digest_message2
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_224_message3_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_224_runner(
      cliauth_test_crypto_hash_message3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES),
      cliauth_test_crypto_hash_sha2_512_224_digest_message3
   );
}

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE1_NODE_LABEL \
   "crypto/hash/sha2-512-224 (message 1)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_224_message1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_224_message1_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE2_NODE_LABEL \
   "crypto/hash/sha2-512-224 (message 2)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE2_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_224_message2_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_224_message2_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE3_NODE_LABEL \
   "crypto/hash/sha2-512-224 (message 3)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE3_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_224_message3_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_MESSAGE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_224_message3_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_NODE_LABEL \
   "crypto/hash/sha2-512-224"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_sha2_512_224_node_children [] = {
   &cliauth_test_crypto_hash_sha2_512_224_message1_node,
   &cliauth_test_crypto_hash_sha2_512_224_message2_node,
   &cliauth_test_crypto_hash_sha2_512_224_message3_node
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_sha2_512_224_node_children) / \
      sizeof(cliauth_test_crypto_hash_sha2_512_224_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_224_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_NODE_LABEL,
   cliauth_test_crypto_hash_sha2_512_224_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_224_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_224 */

#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_256
/*----------------------------------------------------------------------------*/

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_256_runner(
   const CliAuthUInt8 * message,
   CliAuthUInt32 message_bytes,
   const CliAuthUInt8 * digest_expected
) {
   return cliauth_test_crypto_hash_runner(
      message,
      message_bytes,
      digest_expected,
      CLIAUTH_LITERAL_UINT8(CLIAUTH_CRYPTO_HASH_INDEX_SHA2_512_256)
   );
}

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_256_digest_message1 [] = {
   0x3e, 0xa3, 0x8d, 0x68, 0x20, 0xd2, 0x34, 0x44,
   0x06, 0x2d, 0x4d, 0x51, 0x2a, 0x42, 0x85, 0x9d,
   0x02, 0x75, 0x7e, 0xa2, 0x99, 0x51, 0xb8, 0x31,
   0x6c, 0xec, 0x62, 0x28, 0x62, 0xd6, 0x05, 0xa8
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_256_digest_message2 [] = {
   0x16, 0xca, 0x9b, 0x16, 0x07, 0xf9, 0x78, 0x5f,
   0x17, 0xae, 0x83, 0xb0, 0xe4, 0xd0, 0x25, 0x74,
   0x2e, 0x00, 0x3f, 0x4d, 0x6e, 0x2c, 0x3b, 0x50,
   0xf7, 0x21, 0xc2, 0xf9, 0x9d, 0xf3, 0x8f, 0x45
};

static const CliAuthUInt8
cliauth_test_crypto_hash_sha2_512_256_digest_message3 [] = {
   0x27, 0x49, 0x4a, 0xc8, 0xfa, 0x1a, 0x7b, 0x19,
   0x35, 0x9e, 0x10, 0x9d, 0xad, 0x26, 0xe3, 0x86,
   0xcc, 0x02, 0x1b, 0xb1, 0x21, 0x0a, 0x5a, 0x72,
   0x37, 0x2d, 0xdf, 0x8e, 0xbd, 0xe9, 0x12, 0xf2
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_256_message1_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_256_runner(
      cliauth_test_crypto_hash_message1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE1_BYTES),
      cliauth_test_crypto_hash_sha2_512_256_digest_message1
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_256_message2_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_256_runner(
      cliauth_test_crypto_hash_message2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE2_BYTES),
      cliauth_test_crypto_hash_sha2_512_256_digest_message2
   );
}

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_hash_sha2_512_256_message3_runner(void) {
   return cliauth_test_crypto_hash_sha2_512_256_runner(
      cliauth_test_crypto_hash_message3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_MESSAGE3_BYTES),
      cliauth_test_crypto_hash_sha2_512_256_digest_message3
   );
}

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE1_NODE_LABEL \
   "crypto/hash/sha2-512-256 (message 1)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE1_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_256_message1_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_256_message1_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE2_NODE_LABEL \
   "crypto/hash/sha2-512-256 (message 2)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE2_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_256_message2_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_256_message2_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE3_NODE_LABEL \
   "crypto/hash/sha2-512-256 (message 3)"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE3_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_256_message3_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_MESSAGE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_hash_sha2_512_256_message3_runner
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_NODE_LABEL \
   "crypto/hash/sha2-512-256"
#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_sha2_512_256_node_children [] = {
   &cliauth_test_crypto_hash_sha2_512_256_message1_node,
   &cliauth_test_crypto_hash_sha2_512_256_message2_node,
   &cliauth_test_crypto_hash_sha2_512_256_message3_node
};

#define CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_sha2_512_256_node_children) / \
      sizeof(cliauth_test_crypto_hash_sha2_512_256_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_hash_sha2_512_256_node = {
   CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_NODE_LABEL,
   cliauth_test_crypto_hash_sha2_512_256_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_SHA2_512_256_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_256 */

#define CLIAUTH_TEST_CRYPTO_HASH_NODE_LABEL \
   "crypto/hash"
#define CLIAUTH_TEST_CRYPTO_HASH_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_HASH_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_hash_node_children [] = {
#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA1
   &cliauth_test_crypto_hash_sha1_node,
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA1 */
#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_224
   &cliauth_test_crypto_hash_sha2_224_node,
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_224 */
#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_256
   &cliauth_test_crypto_hash_sha2_256_node,
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_256 */
#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_384
   &cliauth_test_crypto_hash_sha2_384_node,
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_384 */
#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512
   &cliauth_test_crypto_hash_sha2_512_node,
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512 */
#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_224
   &cliauth_test_crypto_hash_sha2_512_224_node,
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_224 */
#if CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_256
   &cliauth_test_crypto_hash_sha2_512_256_node,
#endif /* CLIAUTH_CONFIG_CRYPTO_HASH_SHA2_512_256 */
};

#define CLIAUTH_TEST_CRYPTO_HASH_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_hash_node_children) / \
      sizeof(cliauth_test_crypto_hash_node_children[0]) \
   )

const struct CliAuthTestNode
cliauth_test_crypto_hash_node = {
   CLIAUTH_TEST_CRYPTO_HASH_NODE_LABEL,
   cliauth_test_crypto_hash_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_HASH_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

