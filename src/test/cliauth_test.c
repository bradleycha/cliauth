/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2025                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/test/cliauth_test.c - Unit tests application entrypoint.               */
/*----------------------------------------------------------------------------*/

#include "test/cliauth_test.h"
#include "test/crypto/crypto.h"
#include "cliauth/cliauth.h"
#include "cliauth/io/log.h"

#include <inttypes.h>

/* the root list of unit tests */
static const struct CliAuthTestNode *
cliauth_test_root_nodes [] = {
   &cliauth_test_crypto_node
};

#define CLIAUTH_TEST_ROOT_NODES_COUNT \
   CLIAUTH_ARRAY_ELEMENTS(cliauth_test_root_nodes)

/* the number of failed and total unit tests for a particular node. */
struct CliAuthTestExecuteCount {
   /* the number of failed unit tests, with a maximum of 'total'. */
   CliAuthUInt32 failed;

   /* the total number of unit tests for the node. */
   CliAuthUInt32 total;
};

/* recursively executes all unit tests in the node, reporting failures along */
/* the way. */
static struct CliAuthTestExecuteCount
cliauth_test_execute_node(
   const struct CliAuthTestNode * node
) {
   struct CliAuthTestExecuteCount retn;
   enum CliAuthTestRunnerStatus status;
   const struct CliAuthTestNode ** children_iter;
   CliAuthUInt32 children_count;
   struct CliAuthTestExecuteCount child_execute_count;

   retn.failed = CLIAUTH_LITERAL_UINT32(0u);

   if (node->children_count == CLIAUTH_LITERAL_UINT32(0u)) {
      if (node->runner == CLIAUTH_NULLPTR) {
         retn.total = CLIAUTH_LITERAL_UINT32(0u);
         return retn;
      }

      status = node->runner();
      switch (status) {
         case CLIAUTH_TEST_RUNNER_STATUS_PASSED:
            break;
         case CLIAUTH_TEST_RUNNER_STATUS_FAILED:
            retn.failed = CLIAUTH_LITERAL_UINT32(1u);
            cliauth_io_log(
               CLIAUTH_IO_LOG_ERROR("test failed: %.*s"),
               node->label_characters,
               node->label
            );
            break;
         default:
            CLIAUTH_UNREACHABLE;
      }

      retn.total = CLIAUTH_LITERAL_UINT32(1u);
      return retn;
   }

   retn.total = CLIAUTH_LITERAL_UINT32(0u);

   children_iter = node->children;
   children_count = node->children_count;

   do {
      child_execute_count = cliauth_test_execute_node(*children_iter);

      retn.failed += child_execute_count.failed;
      retn.total += child_execute_count.total;

      children_iter++;
      children_count--;
   } while (children_count != CLIAUTH_LITERAL_UINT32(0u));

   if (retn.failed != CLIAUTH_LITERAL_UINT32(0u)) {
      cliauth_io_log(
         CLIAUTH_IO_LOG_WARNING("%" PRIu32 " tests failed for %.*s"),
         retn.failed,
         node->label_characters,
         node->label
      );
   }

   return retn;
}

#define CLIAUTH_TEST_ABOUT \
   CLIAUTH_PACKAGE_NAME " version " CLIAUTH_PACKAGE_VERSION " test runner"

/* Return status enum for cliauth_test_main(). */
#define CLIAUTH_TEST_EXIT_STATUS_FIELD_COUNT 3u
enum CliAuthTestExitStatus {
   /* The program executed successfully without any errors. */
   CLIAUTH_TEST_EXIT_STATUS_SUCCESS = 0u,

   /* An unknown test suite was passed. */
   CLIAUTH_TEST_EXIT_STATUS_UNKNOWN_TEST_SUITE = 1u,

   /* One or more tests failed. */
   CLIAUTH_TEST_EXIT_STATUS_TESTS_FAILED = 2u
};

static enum CliAuthTestExitStatus
cliauth_test_main(void) {
   struct CliAuthTestExecuteCount root_count;
   struct CliAuthTestExecuteCount node_count;
   const struct CliAuthTestNode ** children_iter;
   CliAuthUInt32 children_count;

   cliauth_io_log(CLIAUTH_IO_LOG_INFO(CLIAUTH_TEST_ABOUT));

   root_count.failed = CLIAUTH_LITERAL_UINT32(0u);
   root_count.total = CLIAUTH_LITERAL_UINT32(0u);

   children_iter = cliauth_test_root_nodes;
   children_count = CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_ROOT_NODES_COUNT);

   do {
      node_count = cliauth_test_execute_node(*children_iter);
      root_count.failed += node_count.failed;
      root_count.total += node_count.total;

      children_iter++;
      children_count--;
   } while (children_count != CLIAUTH_LITERAL_UINT32(0u));

   switch (root_count.failed) {
      case CLIAUTH_LITERAL_UINT32(0u):
         cliauth_io_log(
            CLIAUTH_IO_LOG_INFO("% " PRIu32 "/%" PRIu32 " tests passed, all tests passed :)"),
            root_count.total - root_count.failed,
            root_count.total
         );
         break;

      default:
         cliauth_io_log(
            CLIAUTH_IO_LOG_WARNING("% " PRIu32 "/%" PRIu32 " tests passed, %" PRIu32 " tests failed :("),
            root_count.total - root_count.failed,
            root_count.total,
            root_count.failed
         );
         break;
   };

   return CLIAUTH_TEST_EXIT_STATUS_SUCCESS;
}

int main(int argc, char * argv []) {
   enum CliAuthTestExitStatus exit_status;

   if (argc != 1) {
      cliauth_io_log(CLIAUTH_IO_LOG_WARNING("ignoring command-line arguments"));
      (void)argv;
   }

   exit_status = cliauth_test_main();

   return (int)exit_status;
}

