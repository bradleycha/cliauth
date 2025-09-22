/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/test/cliauth_test.h - Global project header which contains common      */
/*    structs and definitions.                                                */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_TEST_H
#define _CLIAUTH_TEST_H
/*----------------------------------------------------------------------------*/

#include "cliauth/cliauth.h"

/*----------------------------------------------------------------------------*/
/* The result of an individual unit test.                                     */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_TEST_RUNNER_STATUS_PASSED -                                        */
/*    The unit test passed successfully.                                      */
/*                                                                            */
/* CLIAUTH_TEST_RUNNER_STATUS_FAILED -                                        */
/*    The unit test failed and should be reported to the user.                */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_TEST_RUNNER_STATUS_FIELD_COUNT 2u
enum CliAuthTestRunnerStatus {
   CLIAUTH_TEST_RUNNER_STATUS_PASSED,
   CLIAUTH_TEST_RUNNER_STATUS_FAILED
};

/*----------------------------------------------------------------------------*/
/* A function which runs a particular unit test.                              */
/*----------------------------------------------------------------------------*/
/* Return value -                                                             */
/*    Whether the unit test passed or failed.                                 */
/*----------------------------------------------------------------------------*/
typedef enum CliAuthTestRunnerStatus (*CliAuthTestUnitFunctionRunner)(void);

/*----------------------------------------------------------------------------*/
/* Defines a unit test node and its children.                                 */
/*----------------------------------------------------------------------------*/
/* label -                                                                    */
/*    The display name for the unit test.  This is how the unit test will be  */
/*    both shown to and identified by those running the unit test.            */
/*                                                                            */
/* children -                                                                 */
/*    An array of child unit tests to run when invoked.                       */
/*                                                                            */
/* label_characters -                                                         */
/*    The length of 'label' in characters.                                    */
/*                                                                            */
/* children_count -                                                           */
/*    The length of 'children' in characters.                                 */
/*                                                                            */
/* runner -                                                                   */
/*    The test runner function to execute.  This field is only valid when     */
/*    'children_count' is zero, i.e. when this is a leaf node.                */
/*----------------------------------------------------------------------------*/
struct CliAuthTestNode {
   const char *                     label;
   const struct CliAuthTestNode **  children;
   CliAuthUInt32                    label_characters;
   CliAuthUInt32                    children_count;
   CliAuthTestUnitFunctionRunner    runner;
};

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_TEST_H */

