/* Open a file and make a seek syscall. Read 10 characters from the file and compare output to check if position of the file read/write pointer was moved. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include <string.h>

void test_main(void) {

  char* file_name = "sample.txt";
  int handle;
  char buffer[512];
  int ret_code;
  char* correct_output = "Electronic";
  char* correct_output2 = "\"Amazing";
  int handle2;
  int ret_code2;
  char buffer2[512];

  /* Keep opening new files, their pointers should be independent of each other. */
  handle = open(file_name);
  if (handle < 2) {
    fail("First open() returned %d", handle);
  }

  /* Open the same file. Files pointers should be independent. */
  handle2 = open(file_name);
  if (handle < 2) {
    fail("First open() returned %d", handle);
  }

  /* Move file pointer 9 characters ahead. */
  seek(handle, 9);

  /* Check if output matches */
  ret_code = read(handle, buffer, 10);
  if (ret_code == -1) {
    fail("Failed read.");
  }

  if (strcmp(correct_output, buffer) != 0) {
    fail("%s", buffer);
  }

  /* Open the same file and read from the start. Files pointers should be independent. */
  handle2 = open(file_name);
  if (handle < 2) {
    fail("First open() returned %d", handle);
  }

  /* Move file pointer 9 characters ahead. */
  seek(handle, 9);

  /* Check if output matches */
  ret_code = read(handle, buffer, 10);
  if (ret_code == -1) {
    fail("Failed read.");
  }

  if (strcmp(correct_output, buffer) != 0) {
    fail("%s", buffer);
  }

  /* Read 8 characters into buffer2, should be '"Amazing' because files should be independent. */
  ret_code2 = read(handle2, buffer2, 8);
  if (ret_code2 == -1) {
    fail("Failed read.");
  }

  /* Check if output matches */
  if (strcmp(correct_output2, buffer2) != 0) {
    fail("%s", buffer2);
  }
}