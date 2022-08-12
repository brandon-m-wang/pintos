/* Open a file and read 25 bytes from it. Call tell and check if pointer is in correct location. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  char* file_name = "sample.txt";
  int position;
  int handle;
  char buffer[512];
  int ret_code;

  /* Keep opening new files, their pointers should be independent of each other. */
  for (int i = 0; i < 5; i++) {
    handle = open(file_name);
    if (handle < 2) {
      fail("first open() returned %d", handle);
    }

    /* Check if output matches */
    ret_code = read(handle, buffer, 25);
    if (ret_code == -1) {
      fail("Failed read.");
    }

    position = tell(handle);

    if (position != 25) {
      fail("Failed to give correct position of frist file read/write pointer.");
    }
  }
}