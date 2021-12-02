#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


void
parse_callback1(const uint8_t *data, size_t size) {
  printf("We are now in callback\n");

  if (size < 3) {
    return;
  } 

  if (data[0] == 'B') {
    printf("H3\n");
  }
  printf("H5\n");
}

void
parse_callback2(const uint8_t *data, size_t size) {
  printf("We are now in callback\n");

  if (size < 3) {
    return;
  } 

  if (data[0] == 'A') {
    printf("H1\n");
  }
  printf("H2\n");
}

int
parse(const uint8_t *data, size_t size) {
  void (*fun_ptr)(const uint8_t *, size_t); 

  if (size < 10) return 0;

  if (data[3] == 'C') {
    fun_ptr = parse_callback1;
  } else {
    fun_ptr = parse_callback2;
  }
  fun_ptr(data, size);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return parse(data, size);
}
