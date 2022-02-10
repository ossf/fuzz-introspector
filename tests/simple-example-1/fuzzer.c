#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int
compare_mem(const uint8_t *data) {
  if (data[0] == 'A')  return 1;
  return 0;
}

void
parse_callback1(const uint8_t *data, size_t size) {
  printf("We are now in callback\n");

  if (size < 3) return;
  if (compare_mem(data) == 0) printf("H3\n");

  printf("H5\n");
}


void
parse_callback2(const uint8_t *data, size_t size, size_t *thep) {
  printf("We are now in callback\n");

  if (size < 3) return;
  if (data[0] == 'A') printf("H1\n");

  printf("H2\n");
}


int
parse1(const uint8_t *data, size_t size) {
  if (size < 10) return 0;
  parse_callback1(data, size);
  return 0;
}

int
parse2(const uint8_t *data, size_t size) {
  int total_val = 0;
  if (size == 1) total_val++;
  if (size == 2) total_val++;
  if (size == 3) total_val++;
  if (size == 4) total_val++;

  if (size < 5) {
    return total_val;
  }

  if (data[0] == 'A' && data[1] == 'R') total_val += 2;
  if (data[0] == 'B' && data[1] == 'Q') total_val += 2;
  if (data[0] == 'C' && data[1] == 'P') total_val += 2;
  if (data[0] == 'D' && data[1] == 'O') total_val += 2;
  if (data[0] == 'E' && data[1] == 'N') total_val += 2;
  if (data[0] == 'F' && data[1] == 'M') total_val += 2;

  data += 3;
  if (compare_mem(data) == 0) total_val++;

  return total_val;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return parse1(data, size);
}
