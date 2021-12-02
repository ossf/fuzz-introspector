#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>



void
print_stuff() {
    printf("Hello world\n");
}

void proxy(void (*a)(), int val){
  if (val == 123123) {
    a();
  }
  printf("Hup\n");
}

int
parse1(const uint8_t *data, size_t size) {
  proxy(print_stuff, size);
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return parse1(data, size);
}
