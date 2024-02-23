#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct dummy dummy_session;

struct dummy{
    char *d1;
    int d2;
    int d3;
};

void zipzup3(char **d, int v, char *e) {
  if (d == 0xdeadbeef) {
    printf("Hep hey\n");
  }
  else {
    printf("Zingu\n");
  }
  if (strcmp(e, "ds;lk") == 0) {
    printf("check\n");
  }
}

void zipzup2(char **d, char *e) {
  if (d == 0xdeadbeef) {
    printf("Hep hey\n");
  }
  else {
    printf("Zingu\n");
  }
  if (strcmp(e, "ds;lk") == 0) {
    printf("check\n");
  }
}

void zipzup(char **d) {
  if (d == 0xdeadbeef) {
    printf("Hep hey\n");
  }
  else {
    printf("Zingu\n");
  }
}

void hepehey(dummy_session *d1) {
	printf("Dummy hep hey %d\n", d1->d2);
}

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
