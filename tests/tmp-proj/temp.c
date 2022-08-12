#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "fuzz.h"	

void execute_sys1(char *directory) {
  if (strlen(directory) > 70) {
    return;
  }
  char cmd[80];
  sprintf(cmd, "ls -la %s", directory);
  system(cmd);
}

void execute_sys2(char *directory) {
  if (strcmp(directory, "/tmp/") == 0) {
    char cmd[80];
    sprintf(cmd, "ls -la %s", directory);
    system(cmd);
  }
}

void execute_sys3(char *cmd) {
  system("ls -la /tmp/");
}

void execute_sys4(char *directory) {
  if (strlen(directory) > 70) {
    return;
  }
  char cmd[80];
  sprintf(cmd, "%s", directory);
  system(cmd);
}

void check_directory(char *directory, int api) {
  if (api == 1) {
    execute_sys1(directory);
  }
  else if (api == 2) {
    execute_sys2(directory);
  }
  else if (api == 3) {
    execute_sys3(directory);
  }
  // Intentionally commented out
  //else {
  //  execute_sys4(directory);
  //}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 5) {
	  return 0;
  }
  char *s1 = (char*)malloc(size+1);
  memcpy(s1, data, size);
  s1[size] = '\0';

  check_directory(s1, 2);
  check_directory(s1, 3);

  print_helloworld();
  return 0;
}
