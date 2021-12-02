#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


int unreached_target2(const uint8_t *data) {
        return 5;
}


int unreached_target1(const uint8_t *data) {
    if (data[0] == 0x11) {
        return unreached_target2(data);
    }
    char *mc = (char*)malloc(12);
    if (data[0] == 0x12) {
        return 0;
    }
    return 5;
}

int un(char *n1, char *n2, char *n3, char *n5, size_t s1) {
  return 0;
}

int unreached_target3(const uint8_t *data, size_t *theval) {
    if (data[0] == 0x11) {
        return unreached_target1(data);
    }

    return 5;
}

char *d = {0x12};
int target2(const uint8_t *data) {
	if (data[0] == 0x41) return 1;
    unreached_target1(d);
	return 2;
}

int target3(const uint8_t *data) {
	if (data[0] == 0x42) return 4;
	return 3;
}

int fuzz_entry(const uint8_t *data, size_t size) {
	int ret;
	if (size == 2) {
		ret = target2(data);
	} 
	else if (size == 3) {
		ret = target3(data);
	}
	else {
		ret = 1;
	}
	return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *kldfj = (char*)malloc(123);
    fuzz_entry(data, size);
    return 0;
}

