#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

void run(void) {
	puts("Hello from lib_sample.so!");
	return;
}

__attribute__ ((constructor)) void init(void) {
	puts("Lib initialized successfully!");
	return;
}
