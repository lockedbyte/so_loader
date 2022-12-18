#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
unsigned int __xlf_hash(unsigned char *word) {
	unsigned int hash = 0;
	for (int i = 0 ; word[i] != '\0' && word[i] != '@' ; i++)
		hash = 31*hash + word[i];
	return hash;
}
*/

/* 
   hash algorithm for strings (Jenkins One At A Time)
     Ref: https://en.wikipedia.org/wiki/Jenkins_hash_function
*/
uint32_t jenkings_one_at_a_time(char *key, size_t len) {
	uint32_t hash = 0, i = 0;

	for(hash = i = 0; i < len; ++i) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}

/* String-view wrapper for Jenkins One At A Time hash algorithm */

uint32_t __xlf_hash(char *str) {
	return jenkings_one_at_a_time(str, strlen(str));
}

int main(int argc, char *argv[]) {
	uint32_t hash_out = 0;

	if(argc != 2) {
		printf("[i] Usage: %s <string>\n", argv[0]);
		exit(0);
	}
	
	hash_out = __xlf_hash(argv[1]);
	printf("[i] '%s' => 0x%x\n", argv[1], hash_out);
	return 0;
}


