#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#if __GNUC__
#if __x86_64__ || __ppc64__
#include "elf_x86_64_ldr.h"
#else
#include "elf_x86_ldr.h"
#endif
#endif

char *get_lb_name_from_path(char *path) {
	char *name = NULL;
	char *tmp_ptr = NULL;
	int i = 0;
	
	tmp_ptr = strchr(path, '/');
	if(!tmp_ptr)
		return strdup(path);
		
	tmp_ptr = path + strlen(path) - 1;
	
	while(i < strlen(path)) {
		if(*tmp_ptr == '/') {
			tmp_ptr++;
			return strdup(tmp_ptr);
		}
		tmp_ptr--;
		i++;
	}
	
	return NULL;
}

int main(int argc, char *argv[]) {
	FILE *fp = NULL;
	void *addr = NULL;
	size_t size = 0;
	size_t out_sz = 0;
	void *lib_addr = NULL;
	void *func_addr = NULL;
	void (*fptr)(char *) = NULL;
	struct stat st;
	int mode = 0;
	
	if(argc != 4) {
		printf("[i] Usage: %s <lib path> <function> <mode>\n", argv[0]);
		printf("\nAvailable modes:\n\n[i] 1 => Reflective ELF Loader\n[i] 2 => ELF Loader using dynamic-linker hooks\n[i] 3 => Inmem API loader via memfd_create()\n\n");
		exit(0);
	}
	
	mode = atoi(argv[3]);
	if(mode < 1 || mode > 3) {
		puts("[-] Unknown mode");
		exit(1);
	}
	
	stat(argv[1], &st);
	size = st.st_size;
	
	fp = fopen(argv[1], "r");
	if(!fp) {
		puts("[-] Error opening provided path");
		exit(1);
	}
	
	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(addr == MAP_FAILED) {
		puts("[-] mmap() failed!");
		exit(1);
	}
	
	fread(addr, size, sizeof(char), fp);
	
	if(fp)
		fclose(fp);
	
	if(!load_lib(get_lb_name_from_path(argv[1]), addr, size, &lib_addr, &out_sz, mode) || !lib_addr) {
		puts("[-] Failed loading provided library");
		exit(1);
	}
	
	printf("[+] Loaded library '%s' @ %p\n", argv[1], lib_addr);
	
	func_addr = resolve_func(lib_addr, argv[2], mode);
	if(!func_addr) {
		puts("[-] Error resolving provided function");
		exit(1);
	}
	
	printf("[+] Resolved function '%s' @ %p\n", argv[2], func_addr);
		
	fptr = func_addr;
	printf("[*] Calling function %s @ %p\n", argv[2], func_addr);
	fptr("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	
	printf("[i] Unloading now the shared object...\n");
	unload_lib(addr, out_sz);
	
	puts("[+] Test completed successfully!");
	
	return 0;
}



