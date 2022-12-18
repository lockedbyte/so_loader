/*

*/

#pragma once

#include <stdint.h>
#include <elf.h>

typedef enum {
	UNKNOWN_MODE = 0,
	MODE_REFLECTIVE_ELF_LOADER,
	MODE_HOOK_INJ,
	MODE_INMEM_API_LOAD
} load_mode_t;

int load_lib(char *lb_name, void *addr, size_t size, void **out_addr, size_t *out_sz, int mode);
void *resolve_func(void *lib, const char *func_str, int mode);
void unload_lib(void *addr, size_t size);
