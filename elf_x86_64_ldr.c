/*

...

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdint.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <syscall.h>

#include "elf_x86_64_ldr.h"

#define ENABLE_API_INMEM_LOAD 1
#define ENABLE_HOOK_INJ_LOAD 1
#define ENABLE_ELF_LOADER_LOAD 1

#define LD_DEBUG 0

#define PAGE_SIZE 0x1000
#define _E_OBF_XOR_K 0x03

#define MAX_MAPS_SIZE 4096*6

#define LD_NAME "\x6f\x67\x2e\x6f\x6a\x6d\x76\x7b\x2e\x7b\x3b\x35\x2e\x35\x37\x2d\x70\x6c\x2d\x31" /* "ld-linux-x86-64.so.2" */
#define MAGIC_PATHNAME "\x6f\x6a\x61\x60\x73\x73\x2e\x32\x32\x2d\x70\x6c\x2d\x30" /* "libcpp-11.so.3" */
#define MAGIC_FD_COOKIE 0x74

#define MAX_MEMFD_NAME 256
#define MAX_MEMFD_PATH 18
#define MAPS_FILE "\x2c\x73\x71\x6c\x60\x2c\x70\x66\x6f\x65\x2c\x6e\x62\x73\x70" /* "/proc/self/maps" */
#define MEMFD_NAME "\x6f\x6a\x61\x60\x2d\x70\x6c\x2d\x32" /* "libc.so.1" */
#define LIBC_DL_NAME "\x6f\x6a\x61\x60\x2d\x70\x6c\x2d\x35" /* "libc.so.6" */

#define PAGE_SIZE 0x1000

#define PAGE_ALIGN(addr) ((addr & ~(PAGE_SIZE-1)) + PAGE_SIZE)
#define SIZE_ALIGN(size) ((size & ~(PAGE_SIZE-1)) + PAGE_SIZE)

#define DYNSYM_HASH  0x24362d7a /* .dynsym */
#define DYNSTR_HASH  0x4b4807b1 /* .dynstr */
#define GOTPLT_HASH  0xa8a99053 /* .got.plt */
#define RELAPLT_HASH 0x3689eaf0 /* .rela.plt */
#define RELADYN_HASH 0xfe3a4686 /* .rela.dyn */
#define DYNAMIC_HASH 0xdb5f48e0 /* .dynamic */

#define MAX_CONCURRENT_ELF_MODULES 256

uint8_t elf_magic_x[] = { 0x7f, 'E', 'L', 'F', 0};

int e_def_lock = 0;
int gen_load_lock = 0;

typedef struct __elf_mod_def {
	int in_use;
	void *orig_elf_file;
	size_t orig_elf_file_sz;
	void *mapped_elf;
	const char *name;
} elf_mod_def;

elf_mod_def *__elf_defs = NULL;

typedef struct _x_lib_def_t {
    void *data;
    int size;
    int current;
} x_lib_def_t;

x_lib_def_t __x_lib_def;

char *__edeobf_str(const char *__optr) {
	char *__tptr = NULL;
	
	__tptr = calloc(strlen(__optr) + 1, sizeof(char));
	if(!__tptr)
		return NULL; /* nothing to do in this situation */

	for(int i = 0 ; i < strlen(__optr) ; i++)
		__tptr[i] = __optr[i] ^ _E_OBF_XOR_K;
		
	return __tptr;
}

int check_magic(void *addr) {
	int ret = 0;
	if(memcmp(addr, elf_magic_x, 4) == 0)
		ret = 1;
	return ret;
}

void *memdup(const void *mem, size_t size) { 
	void *out = calloc(size, sizeof(char));
	if(!out)
		return NULL;
	memcpy(out, mem, size);
	return out;
}

void __s_lock(int *x) {
	if(!x)
		return;
	while(*x)
		sleep(0.1);
	*x = 1;
	return;
}

void __s_unlock(int *x) {
	if(!x)
		return;
	*x = 0;
	return;
}

/* TODO: add sanity checks to prevent mem corruption */
void *__custom_func_resolve(void *lib, const char *func_str) {
	void *func_addr = NULL;
	void *e_func_addr = NULL;
	Elf64_Ehdr *elf_ehdr = NULL;
	Elf64_Shdr *shdr = NULL;
	Elf64_Phdr *phdr = NULL;
	Elf64_Sym *sym = NULL;
	char *sname = NULL;
	uint64_t ptl_seg_off = 0;
	uint64_t ptl_seg_va_s = 0;
	uint64_t ptl_seg_off_s = 0;
	uint64_t ptl_seg_sz = 0;
	uint64_t ptl_seg_va = 0;
	uint64_t relative_pt_off = 0;
	char *sdata = NULL;
	void *st_elf = NULL;
	int num = 0;
	int idx_def = -1;

	if(!check_magic(lib))
		return NULL;
		
	__s_lock(&e_def_lock);
	
	if(!__elf_defs) {
		__s_unlock(&e_def_lock);
		return NULL;
	}
			
	for(int i = 0 ; i < MAX_CONCURRENT_ELF_MODULES ; i++) {
		if(__elf_defs[i].in_use && __elf_defs[i].mapped_elf == lib) {
			idx_def = i;
			break;
		}
	}
	
	if(idx_def == -1) {
		__s_unlock(&e_def_lock);
		return NULL;
	}
		
	st_elf = __elf_defs[idx_def].orig_elf_file;
	if(!st_elf) {
		__s_unlock(&e_def_lock);
		return NULL;
	}
	
	__s_unlock(&e_def_lock);
	
	elf_ehdr = (Elf64_Ehdr *)st_elf;
	shdr = (Elf64_Shdr *)(st_elf + elf_ehdr->e_shoff);
	phdr = (Elf64_Phdr *)(st_elf + elf_ehdr->e_phoff);
	sname = (char *)(st_elf + shdr[elf_ehdr->e_shstrndx].sh_addr);
	
	for(int i = 0 ; i < elf_ehdr->e_shnum ; i++) {
		if(shdr[i].sh_type != SHT_DYNSYM)
			continue;
			
		sym = (Elf64_Sym *)(st_elf + shdr[i].sh_addr);
		num = shdr[i].sh_size / shdr[i].sh_entsize;
		sdata = (char *)st_elf + shdr[shdr[i].sh_link].sh_addr;
		
		for(int j = 0 ; j < num ; j++) {
			if(strcmp(sdata + sym[j].st_name, func_str) == 0) {
				func_addr = (void *)sym[j].st_value;
				goto END_RSOLV;
			}
		}
	}

END_RSOLV:
	if(!func_addr)
		return NULL;
		
	e_func_addr = lib + (off_t)func_addr;

	return e_func_addr;
}

void *__dlsym_func_resolve(void *lib, const char *func_str) {
	void *func_addr = NULL;

	func_addr = dlsym(lib, func_str);
	if(!func_addr)
		return NULL;
	
	return func_addr;
}

/* 
   hash algorithm for strings (Jenkins One At A Time)
     Ref: https://en.wikipedia.org/wiki/Jenkins_hash_function
*/
uint32_t x_jenkings_one_at_a_time(char *key, size_t len) {
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
	return x_jenkings_one_at_a_time(str, strlen(str));
}

/*
unsigned int __xlf_hash(unsigned char *word) {
	unsigned int hash = 0;
	for (int i = 0 ; word[i] != '\0' && word[i] != '@' ; i++)
		hash = 31*hash + word[i];
	return hash;
}
*/

int __hash_sec_rsolve(unsigned int sec_hash, Elf64_Shdr *_sec_l, unsigned char *__sh_strtab, unsigned int n_sec) {
	unsigned char *sec_name = NULL;	
	for(int i = 0; i < n_sec; i++) {
		sec_name = __sh_strtab + _sec_l[i].sh_name;
		if(__xlf_hash(sec_name) == sec_hash)
			return i;
	}
	return -1;
}

#if ENABLE_ELF_LOADER_LOAD

/*
  1.- Create every segment using mmap() + brk() at load base plus Phdr-specified virtual addresses 
  2.- Iterate over every segment definition and copy the disk-elf-version data into the mmap'ed memory region
  3.- Load all DT_NEEDED libraries
  4.- Apply necessary relocations
  5.- mprotect() every segment with the proper permissions (from initial RW to the needed ones)
  6.- Resolve PLT/GOT references
  7.- Invoke init
*/
/* TODO: add sanity checks to prevent memory corruption */
void *__reflective_elf_sl_load(char *lb_name, void *addr, size_t size, size_t *out_sz) {
	size_t out_size = 0;
	size_t tot_mapping_sz = 0;
	uint64_t last_vaddr = 0;
	int mem_prot = 0;
	int num = 0;
	size_t needed_n = 0;
	size_t n_pg = 0;
	size_t dyn_x_num = 0;
	unsigned int z = 0;
	int idx_x = 0;
	int def_index = -1;
	size_t init_array_sz = 0;
	void **init_array = NULL;
	void *tmp_ptr = NULL;
	void *hdlptr = NULL;
	void **lb_hdl = NULL;
	void (* init_fptr)() = NULL;
	void *lib_addr = NULL;
	Elf64_Dyn *dyn = NULL;
	Elf64_Ehdr *elf_ehdr = NULL;
	Elf64_Shdr *shdr = NULL;
	Elf64_Phdr *phdr = NULL;
	Elf64_Shdr *dyn_x_sec = NULL;
	Elf64_Dyn *dyn_x = NULL;
	Elf64_Shdr *rela_plt_sec = NULL;
	Elf64_Rela *rela_plt = NULL;
	Elf64_Shdr *rela_dyn_sec = NULL;
	Elf64_Rela *rela_dyn = NULL;
	Elf64_Sym *dyn_sym = NULL;
	Elf64_Shdr *dyn_str_sec = NULL;
	Elf64_Shdr *got_plt_sec = NULL;
	unsigned char *dyn_str = NULL;
	unsigned char *_sh_strtab_x = NULL;
	void *(*__fp_mmapx)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
	int (*__fp_mprotectx)(void *addr, size_t len, int prot) = NULL;
	char *s_name = NULL;
	void *f_addr = NULL;
	char *sdata = NULL;

	__s_lock(&e_def_lock);
	
	if(!__elf_defs)
		__elf_defs = (elf_mod_def *)calloc(MAX_CONCURRENT_ELF_MODULES, sizeof(elf_mod_def));
		
	for(int i = 0 ; i < MAX_CONCURRENT_ELF_MODULES ; i++) {
		if(__elf_defs[i].in_use == 1)
			continue;
		def_index = i;
	}
	
	if(def_index == -1) {
		__s_unlock(&e_def_lock);
		return NULL;
	}
	
	__elf_defs[def_index].in_use = 1;
	
	__s_unlock(&e_def_lock);
	
	if(!out_sz) {
		__elf_defs[def_index].in_use = 0;
		return NULL;
	}
	
	if(!check_magic(addr)) {
		__elf_defs[def_index].in_use = 0;
		return NULL;
	}
	
	if(size <= sizeof(Elf64_Ehdr)) {
		__elf_defs[def_index].in_use = 0;
		return NULL;
	}

	#if LD_DEBUG
		printf("[i] Parsing ELF object...\n");
	#endif
	
	elf_ehdr = (Elf64_Ehdr *)addr;
	shdr = (Elf64_Shdr *)(addr + elf_ehdr->e_shoff);
	phdr = (Elf64_Phdr *)(addr + elf_ehdr->e_phoff);
	_sh_strtab_x = (unsigned char *)(addr + shdr[elf_ehdr->e_shstrndx].sh_offset);
	
	for(int i = 0 ; i < elf_ehdr->e_phnum ; i++) {

		if(phdr[i].p_type != PT_LOAD)
			continue;
			
		if(phdr[i].p_memsz > phdr[i].p_align)
			n_pg = 1 + (phdr[i].p_memsz - phdr[i].p_memsz % phdr[i].p_align) / phdr[i].p_align;
		else
			n_pg = 1;
			
		tot_mapping_sz += phdr[i].p_align * n_pg;
	}
	
	tot_mapping_sz += 0x4000;

	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return NULL;
	
	__fp_mmapx = dlsym(hdlptr, __edeobf_str("\x6e\x6e\x62\x73")); /* "mmap" */
	if(!__fp_mmapx)
		return NULL;
		
	__fp_mprotectx = dlsym(hdlptr, __edeobf_str("\x6e\x73\x71\x6c\x77\x66\x60\x77")); /* "mprotect" */
	if(!__fp_mprotectx)
		return NULL;
		
	lib_addr = __fp_mmapx(NULL, tot_mapping_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(lib_addr == MAP_FAILED) {
		__elf_defs[def_index].in_use = 0;
		return NULL;
	}
		
	for(int i = 0 ; i < elf_ehdr->e_phnum ; i++) {

		if(phdr[i].p_type != PT_LOAD)
			continue;

		tmp_ptr = lib_addr + phdr[i].p_vaddr;
		if(tmp_ptr >= lib_addr + tot_mapping_sz) {
			#if LD_DEBUG
				puts("[-] OOB check failure");
			#endif
			__elf_defs[def_index].in_use = 0;
			return NULL;
		}
				
		if(phdr[i].p_memsz > phdr[i].p_filesz) {
			/* XXX: requires special treatment; is this the good way to go? */
			memcpy(tmp_ptr, addr + phdr[i].p_offset, phdr[i].p_filesz);
			memset(tmp_ptr + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);
		} else if(phdr[i].p_memsz == phdr[i].p_filesz)	
			memcpy(tmp_ptr, addr + phdr[i].p_offset, phdr[i].p_memsz); 
		else {
			__elf_defs[def_index].in_use = 0;
			return NULL; /* memory size is less than disk size? */
		}	
	}

	idx_x = __hash_sec_rsolve(DYNAMIC_HASH, shdr, _sh_strtab_x, elf_ehdr->e_shnum);
	if(idx_x == -1)
		return NULL;
		
	dyn_x_sec = (Elf64_Shdr *)(&shdr[idx_x]);
	dyn_x_num = shdr[idx_x].sh_size / shdr[idx_x].sh_entsize;
	dyn_x = lib_addr + dyn_x_sec->sh_addr;
		
	idx_x = __hash_sec_rsolve(DYNSTR_HASH, shdr, _sh_strtab_x, elf_ehdr->e_shnum);
	if(idx_x == -1)
		return NULL;
		
	dyn_str_sec = (Elf64_Shdr *)(&shdr[idx_x]);
	dyn_str = lib_addr + dyn_str_sec->sh_addr;
		
	idx_x = __hash_sec_rsolve(RELAPLT_HASH, shdr, _sh_strtab_x, elf_ehdr->e_shnum);
	if(idx_x == -1)
		return NULL;
		
	rela_plt_sec = (Elf64_Shdr *)(&shdr[idx_x]);
	rela_plt = lib_addr + rela_plt_sec->sh_addr;
		
	idx_x = __hash_sec_rsolve(RELADYN_HASH, shdr, _sh_strtab_x, elf_ehdr->e_shnum);
	if(idx_x == -1)
		return NULL;
		
	rela_dyn_sec = (Elf64_Shdr *)(&shdr[idx_x]);
	rela_dyn = lib_addr + rela_dyn_sec->sh_addr;
		
	idx_x = __hash_sec_rsolve(GOTPLT_HASH, shdr, _sh_strtab_x, elf_ehdr->e_shnum);
	if(idx_x == -1)
		return NULL;
		
	got_plt_sec = (Elf64_Shdr *)(&shdr[idx_x]);
		
	for(int i = 0 ; dyn_x[i].d_tag != DT_NULL ; i++) {
		if(dyn_x[i].d_tag == DT_SYMTAB) {
			idx_x = __hash_sec_rsolve(DYNSYM_HASH, shdr, _sh_strtab_x, elf_ehdr->e_shnum);
			if(idx_x == -1)
				return NULL;
				
			dyn_sym = lib_addr + dyn_x[i].d_un.d_ptr;
		}
	}
	
	#if LD_DEBUG
		printf("\t[i] ELF ehdr = %p\n", elf_ehdr);
		printf("\t[i] ELF phdr = %p\n", phdr);
		printf("\t[i] ELF shdr = %p\n", shdr);
		printf("\t[i] base = %p\n", lib_addr);
		printf("\t[i] dyn_x = %p\n", dyn_x);
		printf("\t[i] dyn_str = %p\n", dyn_str);
		printf("\t[i] rela_plt = %p\n", rela_plt);
		printf("\t[i] rela_dyn = %p\n", rela_dyn);
		printf("\t[i] got_plt_sec = %p\n", got_plt_sec);
	#endif
	
	#if LD_DEBUG
		printf("[i] Loading DT_NEEDED libraries...\n");
	#endif
	
	/* load all DT_NEEDED libraries */
	for(int i = 0 ; dyn_x[i].d_tag != DT_NULL ; i++) {
		if(dyn_x[i].d_tag == DT_NEEDED)
			needed_n++;
	}
	
	lb_hdl = calloc(needed_n, sizeof(void *));
	if(!lb_hdl)
		return NULL;
		
	#if LD_DEBUG
		printf("\t[i] There are %ld dependencies!\n", needed_n);
		printf("\t[i] lb_hdl = %p\n", lb_hdl);
	#endif
	
	for(int i = 0 ; dyn_x[i].d_tag != DT_NULL && z < needed_n ; i++) {
		if(dyn_x[i].d_tag == DT_NEEDED) {
			#if LD_DEBUG
				printf("\t[i] Loading: %s (%p)...\n", dyn_str + dyn_x[i].d_un.d_ptr, dyn_str + dyn_x[i].d_un.d_ptr);
			#endif
			
			lb_hdl[z] = dlopen(dyn_str + dyn_x[i].d_un.d_ptr, RTLD_NOW);
			if(!lb_hdl[z])
				return NULL;
			z++;
		}
	}

	#if LD_DEBUG
		printf("[i] Applying relocations...\n");
	#endif
	int not_supported = 0;
	
	/* apply relocations */
	for(int x = 0 ; x < (rela_dyn_sec->sh_size / sizeof(Elf64_Rela)) ; x++) {	
		// TODO: finsh the actual relocation application
		switch(ELF64_R_TYPE(rela_dyn[x].r_info)) {
			case R_X86_64_NONE:
				break;
			case R_X86_64_64:
				idx_x = ELF64_R_SYM(rela_dyn[x].r_info);
				*((uint64_t *)(lib_addr + rela_dyn[x].r_offset)) = dyn_sym[idx_x].st_value + rela_dyn[x].r_addend;
				break;
			case R_X86_64_PC32:
				not_supported++;
				break;
			case R_X86_64_GOT32:
				not_supported++;
				break;
			case R_X86_64_PLT32:
				not_supported++;
				break;
			case R_X86_64_COPY:
				not_supported++;
				break;
			case R_X86_64_GLOB_DAT:
			case R_X86_64_JUMP_SLOT:
				idx_x = ELF64_R_SYM(rela_dyn[x].r_info);
				*((uint64_t *)(lib_addr + rela_dyn[x].r_offset)) = dyn_sym[idx_x].st_value + rela_dyn[x].r_addend;
				 break;
			case R_X86_64_RELATIVE:
				idx_x = ELF64_R_SYM(rela_dyn[x].r_info);
				*((uint64_t *)(lib_addr + rela_dyn[x].r_offset)) = dyn_sym[idx_x].st_value;
				break;
			case R_X86_64_GOTPCREL:
			case R_X86_64_32:
				idx_x = ELF64_R_SYM(rela_dyn[x].r_info);
				*((uint32_t *)(lib_addr + rela_dyn[x].r_offset)) = dyn_sym[idx_x].st_value + rela_dyn[x].r_addend;
				break;
			case R_X86_64_32S:
				idx_x = ELF64_R_SYM(rela_dyn[x].r_info);
				*((int32_t *)(lib_addr + rela_dyn[x].r_offset)) = dyn_sym[idx_x].st_value + rela_dyn[x].r_addend;
				break;
			case R_X86_64_16:
				idx_x = ELF64_R_SYM(rela_dyn[x].r_info);
				*((uint16_t *)(lib_addr + rela_dyn[x].r_offset)) = dyn_sym[idx_x].st_value + rela_dyn[x].r_addend;
				break;
			case R_X86_64_PC16:
				not_supported++;
				break;
			case R_X86_64_8:
				idx_x = ELF64_R_SYM(rela_dyn[x].r_info);
				*((uint8_t *)(lib_addr + rela_dyn[x].r_offset)) = dyn_sym[idx_x].st_value + rela_dyn[x].r_addend;
				break;
			case R_X86_64_PC8:
			case R_X86_64_DTPMOD64:
			case R_X86_64_DTPOFF64:
			case R_X86_64_TPOFF64:
				/* recommendable to be implemented */
			case R_X86_64_TLSGD:
			case R_X86_64_TLSLD:
			case R_X86_64_DTPOFF32:
			case R_X86_64_GOTTPOFF:
			case R_X86_64_TPOFF32:
				/* recommendable to be implemented */
			case R_X86_64_PC64:
			case R_X86_64_GOTOFF64:
			case R_X86_64_GOTPC32:
			case R_X86_64_GOT64:
			case R_X86_64_GOTPCREL64:
			case R_X86_64_GOTPC64:
			case R_X86_64_GOTPLT64:
			case R_X86_64_PLTOFF64:
			case R_X86_64_SIZE32:
			case R_X86_64_SIZE64:
			case R_X86_64_GOTPC32_TLSDESC:
			case R_X86_64_TLSDESC_CALL:
			case R_X86_64_TLSDESC:
			case R_X86_64_IRELATIVE:
			case R_X86_64_RELATIVE64:
			case R_X86_64_GOTPCRELX:
			case R_X86_64_REX_GOTPCRELX:
			case R_X86_64_NUM:
				not_supported++;
				break;
			default:
				#if LD_DEBUG
					printf("\t[i] Warning: Undefined relocation received: this may be a sign of corruption or parsing bugs\n");
				#endif
				break;

		}
	}
	
	#if LD_DEBUG
		if(not_supported)
			printf("\t[i] %d relocations failed, reason: not supported\n", not_supported);
		printf("[i] Fixing segment memory protections...\n");
	#endif
	
	for(int i = 0 ; i < elf_ehdr->e_phnum ; i++) {

		if(phdr[i].p_type != PT_LOAD)
			continue;

		tmp_ptr = lib_addr + phdr[i].p_vaddr;
		if(tmp_ptr >= lib_addr + tot_mapping_sz)
			return NULL;
		
		mem_prot = phdr[i].p_flags;
		__fp_mprotectx(tmp_ptr, SIZE_ALIGN(phdr[i].p_memsz), mem_prot);
		
	}

	#if LD_DEBUG
		printf("[i] Resolving PLT/GOT references...\n");
	#endif
	
	/* resolve PLT/GOT references */
	for(int i = 0 ; i < (rela_plt_sec->sh_size / sizeof(Elf64_Rela)) ; i++) {
		switch(ELF64_R_TYPE(rela_plt[i].r_info)) {
			case R_X86_64_JUMP_SLOT:
				idx_x = ELF64_R_SYM(rela_plt[i].r_info);
				
				s_name = dyn_str + dyn_sym[idx_x].st_name;

				if(ELF64_ST_TYPE(dyn_sym[idx_x].st_info) == STT_FUNC && dyn_sym[idx_x].st_shndx != SHN_UNDEF) {
					*((unsigned long *)(lib_addr + rela_plt[i].r_offset)) = (uint64_t)(lib_addr + dyn_sym[idx_x].st_value);
				} else {
					for(int p = 0 ; p < needed_n ; p++) {
						if(__xlf_hash(s_name) == 0x211a3b87) /* __gmon_start__ */
							break; 
							
						f_addr = dlsym((void *)lb_hdl[p], s_name);
						#if LD_DEBUG
							printf("\t[i] Resolving %s @ %p\n", s_name, f_addr);
						#endif
						if(f_addr != NULL) {
							*((unsigned long *)(lib_addr + rela_plt[i].r_offset)) = (unsigned long )((unsigned long)f_addr);
							#if LD_DEBUG
								printf("\t[i] Patched %p to %p\n", f_addr, (unsigned long *)(lib_addr + rela_plt[i].r_offset));
							#endif
							break;
						}									
					}
				}
				
				break;
			default:
				break;
		}
	}

	#if LD_DEBUG
		printf("[i] Executing init...\n");
	#endif
		
	for(int j = 0 ; j < dyn_x_num ; j++) {
		if(dyn_x[j].d_tag == DT_INIT_ARRAYSZ) {
			init_array_sz = dyn_x[j].d_un.d_val;
			break;
		}
	}
	
	#if LD_DEBUG
		printf("\t[i] init_array_sz = %ld\n", init_array_sz);
	#endif
	
	if(init_array_sz < sizeof(void *)*2)
		goto END_LOAD; /* there are no constructors */
		
	if(init_array_sz % sizeof(void *) != 0) {
		#if LD_DEBUG
			printf("\t[i] Warning: init_array_sz not QWORD-aligned: this may be a sign of corruption or parsing bugs\n");
		#endif
		goto END_LOAD;
	}
	
	for(int j = 0 ; j < dyn_x_num ; j++) {
		if(dyn_x[j].d_tag == DT_INIT_ARRAY) {
			init_array = (void **)(lib_addr + dyn_x[j].d_un.d_ptr);
			#if LD_DEBUG
				printf("\t[i] DT_INIT_ARRAY offset 0x%lx\n", dyn_x[j].d_un.d_ptr);
				printf("\t[i] DT_INIT_ARRAY vaddr %p\n", init_array);
			#endif
			break;
		}
	}
	
	if(!init_array)
		goto END_LOAD;

	// XXX: first entry in init_array ends with 000, just second is valid?		
	for(int i = 0 ; i < (init_array_sz / sizeof(void *)) ; i++) {
		init_fptr = (lib_addr + (off_t)init_array[i]);
		if(((uint64_t)init_fptr & 0x0000000000000fff) == 0x0000000000000000)
			continue;
		#if LD_DEBUG
			printf("\t[i] init_fptr = %p\n", init_fptr);
		#endif
		if(!init_fptr)
			continue;
		init_fptr();
	}

END_LOAD:

	__elf_defs[def_index].in_use = 1;
	__elf_defs[def_index].orig_elf_file = memdup(addr, size);
	__elf_defs[def_index].orig_elf_file_sz = size;
	__elf_defs[def_index].mapped_elf = lib_addr;
	__elf_defs[def_index].name = strdup(lb_name);
	
	if(out_sz)
		*out_sz = out_size;

	return lib_addr;
}

#endif

#if ENABLE_API_INMEM_LOAD

/*
  Backward compatibility for those libc version that did not support memfd_create
   as a wrapper
*/
static inline int x_memfd_create(const char *name, unsigned int flags) {
	return syscall(__NR_memfd_create, name, flags);
}

void *__memfd_inmem_api_load(char *lb_name, void *addr, size_t size, size_t *out_sz) {
	int def_index = -1;
	size_t out_size = 0;
	int e_fd = 0;
	int ret = 0;
	void *lib_addr = NULL;
	char memfd_path[MAX_MEMFD_PATH + 1] = { 0 };
	
	if(!out_sz)
		return NULL;
		
	__s_lock(&e_def_lock);
	
	if(!__elf_defs)
		__elf_defs = (elf_mod_def *)calloc(MAX_CONCURRENT_ELF_MODULES, sizeof(elf_mod_def));
		
	for(int i = 0 ; i < MAX_CONCURRENT_ELF_MODULES ; i++) {
		if(__elf_defs[i].in_use == 1)
			continue;
		def_index = i;
	}
	
	if(def_index == -1) {
		__s_unlock(&e_def_lock);
		return NULL;
	}
	
	__elf_defs[def_index].in_use = 1;
	
	__s_unlock(&e_def_lock);
	
	/*
	  1.- memfd_create() a new file descriptor with path
	  2.- mmap() file descriptor with RW permissions
	  3.- use dlopen() to load the library using the path
	*/
	
	e_fd = x_memfd_create(__edeobf_str(MEMFD_NAME), 1);
	if(e_fd < 0) {
		__elf_defs[def_index].in_use = 0;
		return NULL;
	}
	
	#if LD_DEBUG
		printf("[i] ELF size: %ld\n", size);
		printf("[i] memfd fd: %d\n", e_fd);
	#endif
	
	if(ftruncate(e_fd, size) == -1)
		return NULL;
	
	#if LD_DEBUG
		printf("[i] Writing %ld bytes of ELF object to memfd mapping...\n", size);
	#endif
	
	ret = write(e_fd, addr, size);
	if(ret < 0)
		return NULL;
		
	snprintf(memfd_path, MAX_MEMFD_PATH, __edeobf_str("\x2c\x73\x71\x6c\x60\x2c\x26\x67\x2c\x65\x67\x2c\x26\x67"), getpid(), e_fd); /* "" */
	
	#if LD_DEBUG
		printf("[i] memfd fs path: %s\n", memfd_path);
		printf("[i] Attempting to dlopen() in-memory ELF object...\n");
	#endif
	
	lib_addr = dlopen(memfd_path, RTLD_NOW);
	if(!lib_addr) {
		__elf_defs[def_index].in_use = 0;
		#if LD_DEBUG
			printf("[-] Loading failed. Reason: %s\n", dlerror());
		#endif
		return NULL;
	}
		
	__elf_defs[def_index].in_use = 1;
	__elf_defs[def_index].orig_elf_file = memdup(addr, size);
	__elf_defs[def_index].orig_elf_file_sz = size;
	__elf_defs[def_index].mapped_elf = lib_addr;
	__elf_defs[def_index].name = strdup(lb_name);
	
	if(out_sz)
		*out_sz = out_size;

	return lib_addr;
}

#endif

#if ENABLE_HOOK_INJ_LOAD

int     __cb_open(const char *pathname, int flags); 
off_t   __cb_lseek64(int fd, off_t offset, int whence);
ssize_t __cb_read(int fd, void *buf, size_t count);
void * __cb_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     __cb_fstat(int fd, struct stat *buf);
int     __cb_close(int fd);

#define HOOKED_FUNC_N 6

typedef struct _uhook_restore {
	size_t stub_sz;
	void *unhooked_bak;
	void *symbol_addr;
	char *symbol;
} uhook_restore;

uhook_restore hook_bak[HOOKED_FUNC_N];

int __cb_open(const char *pathname, int flags) {
	void *hdlptr = NULL;
	int (*__fp_openx)(const char *pathname, int flags) = NULL;
	
	#if LD_DEBUG
		printf("[i] __cb_open(): callback called! (pathname = '%s')\n", pathname ? pathname : "(nil)");
	#endif
	
	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return -1;
	
	__fp_openx = dlsym(hdlptr, __edeobf_str("\x6c\x73\x66\x6d")); /* "open" */
	if(!__fp_openx)
		return -1;
		
	if(strstr(pathname, __edeobf_str(MAGIC_PATHNAME))) {
		#if LD_DEBUG
			printf("\t[i] __cb_open(): received magic pathname\n");
			printf("\t[i] Returning MAGIC_FD_COOKIE...\n");
		#endif
		
		return MAGIC_FD_COOKIE;
	}

	return __fp_openx(pathname, flags);
}

// XXX: unused in modern libc versions
off_t __cb_lseek64(int fd, off_t offset, int whence) {
	void *hdlptr = NULL;
	off_t (*__fp_lseek64)(int fd, off_t offset, int whence) = NULL;
	
	#if LD_DEBUG
		printf("[i] __cb_lseek64(): callback called! (fd = %d)\n", fd);
	#endif
	
	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return -1;
	
	__fp_lseek64 = dlsym(hdlptr, __edeobf_str("\x6f\x70\x66\x66\x68")); /* "lseek" */
	if(!__fp_lseek64)
		return -1;
		
	if(fd == MAGIC_FD_COOKIE) {
		#if LD_DEBUG
			printf("[i] __cb_lseek64(): received MAGIC_FD_COOKIE\n");
		#endif

		if(whence == SEEK_SET)
			__x_lib_def.current = offset;
		
		if(whence == SEEK_CUR)
			__x_lib_def.current += offset;
		
		if(whence == SEEK_END)
			__x_lib_def.current = __x_lib_def.size + offset;
			
		return __x_lib_def.current;
	}

	return __fp_lseek64(fd, offset, whence);
}

ssize_t __cb_read(int fd, void *buf, size_t count) {
	size_t sz = 0;
	void *hdlptr = NULL;
	ssize_t (*__fp_readx)(int fd, void *buf, size_t count) = NULL;
	
	#if LD_DEBUG
		printf("[i] __cb_read(): callback called! (fd = %d)\n", fd);
	#endif
	
	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return -1;
	
	__fp_readx = dlsym(hdlptr, __edeobf_str("\x71\x66\x62\x67")); /* "read" */
	if(!__fp_readx)
		return -1;
		
	if(fd == MAGIC_FD_COOKIE) {
		#if LD_DEBUG
			printf("\t[i] __cb_read(): received MAGIC_FD_COOKIE\n");
		#endif
		
		sz = ((__x_lib_def.size - __x_lib_def.current) >= count) ? count : (__x_lib_def.size - __x_lib_def.current);

		memcpy(buf, __x_lib_def.data + __x_lib_def.current, sz);
		__x_lib_def.current += sz;
		
		#if LD_DEBUG
			printf("\t[i] len = %ld ; __x_lib_def.size = %d\n", count, __x_lib_def.size);
		#endif
		
		return sz;
	}

	return __fp_readx(fd, buf, count);
}

ssize_t __cb_pread64(int fd, void *buf, size_t count, off_t offset) {
	size_t sz = 0;
	void *hdlptr = NULL;
	ssize_t (*__fp_pread64x)(int fd, void *buf, size_t count) = NULL;
	
	#if LD_DEBUG
		printf("[i] __cb_pread64(): callback called! (fd = %d)\n", fd);
	#endif
	
	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return -1;
	
	__fp_pread64x = dlsym(hdlptr, __edeobf_str("\x73\x71\x66\x62\x67")); /* "pread" */
	if(!__fp_pread64x)
		return -1;
		
	if(fd == MAGIC_FD_COOKIE) {
		#if LD_DEBUG
			printf("\t[i] __cb_pread64(): received MAGIC_FD_COOKIE\n");
		#endif
		
		//sz = ((__x_lib_def.size - __x_lib_def.current) >= count) ? count : (__x_lib_def.size - __x_lib_def.current);
		sz = ((__x_lib_def.size - offset) >= count) ? count : (__x_lib_def.size - offset);
		//memcpy(buf, __x_lib_def.data + __x_lib_def.current + offset, sz);
		memcpy(buf, __x_lib_def.data + offset, sz);
		//__x_lib_def.current += sz;
		
		#if LD_DEBUG
			printf("\r[i] offset = %ld\n", offset);
		#endif
		
		return sz;
	}

	return __fp_pread64x(fd, buf, count);
}

void *__cb_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	int flg = 0;
	uint64_t m = 0;
	size_t sz = 0;
	void *ret = NULL;
	void *hdlptr = NULL;
	uint64_t start = 0;
	void *(*__fp_mmapx)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
	int (*__fp_mprotectx)(void *addr, size_t len, int prot) = NULL;

	#if LD_DEBUG
		printf("[i] __cb_mmap(): callback called! (fd = %d)\n", fd);
	#endif
	
	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return NULL;
	
	__fp_mmapx = dlsym(hdlptr, __edeobf_str("\x6e\x6e\x62\x73")); /* "mmap" */
	if(!__fp_mmapx)
		return NULL;
		
	__fp_mprotectx = dlsym(hdlptr, __edeobf_str("\x6e\x73\x71\x6c\x77\x66\x60\x77")); /* "mprotect" */
	if(!__fp_mprotectx)
		return NULL;
		
	if(fd == MAGIC_FD_COOKIE) {
		#if LD_DEBUG
			printf("\t[i] __cb_mmap(): received MAGIC_FD_COOKIE\n");
		#endif
		
		flg = MAP_PRIVATE | MAP_ANON;
		if(flags & MAP_FIXED)
			flg |= MAP_FIXED;
		
		ret = __fp_mmapx(addr, length, PROT_READ | PROT_WRITE | PROT_EXEC, flg, -1, 0);
		if(ret == MAP_FAILED)
			return NULL;
		
		if(offset >= __x_lib_def.size)
			return NULL;
			
		sz = length > __x_lib_def.size - offset  ? __x_lib_def.size - offset : length;
			
		memcpy(ret, __x_lib_def.data + offset, sz);
		
		start = (uint64_t)ret & (((size_t)-1) ^ (PAGE_SIZE - 1));
		while(start < (uint64_t)ret) {
			__fp_mprotectx((void *)start, PAGE_SIZE, prot); 
			start += PAGE_SIZE;
		}
		
		#if LD_DEBUG
			printf("\t[i] len = %ld, offset = %ld\n", length, offset);
		#endif
		
		return ret;
	}
	
	return __fp_mmapx(addr, length, prot, flags, fd, offset);
}

int __cb_fstat(int fd, struct stat *buf) {
	void *hdlptr = NULL;
	int (*__fp_fstatx)(int fd, struct stat *buf) = NULL;
	
	#if LD_DEBUG
		printf("[i] __cb_fstat(): callback called! (fd = %d)\n", fd);
	#endif
	
	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return -1;
		
	__fp_fstatx = dlsym(hdlptr, __edeobf_str("\x5c\x5c\x65\x7b\x70\x77\x62\x77\x35\x37")); /* "__fxstat64" */
	if(!__fp_fstatx)
		return -1;
	
	if(fd == MAGIC_FD_COOKIE) {
		#if LD_DEBUG
			printf("\t[i] __cb_fstat(): received MAGIC_FD_COOKIE\n");
		#endif
		
		memset(buf, 0, sizeof(struct stat));
		buf->st_size = __x_lib_def.size;
		buf->st_ino = 0x654;
		
		#if LD_DEBUG
			printf("\t[i] Passing stat: buf->st_size = %ld ; buf->st_ino = %ld\n", buf->st_size, buf->st_ino);
		#endif
		
		return 0;
	}
	
	return __fp_fstatx(fd, buf);
}

uint64_t __rsp = 0;

/*
 __backward_stub:
 	leave
 	ret
*/
const char backward_stub[] = {0xc9, 0xc3};
size_t backward_stub_size = 2;
		
#define STUB_OFFSET_RET_ADDR 0x10

int __cb_close(int fd) {
	int i = 0;
	void *hdlptr = NULL;
	int (*__fp_closex)(int fd) = NULL;
	void *(*__fp_mmapx)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
	int (*__fp_mprotectx)(void *addr, size_t len, int prot) = NULL;
	void *page_addr = NULL;
	void *symbol_addr = NULL;
	int x = 0;
	uint64_t *__stack_iter = NULL;
	uint64_t close_sym = 0;
	int found = 0;
	void *tmp_backward_stub = NULL;
	
	#if LD_DEBUG
		printf("[i] __cb_close(): callback called! (fd = %d)\n", fd);
	#endif
	
	hdlptr = dlopen(__edeobf_str(LIBC_DL_NAME), RTLD_NOW);
	if(!hdlptr)
		return -1;
	
	__fp_closex = dlsym(hdlptr, __edeobf_str("\x60\x6f\x6c\x70\x66")); /* "close" */
	if(!__fp_closex)
		return -1;
		
	__fp_mmapx = dlsym(hdlptr, __edeobf_str("\x6e\x6e\x62\x73")); /* "mmap" */
	if(!__fp_mmapx)
		return -1;
		
	__fp_mprotectx = dlsym(hdlptr, __edeobf_str("\x6e\x73\x71\x6c\x77\x66\x60\x77")); /* "mprotect" */
	if(!__fp_mprotectx)
		return -1;
	
	if(fd == MAGIC_FD_COOKIE) {
		#if LD_DEBUG
			printf("\t[i] __cb_close(): received MAGIC_FD_COOKIE\n");
			printf("\t[i] Performing unhooking...\n");
		#endif
		
		i = 0;
		while(i < HOOKED_FUNC_N) {
			
			if(!hook_bak[i].symbol_addr || !hook_bak[i].unhooked_bak || !hook_bak[i].stub_sz || !hook_bak[i].symbol) {
				i++;
				continue;
			}
			
			if(strcmp(hook_bak[i].symbol, __edeobf_str("\x60\x6f\x6c\x70\x66")) == 0) /* "close" */
				close_sym = (uint64_t)hook_bak[i].symbol_addr;

			symbol_addr = hook_bak[i].symbol_addr;
			
			#if LD_DEBUG
				printf("\t\t[i] Unhooking: %p\n", (void *)symbol_addr);
			#endif
			
			page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (PAGE_SIZE - 1)));
			mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_WRITE); 
			
			memcpy((void*)symbol_addr, hook_bak[i].unhooked_bak, hook_bak[i].stub_sz);
			
			mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_EXEC);
	
			i++;
		}
		
		if(!close_sym)
			return 0; /* We failed, let's just crash :-( */

		__asm__(
			".intel_syntax noprefix;"
			"mov __rsp, rsp;"
			".att_syntax;"
		);
		
		#if LD_DEBUG
			printf("\t\t[i] rsp = %p\n", (void *)__rsp);
		#endif
		
		found = 0;
		x = 40;
		__stack_iter = (uint64_t *)__rsp;
		
		while(x < 60) {
			if(__stack_iter[x] == close_sym + STUB_OFFSET_RET_ADDR) {
				x--;
				found = 1;
				break;
			}
			x--;
		}
		
		#if LD_DEBUG
			printf("\t\t[i] Ended up with x = %d\n", x);
		#endif
		
		if(!found) {
			#if LD_DEBUG
				printf("\t\t[-] Failed looking up for target function...\n");
			#endif
			return 0; /* We failed, we'll probably crash */
		}
		
		#if LD_DEBUG
			printf("\t\t[i] ret addr @ %p (%p)\n", &__stack_iter[x+1], (void *)(close_sym + STUB_OFFSET_RET_ADDR));
		#endif
		
		tmp_backward_stub = __fp_mmapx(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if(tmp_backward_stub == MAP_FAILED)
			return -1;
		
		memset(tmp_backward_stub, 0x90, PAGE_SIZE);
		memcpy(tmp_backward_stub, backward_stub, backward_stub_size);
		
		__fp_mprotectx(tmp_backward_stub, PAGE_SIZE, PROT_READ | PROT_EXEC); 
		
		#if LD_DEBUG
			printf("\t\t[i] Setting ret addr to backward stub to: %p \n", tmp_backward_stub);
		#endif
		
		__stack_iter[x+1] = (uint64_t)tmp_backward_stub;
		
		#if LD_DEBUG
			printf("\t\t[i] New ret addr at %p: %p \n", &__stack_iter[x+1], (void *)__stack_iter[x]);
		#endif
		
		return 0;
	}
	return __fp_closex(fd);
}

int locate_ld_lib(void **start, void **end) {
	void *_start = NULL;
	void *_end = NULL;
	FILE *fp = NULL;
	int found = 0;
	char *tmp = NULL;
	char mpbuf[MAX_MAPS_SIZE + 1] = { 0 };
	
	if(!start || !end)
		return 0;
		
	#if LD_DEBUG
		printf("[i] Locating ld.so in memory...\n");
	#endif
		
	fp = fopen(__edeobf_str(MAPS_FILE), "r");
	if(!fp)
		return 0;

	found = 0;
	while(fgets(mpbuf, sizeof(mpbuf), fp)) {
		if(!strstr(mpbuf, __edeobf_str("\x71\x2e\x7b\x73"))) /* "r-xp" */
			continue;
		
		if(!strstr(mpbuf, __edeobf_str(LD_NAME)))
			continue;

		mpbuf[strlen(mpbuf) - 1] = '\0';
		
		tmp = strrchr(mpbuf, ' ');
		if(tmp == NULL || tmp[0] != ' ')
			continue;
		tmp++;

		_start = strtok(mpbuf, "-");
		_end = strtok(NULL, " ");

		found = 1;
		break;
	}

	if(fp) {
		fclose(fp);
		fp = NULL;
	}
	
	if(!found)
		return 0;
	
	if(start && end) {
		*start = (void *)strtoul(_start, NULL, 16);
		*end = (void *)strtoul(_end, NULL, 16);;
	}
	
	return 1;
}

/*
__hook_stub:
	push   rbp
	mov    rbp,rsp
	movabs rax, 0x0000000000000000
	call   rax
	leave  
	ret
*/
char stub[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd0, 0xc9, 0xc3};
size_t stub_length = 18;

// 0x7ffff7fc99ad <open_verify+109>:	sub    rdx,rax
// 0x7ffff7fc99b0 <open_verify+112>:	lea    rsi,[rdi+rax*1]
// 0x7ffff7fc99b4 <open_verify+116>:	mov    edi,r15d
// 0x7ffff7fc99b7 <open_verify+119>:	call   0x7ffff7fe9b80 <__GI___read_nocancel>

// 0x7ffff7fc99ad <open_verify+109>:	0x48	0x29	0xc2
// 0x7ffff7fc99b0 <open_verify+112>:	0x48	0x8d	0x34	0x07
// 0x7ffff7fc99b4 <open_verify+116>:	0x44	0x89	0xff
// 0x7ffff7fc99b7 <open_verify+119>:	0xe8	0xc4	0x01	0x02	0x00

const char read_func_pattern[] = {0x48, 0x29, 0xc2, 0x48, 0x8d, 0x34, 0x07, 0x44, 0x89, 0xff, 0xe8};
#define READ_FUNC_PATTERN_LEN 11

// 0x7ffff7fcc088 <_dl_map_object_from_fd+1208>:	mov    ecx,0x812
// 0x7ffff7fcc08d <_dl_map_object_from_fd+1213>:	mov    DWORD PTR [rbp-0xe0],r11d
// 0x7ffff7fcc094 <_dl_map_object_from_fd+1220>:	call   0x7ffff7fe9cc0 <__mmap64>

// 0x7ffff7fcc088 <_dl_map_object_from_fd+1208>:	0xb9	0x12	0x08	0x00	0x00
// 0x7ffff7fcc08d <_dl_map_object_from_fd+1213>:	0x44	0x89	0x9d	0x20	0xff	0xff	0xff
// 0x7ffff7fcc094 <_dl_map_object_from_fd+1220>:	0xe8	0x27	0xdc	0x01	0x00

const char mmap_func_pattern[] = {0xb9, 0x12, 0x08, 0x00, 0x00, 0x44, 0x89, 0x9d, 0x20, 0xff, 0xff, 0xff, 0xe8};
#define MMAP_FUNC_PATTERN_LEN 13


// XXX: lseek64 seems to be unused now. It has been replaced by pread64

// 0x00007ffff7de26c2 <+2466>: sub    rsp,rax
// 0x00007ffff7de26c5 <+2469>: mov    edi,r15d
// 0x00007ffff7de26c8 <+2472>: lea    r12,[rsp+0x4c7]
// 0x00007ffff7de26cd <+2477>: call   0x7ffff7df3380 <lseek64>
              
// 0x7ffff7de26c2 <_dl_map_object_from_fd+2466>: 0x48 0x29 0xc4 0x44 0x89 0xff 0x4c 0x8d
// 0x7ffff7de26ca <_dl_map_object_from_fd+2474>: 0x64 0x24 0x47 0xe8 0xae 0x0c 0x01 0x00

const char lseek_func_pattern[] = {0x48, 0x29, 0xc4, 0x44, 0x89, 0xff, 0x4c, 0x8d, 0x64, 0x24, 0x47, 0xe8};
#define LSEEK_FUNC_PATTERN_LEN 12

// 0x7ffff7fcc0c8 <_dl_map_object_from_fd+1272>:	mov    edi,DWORD PTR [rbp-0xd4]
// 0x7ffff7fcc0ce <_dl_map_object_from_fd+1278>:	lea    rsi,[rbp-0xc0]
// 0x7ffff7fcc0d5 <_dl_map_object_from_fd+1285>:	call   0x7ffff7fe98a0 <__GI___fstat64>

// 0x7ffff7fcc0c8 <_dl_map_object_from_fd+1272>:	0x8b	0xbd	0x2c	0xff	0xff	0xff
// 0x7ffff7fcc0ce <_dl_map_object_from_fd+1278>:	0x48	0x8d	0xb5	0x40	0xff	0xff	0xff
// 0x7ffff7fcc0d5 <_dl_map_object_from_fd+1285>:	0xe8	0xc6	0xd7	0x01	0x00

const char fxstat_func_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xb5, 0x40, 0xff, 0xff, 0xff, 0xe8};
#define FXSTAT_FUNC_PATTERN_LEN 14

// 0x00007ffff7fcc145 <_dl_map_object_from_fd+1397>:	mov    edi,DWORD PTR [rbp-0xd4]
// 0x00007ffff7fcc14b <_dl_map_object_from_fd+1403>:	call   0x7ffff7fe99f0 <__GI___close_nocancel>

// 0x7ffff7fcc145 <_dl_map_object_from_fd+1397>:	0x8b	0xbd	0x2c	0xff	0xff	0xff
// 0x7ffff7fcc14b <_dl_map_object_from_fd+1403>:	0xe8	0xa0	0xd8	0x01	0x00

const char close_func_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0xe8};
#define CLOSE_FUNC_PATTERN_LEN 7

// 0x7ffff7fc996a <open_verify+42>:	mov    esi,0x80000
// 0x7ffff7fc996f <open_verify+47>:	mov    rdi,r14
// 0x7ffff7fc9972 <open_verify+50>:	xor    eax,eax
// 0x7ffff7fc9974 <open_verify+52>:	call   0x7ffff7fe9b00 <__GI___open64_nocancel>

// 0x7ffff7fc996a <open_verify+42>:	0xbe	0x00	0x00	0x08	0x00
// 0x7ffff7fc996f <open_verify+47>:	0x4c	0x89	0xf7
// 0x7ffff7fc9972 <open_verify+50>:	0x31	0xc0
// 0x7ffff7fc9974 <open_verify+52>:	0xe8	0x87	0x01	0x02	0x00

const char open_func_pattern[] = {0xbe, 0x00, 0x00, 0x08, 0x00, 0x4c, 0x89, 0xf7, 0x31, 0xc0, 0xe8};
#define OPEN_FUNC_PATTERN_LEN 11

// 0x00007ffff7fcc275 <+1701>:	mov    rsi,rax
// 0x00007ffff7fcc278 <+1704>:	mov    QWORD PTR [rbp-0x158],rax
// 0x00007ffff7fcc27f <+1711>:	call   0x7ffff7fe9bb0 <__GI___pread64_nocancel>

// 0x7ffff7fcc275 <_dl_map_object_from_fd+1701>:	0x48	0x89	0xc6
// 0x7ffff7fcc278 <_dl_map_object_from_fd+1704>:	0x48	0x89	0x85	0xa8	0xfe	0xff	0xff
// 0x7ffff7fcc27f <_dl_map_object_from_fd+1711>:	0xe8	0x2c	0xd9	0x01	0x00

const char pread64_func_pattern[] = {0x48, 0x89, 0xc6, 0x48, 0x89, 0x85, 0xa8, 0xfe, 0xff, 0xff, 0xe8};
#define PREAD64_FUNC_PATTERN_LEN 11

const char *patterns[] = {read_func_pattern, mmap_func_pattern, fxstat_func_pattern, close_func_pattern,
                          open_func_pattern, pread64_func_pattern, NULL};

const size_t pattern_lens[] = {READ_FUNC_PATTERN_LEN, MMAP_FUNC_PATTERN_LEN, 
                                  FXSTAT_FUNC_PATTERN_LEN, CLOSE_FUNC_PATTERN_LEN, OPEN_FUNC_PATTERN_LEN, PREAD64_FUNC_PATTERN_LEN, 0};

const char *symbols[] = {
			"\x71\x66\x62\x67",		/* "read" */
			"\x6e\x6e\x62\x73",		/* "mmap" */
			"\x65\x7b\x70\x77\x62\x77",	/* "fxstat" */
			"\x60\x6f\x6c\x70\x66",		/* "close" */
			"\x6c\x73\x66\x6d",		/* "open" */
			"\x73\x71\x66\x62\x67",		/* "pread" */
			 NULL
			};

uint64_t functions[] = {(uint64_t)&__cb_read, (uint64_t)&__cb_mmap, (uint64_t)&__cb_fstat, 
                        (uint64_t)&__cb_close, (uint64_t)&__cb_open, (uint64_t)&__cb_pread64, 0};

int apply_patch_hook_inject(void *ld_start, void *ld_end, const char *pattern, size_t pattern_len, const char *symbol, uint64_t rep_addr, uhook_restore *__h_bak) {
	uint64_t tmp_ptr = 0;
	int found = 0;
	int32_t offset = 0;
	uint64_t symbol_addr = 0;
	char *code = NULL;
	void *page_addr = NULL;

	if(!ld_start || !ld_end || !pattern || !pattern_len || !symbol || !rep_addr || !__h_bak)
		return 0;
	
	#if LD_DEBUG
		printf("[i] Searching offset for %s\n", symbol);
	#endif
	
	tmp_ptr = (uint64_t)ld_start;
	while(((tmp_ptr + pattern_len) < (uint64_t)ld_end)) {
		if(!memcmp((void*)tmp_ptr, (void*)pattern, pattern_len)) {
			found = 1;
			break;
		}
		tmp_ptr++;
	}

	if(!found)
		return 0;

	offset = *((uint64_t*)(tmp_ptr + pattern_len));
	symbol_addr = tmp_ptr + pattern_len + 4 + offset;
	
	__h_bak->stub_sz = stub_length;
	__h_bak->unhooked_bak = memdup((void *)symbol_addr, stub_length);
	__h_bak->symbol_addr = (void *)symbol_addr;
	__h_bak->symbol = strdup(symbol);

	#if LD_DEBUG
		printf("\t[+] Offset found: 0x%x\n", offset);
		printf("\t[+] Symbol address: %p\n", (void *)symbol_addr);
	#endif

	code = calloc(stub_length, sizeof(char));
	if(!code)
		return 0;
	
	memcpy(code, stub, stub_length);
	memcpy(code + 6, &rep_addr, sizeof(uint64_t));

	#if LD_DEBUG
		printf("\t[i] Patching %s...\n", symbol);
	#endif

	page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (PAGE_SIZE - 1)));
	mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_WRITE); 
	
	memcpy((void*)symbol_addr, code, stub_length);
	
	mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_EXEC); 

	#if LD_DEBUG
		printf("\t[i] Stub injected in %s @ %p\n", symbol, (void *)symbol_addr);
	#endif
	
	return 1;
}

/*
   Ref: https://github.com/m1m1x/memdlopen
   Ref: http://web.archive.org/web/20160803183622/http://http://www.nologin.org/Downloads/Papers/remote-library-injection.pdf
*/
void *__hook_inj_elf_dl_load(char *lb_name, void *addr, size_t size, size_t *out_sz) {
	void *lib_addr = NULL;
	void *__dat_cpy = NULL;
	void *start = NULL;
	void *end = NULL;
	int def_index = -1;
	int i = 0;
	
	__s_lock(&e_def_lock);

	if(!__elf_defs)
		__elf_defs = (elf_mod_def *)calloc(MAX_CONCURRENT_ELF_MODULES, sizeof(elf_mod_def));
		
	for(int i = 0 ; i < MAX_CONCURRENT_ELF_MODULES ; i++) {
		if(__elf_defs[i].in_use == 1)
			continue;
		def_index = i;
	}
	
	if(def_index == -1) {
		__s_unlock(&e_def_lock);
		return NULL;
	}
	
	__elf_defs[def_index].in_use = 1;
	
	__dat_cpy = memdup(addr, size);
	if(!__dat_cpy) {
		__elf_defs[def_index].in_use = 0;
		__s_unlock(&e_def_lock);
		return NULL;
	}
	
	__s_unlock(&e_def_lock);
		
	__x_lib_def.data = __dat_cpy;
	__x_lib_def.size = size;
	__x_lib_def.current = 0;
	
	if(!locate_ld_lib(&start, &end)) {
		__elf_defs[def_index].in_use = 0;
		return NULL;
	}
	
	#if LD_DEBUG
		printf("\t[+] ld.so found: %p - %p\n", start, end);
	#endif
	
	i = 0;
	while(patterns[i] != NULL) {
		if(!apply_patch_hook_inject(start, end, patterns[i], pattern_lens[i], __edeobf_str(symbols[i]), functions[i], &hook_bak[i])) {
			__elf_defs[def_index].in_use = 0;
			return NULL;
		}
		i++;
	}
	
	#if LD_DEBUG
		printf("[i] Calling dlopen() API...\n");
	#endif
	
	lib_addr = dlopen(__edeobf_str(MAGIC_PATHNAME), RTLD_NOW);
	if(!lib_addr) {
		__elf_defs[def_index].in_use = 0;
		return NULL;
	}
	
	__elf_defs[def_index].in_use = 1;
	__elf_defs[def_index].orig_elf_file = __dat_cpy;
	__elf_defs[def_index].orig_elf_file_sz = size;
	__elf_defs[def_index].mapped_elf = lib_addr;
	__elf_defs[def_index].name = strdup(lb_name);
	
	return lib_addr;
}

#endif

int load_lib(char *name, void *addr, size_t size, void **out_addr, size_t *out_sz, int mode) {
	void *ret = NULL;
	size_t out_sz_x = 0;
	
	if(!out_addr || !out_sz)
		return 0;
	
	*out_addr = NULL;
	*out_sz = 0;
	
	__s_lock(&gen_load_lock);
	
	if(mode == MODE_REFLECTIVE_ELF_LOADER) {
		#if ENABLE_ELF_LOADER_LOAD
		ret = __reflective_elf_sl_load(name, addr, size, &out_sz_x);
		#else
		ret = NULL; /* currently unsupported mode */
		#endif
	} else if(mode == MODE_HOOK_INJ) {
		#if ENABLE_HOOK_INJ_LOAD
		ret = __hook_inj_elf_dl_load(name, addr, size, &out_sz_x);
		#else
		ret = NULL; /* currently unsupported mode */
		#endif
	} else if(mode == MODE_INMEM_API_LOAD) {
		#if ENABLE_API_INMEM_LOAD
		ret =  __memfd_inmem_api_load(name, addr, size, &out_sz_x);
		#else
		ret = NULL; /* currently unsupported mode */
		#endif
	}
		
	__s_unlock(&gen_load_lock);
	
	if(ret == NULL)
		return 0;
	
	if(out_addr && out_sz) {
		*out_addr = ret;
		*out_sz = out_sz_x;
	}
	
	return 1;
}

void *resolve_func(void *lib, const char *func_str, int mode) {
	void *ret = NULL;
	
	__s_lock(&gen_load_lock);
	
	if(mode == MODE_REFLECTIVE_ELF_LOADER) {
		#if ENABLE_ELF_LOADER_LOAD
		ret = __custom_func_resolve(lib, func_str);
		#else
		ret = NULL; /* currently unsupported mode */
		#endif
	} else if(mode == MODE_HOOK_INJ || mode == MODE_INMEM_API_LOAD)
		ret = __dlsym_func_resolve(lib, func_str);
	
	__s_unlock(&gen_load_lock);
	
	return ret;
}

void unload_lib(void *addr, size_t size) {
	// TODO: finish unload implementation
	return;
}



