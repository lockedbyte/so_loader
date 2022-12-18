CC = gcc

all:
	${CC} elf_x86_64_ldr.c -c -o elf_x86_64_ldr.o
	${CC} elf_x86_ldr.c -m32 -c -o elf_x86_ldr.o
	${CC} test.c -m32 -no-pie elf_x86_ldr.o -o test32
	${CC} test.c -no-pie elf_x86_64_ldr.o -o test64
	${CC} lib_sample.c -m32 -shared -o lib_sample32.so
	${CC} lib_sample.c -shared -o lib_sample64.so
	${CC} test_hash.c -o test_hash
	rm *.o
	chmod +x ./test32
	chmod +x ./test64

clean:
	rm test32
	rm test64
	rm lib_sample32.so
	rm lib_sample64.so
	rm test_hash
