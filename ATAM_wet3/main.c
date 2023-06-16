#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define GLOBAL 1
#define SYMTAB 2
#define STRTAB 3
#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	*error_val = 0;
    FILE* file = fopen(exe_file_name, "r");

    if(file == NULL)
        return -11;
    Elf64_Ehdr* r_info = (Elf64_Ehdr*)file;
    if (r_info->e_type != ET_EXEC){
        return -3;
    }
    Elf64_Shdr* section_header_adrs = (Elf64_Shdr*)((char*)file + r_info->e_shoff);
    Elf64_Shdr section_str = section_header_adrs[r_info->e_shstrndx];

    char* string_table = (char*)file + section_str.sh_offset;
    Elf64_Half sections_count = r_info->e_shnum;

    Elf64_Sym* r_symb;
    char *strtab;
    int symbols_count = 0;
    for (int i = 0; i < sections_count; ++i) {
        char* section_name = string_table + section_header_adrs[i].sh_name;
        if(!strcmp(".symtab", section_name) || section_header_adrs[i].sh_type == SYMTAB){
            r_symb = (Elf64_Sym*)((char*)file + section_header_adrs[i].sh_offset);
            symbols_count = section_header_adrs[i].sh_size / section_header_adrs[i].sh_entsize;
        }
        else if(!strcmp(".strtab", section_name) || section_header_adrs[i].sh_type == STRTAB) {
            if ((char *) file + section_header_adrs[i].sh_offset != string_table) {
                strtab = ((char *) file + section_header_adrs[i].sh_offset);
            }
        }
    }
    for(int i = 0; i < symbols_count; i++){
        char* curr_symbol_name = strtab + r_symb[i].st_name;
        if(!strcmp(symbol_name, curr_symbol_name)) {
            if(ELF64_ST_BIND(r_symb[i].st_info) == GLOBAL) {
                Elf64_Addr value = r_symb[i].st_value;

            }
            else {
                *local_count += 1;
            }
        }
    }
	return 0;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}