#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
/*
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
 */
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define ERRORNOTGLOBAL -4
#define ERRORNOTEXEC -3
#define ERRORLOCAL -2
#define NOTFOUND -1
#define FAILED -1
#define FOUND 1
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
    //Open the file
    *error_val = 0;
    FILE* file = fopen(exe_file_name, "rb");
    if(file == NULL) {
        return FAILED;
    }

    //Finding the header
    Elf64_Ehdr header;
    fread(&header, sizeof (Elf64_Ehdr), 1, file);
    if (header.e_type != ET_EXEC){
        *error_val = ERRORNOTEXEC;
        fclose(file);
        return FAILED;
    }

    //Finding section header
    fseek(file, header.e_shoff, SEEK_SET);
    Elf64_Shdr* header_table = malloc(header.e_shoff * sizeof(Elf64_Shdr));
    if(!header_table){
        fclose(file);
        return FAILED;
    }
    fread(header_table, sizeof(Elf64_Shdr), header.e_shnum, file);

    //find the symbol section
    Elf64_Half sections_count = header.e_shnum;
    int symbols_count = 0, sym = NOTFOUND, str = NOTFOUND;
    for (int i = 0; i < sections_count; ++i) {
        if(header_table[i].sh_type == SYMTAB){
            sym = i;
        }
    }
    if (sym == NOTFOUND){
	free(header_table);
        fclose(file);
        *error_val = NOTFOUND;
        return FAILED;
    }
    Elf64_Shdr symtab_head = header_table[sym];
    symbols_count = symtab_head.sh_size / symtab_head.sh_entsize;
    str = symtab_head.sh_link;
    Elf64_Shdr strtab_head = header_table[str];


    //Holding the symtab
    fseek(file, symtab_head.sh_offset, SEEK_SET);
    Elf64_Sym* sym_table = malloc(symtab_head.sh_size);
    if(!sym_table){
        free(header_table);
        fclose(file);
        return FAILED;
    }
    fread(sym_table, symtab_head.sh_size, 1, file);

    //Holding the strtab
    fseek(file, strtab_head.sh_offset, SEEK_SET);
    char * strtab = malloc(strtab_head.sh_size);
    if(!strtab){
        fclose(file);
        free(header_table);
        free(sym_table);
        return FAILED;
    }
    fread(strtab, strtab_head.sh_size, 1, file);

    //Cheking the symbols
    int local_count = 0;
    for(int i = 0; i < symbols_count; i++){
        char* curr_symbol_name = sym_table[i].st_name + strtab;
        if(!strcmp(symbol_name, curr_symbol_name)) {
            if(ELF64_ST_BIND(sym_table[i].st_info) == GLOBAL) {
                Elf64_Half ndx = sym_table[i].st_shndx;
                if(ndx == SHN_UNDEF)
                {
                    *error_val = ERRORNOTGLOBAL;
                    fclose(file);
                    free(header_table);
                    free(sym_table);
                    free(strtab);
                    return FAILED;
                }
                else
                {
                    *error_val = FOUND;
                    fclose(file);
                    free(header_table);
                    free(sym_table);
		    free(strtab);
                    return sym_table[i].st_value;
                }
            }
            else {
                local_count += 1;
            }
        }
    }
    if(local_count > 0) {
        *error_val = ERRORLOCAL;
    }
    else {
        *error_val = NOTFOUND;
    }
    fclose(file);
    free(header_table);
    free(sym_table);
    free(strtab);
    return FAILED;
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