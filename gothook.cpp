#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <errno.h>

#include "gothook.h"

#define DEBUG

#ifdef DEBUG
#define LOG(format, ...) fprintf(stdout, format, ##__VA_ARGS__)
#else
#define LOG(format, ...)
#endif

int change_addr_to_rwx(unsigned long addr) {
	unsigned long pagesize = sysconf(_SC_PAGESIZE);
	unsigned long pagestart = addr & (~(pagesize - 1));
	int nRet = mprotect((void *)pagestart, (pagesize), PROT_READ | PROT_WRITE | PROT_EXEC);
	if (nRet == -1) {
		LOG("[-] mprotect error\n");
		return -1;
	}
	return 0;
}

int write_data_to_addr(unsigned long addr, unsigned long value) {
	int nRet = change_addr_to_rwx(addr);
	if (-1 == nRet) {
		LOG("[-] write_data_to_addr error\n");
		return -1;
	}
	*(unsigned long *)(addr) = value;
	return 0;
}

unsigned long get_module_base(pid_t pid, const char *module_name) {
	FILE *fp = NULL;
	unsigned long addr = 0;
	char *pAddrRange = NULL;
	char filename[32] = {0};
	char line[1024] = {0};

	if (pid < 0) {
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	}
	else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}
	fp = fopen(filename, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				pAddrRange = strtok(line, "-");
				addr = strtoul(pAddrRange, NULL, 16);
#if defined(__x86_64__)
				if (addr == 0x400000) {
					addr = 0;
				}
#elif defined(__i386__)
				if (addr == 0x08048000) {
					addr = 0;
				}
#endif
				break;
			}
		}
		fclose(fp);
	}
	return addr;
}

int getGotTableInfo(const char *lib, unsigned long *base, unsigned long *size) {
	int fd = open(lib, O_RDONLY);
	if (fd < 0) {
		LOG("[-] open file error: %s\n", strerror(errno));
		return -1;
	}
#if defined(__x86_64__)
	Elf64_Ehdr elf_header;
	Elf64_Shdr elf_section_header;
#elif defined(__i386__)
	Elf32_Ehdr elf_header;
	Elf32_Shdr elf_section_header;
#endif
	memset(&elf_header, 0, sizeof(elf_header));
	memset(&elf_section_header, 0, sizeof(elf_section_header));
	read(fd, &elf_header, sizeof(elf_header));
	lseek(fd, elf_header.e_shstrndx * elf_header.e_shentsize + elf_header.e_shoff, SEEK_SET);
	read(fd, &elf_section_header, sizeof(elf_section_header));

	char *lpStringTable = (char *)malloc(elf_section_header.sh_size);
	if (lpStringTable == NULL) {
		LOG("[-] malloc error: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	lseek(fd, elf_section_header.sh_offset, SEEK_SET);
	read(fd, lpStringTable, elf_section_header.sh_size);
	lseek(fd, elf_header.e_shoff, SEEK_SET);

	char ret = -1;

	for (int i = 0; i < elf_header.e_shnum; i++) {
		memset(&elf_section_header, 0, sizeof(elf_section_header));
		read(fd, &elf_section_header, sizeof(elf_section_header));
		if (elf_section_header.sh_type == SHT_PROGBITS) {
			// LOG("sh name: %s\n", lpStringTable + elf_section_header.sh_name);
			if (strcmp(lpStringTable + elf_section_header.sh_name, ".got") == 0) {
				*base = elf_section_header.sh_addr;
				*size = elf_section_header.sh_size;
				ret = 0;
				break;
			}
		}
	}

	close(fd);

	return ret;
}

int hookFunc(const char *lib, void *symbol, void *new_func, void **old_func) {
	unsigned long gotOff;
	unsigned long gotSize;
	if (getGotTableInfo(lib, &gotOff, &gotSize) == -1) {
		LOG("[-] get got table offset and size error\n");
		return -1;
	}
	char ret = -1;
	unsigned long base = get_module_base(-1, lib);
	for (unsigned long i = 0; i < gotSize; i += sizeof(long)) {
		if ((unsigned long)symbol == (*((unsigned long *)(base + gotOff + i)))) {
			*old_func = symbol;
			write_data_to_addr(base + gotOff + i, (unsigned long)new_func);
			ret = 0;
		}
	}
	if (ret == -1) {
		LOG("[-] unable find symbol addr in got table\n");
	}
	return ret;
}
