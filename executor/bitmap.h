#include <stdio.h>

#define KERNEL_TEXT_BASE 0x81000000

typedef unsigned int uint32;

uint32* func_pcs;

uint32 readPcs()
{
	FILE* f = fopen("/funcaddr.map", "r");
	uint32 count = 0;
	if (f == NULL)
		return -1;
	/* detect the number of addresses */
	while (!feof(f)) {
		uint32 pc;
		int ret = fscanf(f, "0x%x\n", &pc);
		if (ret > 0) {
			count++;
		}
	}
	func_pcs = (uint32*)malloc(count * sizeof(uint32));
	if (func_pcs == NULL)
		return -2;
	fseek(f, 0, SEEK_SET);
	uint32* pp = func_pcs;
	while (!feof(f)) {
		uint32 pc;
		int ret = fscanf(f, "0x%x\n", &pc);
		if (ret > 0) {
			*(pp) = pc & 0xffffffff;
			pp++;
		}
	}
	fclose(f);
	return count;
}
