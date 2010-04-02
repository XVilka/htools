// agcc dump.c -o dump
// adb push dump /data/local/tmp/dump
// adb shell su -c '/data/local/tmp/dump' > dump.bin

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

#define OMAP3430_SRAM_BASE 0x40000000
#define OMAP3430_SRAM_SIZE 0x00100000
#define OMAP3430_ROM_BASE  0x00014000
// #define OMAP3430_ROM_BASE  0x00000000
// #define OMAP3430_ROM_SIZE  0x00008000 /* HS devices */
#define OMAP3430_ROM_SIZE 0x0008000 /* GP devices */

int main(int argc, char *argv) {
	int fd = open("/dev/mem", O_RDONLY);
	if (fd < 0) {
		perror("/dev/mem");
		exit(-1);
	}

	unsigned char *map_base;
	map_base = mmap(0, OMAP3430_SRAM_SIZE, PROT_READ, MAP_SHARED, fd, (off_t)OMAP3430_SRAM_BASE);
	if (map_base == MAP_FAILED) {
		perror("mmap failed");
		exit(-1);
	}

	write(1, map_base + OMAP3430_ROM_BASE, OMAP3430_ROM_SIZE);

	munmap(map_base, OMAP3430_SRAM_SIZE);
	close(fd);
	return 0;
}
