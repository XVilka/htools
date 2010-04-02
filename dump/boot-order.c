/*
 * A tool for reading and decoding the value of sys_boot on OMAP 34xx.
 *
 * Copyright (C) 2010 David Kozub <zub at linux.fjfi.cvut.cz>
 *
 * Physical memory reading inspired by devmem2:
 *    http://www.lartmaker.nl/lartware/port/
 *
 * Data taken from TI docs available online. (See below.)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#define SYS_BOOT_ADDR 0x480022f0UL

/*
 * Data taken from:
 * http://focus.ti.com/general/docs/wtbu/wtbudocumentcenter.tsp?templateId=6123&navigationId=12667
 * (Technical Documents/OMAP34xx Multimedia Device Silicon Revision 3.1.x (SWPU223_FinalEPDF_02_18_2010.pdf, 35 MB))
 *
 * sys_boot is specified in 26.2.3 Boot Configuration (p. 3374)
 */

typedef enum
{
	None,
	XIP,
	XIPwait,
	DOC,
	NAND,
	OneNAND,
	MMC1,
	MMC2,
	USB,
	UART3,
	BOOT_LAST = UART3
} BootType;

const char * DEVICE_NAMES[BOOT_LAST+1] =
{
	"--",	// None
	"XIP",
	"XIPwait",
	"DOC",
	"NAND",
	"OneNAND",
	"MMC1",
	"MMC2",
	"USB",
	"UART3"
};

#define BOOT_RECORD_NDEVS 5

typedef struct
{
	unsigned char sys_boot;			// sys_boot[5:0]
	BootType b[BOOT_RECORD_NDEVS];	// boot devices
} BootRecord;

const BootRecord BOOT_TABLE[] =
{
	// reserved
	{0x04, { OneNAND,	USB, None, None, None } },
	{0x05, { MMC2,		USB, None, None, None } },
	{0x06, { MMC1,		USB, None, None, None } },
	// reserved
	{0x0d, { XIP,		USB,	UART3,	MMC1,	None } },
	{0x0e, { XIPwait,	DOC,	USB,	UART3,	MMC1 } },
	{0x0f, { NAND,		USB,	UART3,	MMC1,	None } },
	{0x10, { OneNAND,	USB,	UART3,	MMC1,	None } },
	{0x11, { MMC2,		USB,	UART3,	MMC1,	None } },
	{0x12, { MMC1,		USB,	UART3,	None,	None } },
	{0x13, { XIP,		UART3,	None,	None,	None } },
	{0x14, { XIPwait,	DOC,	UART3,	None,	None } },
	{0x15, { NAND,		UART3,	None,	None,	None } },
	{0x16, { OneNAND,	UART3,	None,	None,	None } },
	{0x17, { MMC2,		UART3,	None,	None,	None } },
	{0x18, { MMC1,		UART3,	None,	None,	None } },
	{0x19, { XIP,		USB,	None,	None,	None } },
	{0x1a, { XIPwait,	DOC,	USB,	None,	None } },
	{0x1b, { NAND,		USB,	None,	None,	None } },
	// reserved
	{0x1f, { XIP,		USB,	UART3,	None,	None } },
	// reserved
	{0x24, { USB,		OneNAND,	None,	None,	None } },
	{0x25, { USB,		MMC2,		None,	None,	None } },
	{0x26, { USB,		MMC1,		None,	None,	None } },
	// reserved
	{0x2d, { USB,		UART3,	MMC1,	XIP,		None } },
	{0x2e, { USB,		UART3,	MMC1,	XIPwait,	None } },
	{0x2f, { USB,		UART3,	MMC1,	NAND,		None } },
	{0x30, { USB,		UART3,	MMC1,	OneNAND,	None } },
	{0x31, { USB,		UART3,	MMC1,	MMC2,		None } },
	{0x32, { USB,		UART3,	MMC1,	None,		None } },
	{0x33, { UART3,		XIP,		None,	None,	None } },
	{0x34, { UART3,		XIPwait,	DOC,	None,	None } },
	{0x35, { UART3,		NAND,		None,	None,	None } },
	{0x36, { UART3,		OneNAND,	None,	None,	None } },
	{0x37, { UART3,		MMC2,		None,	None,	None } },
	{0x38, { UART3,		MMC1,		None,	None,	None } },
	{0x39, { USB,		XIP,		None,	None,	None } },
	{0x3a, { USB,		XIPwait,	DOC,	None,	None } },
	{0x3b, { USB,		NAND,		None,	None,	None } },
	// reserved
	{0x3f, { XIP,		USB,	UART3,	None,	None } },
};

unsigned char read_byte(uintptr_t addr)
{
	const size_t MAP_SIZE = 4096UL;
	const size_t MAP_MASK = MAP_SIZE - 1;

	int fd = open("/dev/mem", O_RDWR | O_SYNC);

	if (fd == -1)
	{
		perror("can't open /dev/mem");
		abort();
	}

	unsigned char *map_base = mmap(0, MAP_SIZE, PROT_READ, MAP_SHARED,
		fd, addr & ~MAP_MASK);
		printf("MAP_BASE : 0x%08lx  MAP_SIZE : 0x%08lx  MAP_MASK : 0x%08lx \n", map_base, MAP_SIZE, MAP_MASK);

	if (map_base == (void*)-1)
	{
		perror("mmap() failed");
		abort();
	}

	unsigned char ret_val = *(map_base + (addr & MAP_MASK));

	if (munmap(map_base, MAP_SIZE) != 0)
	{
		perror("munmap() failed");
		abort();
	}

	close(fd);

	return ret_val;
}

int main(void)
{
	unsigned char sys_boot = read_byte(SYS_BOOT_ADDR) & 0x3F; // lower 6 bits

	printf("sys_boot[5:0]: 0x%02x\n", sys_boot);

	// Decode using BOOT_TABLE
	size_t idx = 0;
	while (idx < sizeof(BOOT_TABLE)/sizeof(BOOT_TABLE[0]) && BOOT_TABLE[idx].sys_boot != sys_boot)
		idx++;

	if (idx < sizeof(BOOT_TABLE)/sizeof(BOOT_TABLE[0]))
	{
		printf("Boot order: ");
		for (int i = 0; i < BOOT_RECORD_NDEVS; ++i)
			printf("%s ", DEVICE_NAMES[BOOT_TABLE[idx].b[i]]);
		puts("");
	}
	else
		puts("This sys_boot value is documented as RESERVED. Odd...");

	return 0;
}
