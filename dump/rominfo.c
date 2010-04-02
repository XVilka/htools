/*
 * A module for reading info about boot ROM on OMAP 34xx.
 *
 * Copyright (C) 2010 XVilka <xvilka at gmail.com>
 *
 * Physical memory reading inspired by devmem2:
 *    http://www.lartmaker.nl/lartware/port/
 *
 * Data taken from TI docs available online.
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

/*
 * Data taken from:
 * http://focus.ti.com/general/docs/wtbu/wtbudocumentcenter.tsp?templateId=6123&navigationId=12667
 * (Technical Documents/OMAP34xx Multimedia Device Silicon Revision 3.1.x (SWPU223_FinalEPDF_02_18_2010.pdf, 35 MB))
 *
 * all of this is specified in 26.4.2 ROM Memory Map (p. 3381)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include <mach/cpu.h>
#include <mach/omap34xx.h>
#include <mach/control.h>

MODULE_DESCRIPTION("Get some info from ROM");
/*
 See OMAP34xx Multimedia Device Silicon Revision 3.1.x
 Technical Reference Manual (Public Version)
 Literature Number: SWPU223
 July 2007 – Revised February 2010
*/

/*
 ROM CODE starts at 0x00014000 
 * 
 * ROM CRC32 start at 				0x14020
 * ROM dead loops start at 			0x14080
 * ROM code start at				0x14100
 * ROM CRC32 HS information at      0x14200
 * ROM CODE version at				0x1BFFC
 * ROM void							0x1BFFF
 */
  
#define M "rominfo: "
#define SRAM_BOOTLOADER_SZ	    0x80
#define OMAP3430_ROM_BASE       0x00014000
#define OMAP3430_SRAM_ROM_BASE  0x40000000
#define OMAP3430_SRAM_ROM_END   0x400FFFFF
#define OMAP3_SRAM_PA           0x40200000
#define OMAP3_SRAM_VA           0xfe400000
#define OMAP3_SRAM_PUB_PA       0x40208000
#define OMAP3_SRAM_PUB_VA       (OMAP3_SRAM_VA + 0x8000)

static unsigned long rom_boot_base;
static unsigned long rom_boot_start;
static unsigned long rom_boot_size;
static unsigned long rom_boot_end;

static int is_sram_locked = 1;

u8 rom_boot_readb(u16 offset)
{
        return __raw_readb(rom_boot_start + offset);
}

u16 rom_boot_readw(u16 offset)
{
        return __raw_readw(rom_boot_start + offset);
}

u32 rom_boot_readl(u16 offset)
{
        return __raw_readl(rom_boot_start + offset);
}

/*
static int is_sram_locked(void)
{
    int type = 0;
    if (cpu_is_omap242x())
        type = omap_rev() & OMAP2_DEVICETYPE_MASK;
	if (type == GP_DEVICE) {
                if (cpu_is_omap34xx()) {
                        __raw_writel(0xFFFF, OMAP34XX_VA_REQINFOPERM0);
                        __raw_writel(0xFFFF, OMAP34XX_VA_READPERM0); 
                        __raw_writel(0xFFFF, OMAP34XX_VA_WRITEPERM0);
                        __raw_writel(0x0, OMAP34XX_VA_ADDR_MATCH2);
                        __raw_writel(0xFFFFFFFF, OMAP34XX_VA_SMS_RG_ATT0);
                type = omap_rev() & OMAP2_DEVICETYPE_MASK;

    if (type == GP_DEVICE) {
                if (cpu_is_omap34xx()) {
                        __raw_writel(0xFFFF, OMAP34XX_VA_REQINFOPERM0); 
                        __raw_writel(0xFFFF, OMAP34XX_VA_READPERM0);
                        __raw_writel(0xFFFF, OMAP34XX_VA_WRITEPERM0);
                        __raw_writel(0x0, OMAP34XX_VA_ADDR_MATCH2);
                        __raw_writel(0xFFFFFFFF, OMAP34XX_VA_SMS_RG_ATT0);
                }
                return 0;
        } else
                return 1;
}
* 
* CONFIG_ARCH_OMAP3_HS
* 
*/

static unsigned long int calculate(void) {

if (is_sram_locked) {
	rom_boot_base = OMAP3_SRAM_PUB_VA;
	rom_boot_start = OMAP3_SRAM_PUB_PA;
	if ((omap_type() == OMAP2_DEVICE_TYPE_EMU) ||
		(omap_type() == OMAP2_DEVICE_TYPE_SEC)) 
	{
		rom_boot_size = 0x7000; /* 28K */
		
	} else 
	{
		rom_boot_size = 0x8000; /* 32K */
	}
} else {
	rom_boot_base = OMAP3_SRAM_VA;
	rom_boot_start = OMAP3_SRAM_PA;
	rom_boot_size = 0x10000; /* 64K */
}
return rom_boot_start + rom_boot_size;
}

static int __init inforom_init(void)
{
	u8 crc32[4] = 0;
	u8 hs[4] = 0;
	u8 ver[3] = 0;
	if (cpu_is_omap3430()) {
		pr_info(M "Reading shadowed boot rom in memory...\n");
		if (rom_boot_end = calculate()) {
			pr_info(M "Found address of some bootloader code!\n");
			pr_info(M "BASE 0x%08lx , START 0x%08lx , END 0x%08lx , SIZE 0x%lx\n", rom_boot_base, rom_boot_start, rom_boot_end, rom_boot_size);
			mempcpy(&crc32, &(rom_boot_readl(0x00020), 4);
			pr_info(M "CRC32 : %p %p %p %p \n", crc32[0], crc32[1], crc32[2], crc32[3]);
			memcpy(&hs, &(rom_boot_readl(0x0200), 4);
			pr_info(M "HS bytes : %p %p %p %p \n", hs[0], hs[1], hs[2], hs[3]);
			ver[0] = rom_boot_readb(0x1BFFC);
			ver[1] = rom_boot_readb(0x1BFFD);
			ver[2] = rom_boot_readb(0x1BFFE);
			pr_info(M "VERSION info : %p %p %p \n", ver[0], ver[1], ver[2]);
		} else {
			pr_info(M "Unknown reading physical memory error!\n");
		}
	}
	return 0;
}

static void inforom_exit(void)
{
	pr_info(M "exit\n");
}

module_init(inforom_init);
module_exit(inforom_exit);
MODULE_LICENSE("GPL");
