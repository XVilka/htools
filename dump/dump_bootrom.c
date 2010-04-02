/*
 * A module for reading boot ROM on OMAP 34xx.
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

MODULE_DESCRIPTION("dump boot ROM");
/*
 See OMAP34xx Multimedia Device Silicon Revision 3.1.x
 Technical Reference Manual (Public Version)
 Literature Number: SWPU223
 July 2007 – Revised February 2010
*/

/*
 ROM CODE starts at 0x00014000
 */
  
#define M "dump_bootrom: "
#define SRAM_BOOTLOADER_SZ	    0x80
#define OMAP3430_ROM_BASE       0x00014000
#define OMAP3430_SRAM_ROM_BASE  0x40000000
#define OMAP3430_SRAM_ROM_END   0x400FFFFF
#define OMAP3_SRAM_PA           0x40200000
#define OMAP3_SRAM_VA           0xfe400000
#define OMAP3_SRAM_PUB_PA       0x40208000
#define OMAP3_SRAM_PUB_VA       (OMAP3_SRAM_VA + 0x8000)
#define DUMP_FILENAME           "/data/bootrom.bin"

static unsigned long rom_boot_base;
static unsigned long rom_boot_start;
static unsigned long rom_boot_size;
static unsigned long rom_boot_end;

bool is_sram_locked = 1;

u8 rom_boot_readb(unsigned long offset)
{
        return __raw_readb(rom_boot_start + offset);
}

long _x_sys_open (const char *name, int flags, int mode)
{
   int fd = get_unused_fd();
   struct file *f = filp_open(name, flags, mode);
   fd_install(fd, f);
   return fd;
}

asmlinkage long _x_write(unsigned int fd, const char * buf, unsigned long count)
{
        int error;
        struct file * file;
        struct dentry * dentry;
        struct inode * inode;
        long (*write)(struct inode *, struct file *, const char *, unsigned long);

        error = -EBADF;
        file = fget(fd);
        if (!file)
                return error;
        dentry = file->f_dentry;
        if (!dentry) | (!(file->f_mode & 2)) {
			fput(file);
			return error;
		}
        error = locks_verify_area(FLOCK_VERIFY_WRITE,inode,file,file->f_pos,count);
        if (error)
                goto out;
        error = -EINVAL;
        if (!file->f_op || !(write = file->f_op->write))
                goto out;
        down(&inode->i_sem);
        error = write(inode,file,buf,count);
        up(&inode->i_sem);
out:
        fput(file);
        return error;
}

long _x_sys_close(unsigned int fd)
{
        int error;
        struct file * filp;
        struct files_struct * files;

        files = current->files;
        error = -EBADF;
        if (fd < NR_OPEN && (filp = files->fd[fd]) != NULL) {
                put_unused_fd(fd);
                FD_CLR(fd, &files->close_on_exec);
                files->fd[fd] = NULL;
                error = close_fp(filp);
        }
        return error;
}


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

static void write_file(char *filename, u8 *data)
{
	struct file *file;
	loff_t pos = 0;
	int fd;
	
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = _x_sys_open(filename, O_WRONLY|O_CREAT, 0644);
	if (fd >= 0) {
		_x_sys_write(fd, data, strlen(data));
		file = fget(fd);
		if (file) {
			vfs_write(file, data, strlen(data), &pos);
			fput(file);
		}
		_x_sys_close(fd);
	}
	set_fs(old_fs);
}


static int __init dump_bootrom_init(void)
{
	u8 *buf;
	size_t buf_size = 1;
	unsigned long offset = 0;

	if (cpu_is_omap3430()) {
		pr_info(M "Reading shadowed boot rom in memory...\n");
		if (rom_boot_end = calculate()) {
			printk(M "Found address of some bootloader code!\n");
			printk(M "BASE 0x%08lx , START 0x%08lx , END 0x%08lx , SIZE 0x%lx\n", rom_boot_base, rom_boot_start, rom_boot_end, rom_boot_size); 
			buf_size = (size_t)rom_boot_size;
			buf = kmalloc(buf_size, GFP_ATOMIC);
			while (rom_boot_start + offset < rom_boot_end)
			{
				*buf++ = rom_boot_readb(offset++);
			}
			pr_info(M "Writing memory dump in file...\n");
			write_file(DUMP_FILENAME, buf);
			kfree(buf);
			pr_info(M "Dumping of boot ROM done!\n");
			printk(M "Size of dump file is %i bytes.\n", buf_size);
		} else {
			pr_info(M "Unknown reading physical memory error!\n");
		}
	}
	return 0;
}


static void dump_bootrom_exit(void)
{
	pr_info(M "exit\n");
}

module_init(dump_bootrom_init);
module_exit(dump_bootrom_exit);
MODULE_LICENSE("GPL");
