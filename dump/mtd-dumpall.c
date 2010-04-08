/*
 * Copyright (C) 2010 Marc Hellwig
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; see the file COPYING. If not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Dump MTD NAND device ignoring the partitioning and interleaving OOB data
 * for offline data recovery and analysis.
 *
 * Author: Marc Hellwig (Marc.Hellwig@gmail.com)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/err.h>
#include <linux/mtd/mtd.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define PRINT_PREF KERN_INFO "mtd_dumpall: "

static int dev;
static int startpage;
static int countpage;
module_param(dev, int, S_IRUGO);
module_param(startpage, int, S_IRUGO);
module_param(countpage, int, S_IRUGO);
MODULE_PARM_DESC(dev, "MTD device number to use");
MODULE_PARM_DESC(startpage, "first page to dump");
MODULE_PARM_DESC(countpage, "number of pages to dump");

/* Our partition node structure */
struct mtd_part {
	struct mtd_info mtd;
	struct mtd_info *master;
	uint64_t offset;
	int index;
	struct list_head list;
	int registered;
};

/*
 * Given a pointer to the MTD object in the mtd_part structure, we can retrieve
 * the pointer to that structure with this macro.
 */
#define PART(x)  ((struct mtd_part *)(x))

static struct mtd_info *mtd;
static struct mtd_info *master;
static unsigned char *iobuf;

static int pgsize;
static int ebcnt;
static int pgcnt;

static struct proc_dir_entry *proc_mtd;

typedef enum {
	DUMPALL_READ,
	DUMPALL_PAGE_DATA,
	DUMPALL_OOB_DATA,
	DUMPALL_FINISHED
} dumpallmode_t;
static dumpallmode_t dumpmode = DUMPALL_READ;
static int dumppage;
static int dumppos;
static int dumpsize;

#define DUMP_PARAM_BUFFER_MAX_SIZE		1024
static char dump_param_buffer[DUMP_PARAM_BUFFER_MAX_SIZE];
static unsigned long dump_param_buffer_size = 0;

static int dumpall_read_raw_page(int block)
{
	int ret;
	struct mtd_oob_ops ops;

	ops.mode      = MTD_OOB_RAW;
	ops.len       = master->writesize;
	ops.retlen    = 0;
	ops.ooblen    = master->oobsize;
	ops.oobretlen = 0;
	ops.ooboffs   = 0;
	ops.datbuf    = iobuf;
	ops.oobbuf    = iobuf;
	ret = master->read_oob(master, block*master->writesize, &ops);	
	if (ops.retlen != master->writesize) {
		printk(PRINT_PREF "error: read oob failed.\n");
	}
	printk(PRINT_PREF "MTD read %u bytes pagedata at %08x ret=%d\n", 
		ops.retlen, block*master->writesize, ret);
	return ops.retlen;
}

static int dumpall_read_proc (char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char line[128];
	int j;
	int used_bytes, psize;
	char *p;

	used_bytes = 0;
	if (off == 0) {
		dumpmode = DUMPALL_READ;
		dumppage = startpage;
		dumppos = 0;
	}
	while (dumpmode != DUMPALL_FINISHED) {
		switch (dumpmode) {
			case DUMPALL_READ:
				dumpsize = dumpall_read_raw_page(dumppage);	
				dumpmode = DUMPALL_PAGE_DATA;
				break;
			case DUMPALL_PAGE_DATA:
				if (dumppos < dumpsize) {
					p = line;
					p += sprintf(p, "d%08x:", dumppage * master->writesize + dumppos);
					for (j = 0; j < 32 && (dumppos+j) < dumpsize; j++)
						p += sprintf(p, "%02x",(unsigned int)iobuf[dumppos+j]);
					p += sprintf(p, "\n");
					psize = p - line;
					if ((count - used_bytes) >= psize) {
						memcpy(page + used_bytes, line, psize);
						used_bytes += psize;
						dumppos += j;
 					} else {
						*eof = 0;
						*start = (char *)1;
						return used_bytes;
					}
				} else {
					dumppos = 0;
					dumpmode = DUMPALL_OOB_DATA;
				}
				cond_resched();

				break;
			case DUMPALL_OOB_DATA:
				if (dumppos < master->oobsize) {
					p = line;
					p += sprintf(p, "o%08x:", dumppage * master->writesize + dumppos);
					for (j = 0; j < 32 && (dumppos+j) < master->oobsize; j++)
						p += sprintf(p, "%02x",(unsigned int)iobuf[dumpsize+dumppos+j]);
					p += sprintf(p, "\n");
					psize = p - line;
					if ((count - used_bytes) >= psize) {
						memcpy(page + used_bytes, line, psize);
						used_bytes += psize;
						dumppos += j;
 					} else {
						*eof = 0;
						*start = (char *)1;
						return used_bytes;
					}
				} else {
					dumppos = 0;
					if (++dumppage >= startpage + countpage) 
						dumpmode = DUMPALL_FINISHED;
					else
						dumpmode = DUMPALL_READ;
				}
				cond_resched();

				break;
			default:
				break;
		}
	}
	*eof = 1;
	*start = (char *)1;
	return used_bytes;
}

static int dumpall_write_proc(struct file *file, const char *buffer, unsigned long count,
		   void *data)
{
	dump_param_buffer_size = count;
	if (dump_param_buffer_size > DUMP_PARAM_BUFFER_MAX_SIZE ) {
		dump_param_buffer_size = DUMP_PARAM_BUFFER_MAX_SIZE;
	}
	
	if ( copy_from_user(dump_param_buffer, buffer, dump_param_buffer_size) ) {
		return -EFAULT;
	}
	
	sscanf(dump_param_buffer, "%d %d", &startpage, &countpage);
	printk(PRINT_PREF "mtd dumpall: startpage=%d countpage=%d\n", 
		startpage, countpage);
	
	proc_mtd->size = countpage * master->writesize;

	return dump_param_buffer_size;
}

static int __init mtd_dumpall_init(void)
{
	uint64_t tmp;
	int err;
	struct mtd_part *part;

	printk(KERN_INFO "\n");
	printk(KERN_INFO "=================================================\n");
	printk(PRINT_PREF "MTD device: %d\n", dev);

	mtd = get_mtd_device(NULL, dev);
	if (IS_ERR(mtd)) {
		err = PTR_ERR(mtd);
		printk(PRINT_PREF "error: Cannot get MTD device\n");
		return err;
	}
	part = PART(mtd);
	// Switch to Master MTD !!MH!! This is dangerous ... 
	// Do a few safety checks before assigning the pointer
	master = part->master;

	pgsize = master->writesize;
	tmp = master->size;
	do_div(tmp, master->erasesize);
	ebcnt = tmp;
	pgcnt = master->erasesize / master->writesize;

	printk(PRINT_PREF "MTD device name %s index %d size %llu, eraseblock size %u, "
	       "page size %u, count of eraseblocks %u, pages per "
	       "eraseblock %u, OOB size %u, startpage %u, countpage %u\n",
	       master->name, master->index, (unsigned long long)master->size, master->erasesize,
	       pgsize, ebcnt, pgcnt, master->oobsize, startpage, countpage);

	err = -ENOMEM;
	iobuf = kmalloc(master->writesize + master->oobsize, GFP_KERNEL);
	if (!iobuf) {
		printk(PRINT_PREF "error: cannot allocate memory\n");
	} else {

		if ((proc_mtd = create_proc_entry( "mtd_dumpall", 0644, NULL ))) {
			proc_mtd->read_proc = dumpall_read_proc;
			proc_mtd->write_proc = dumpall_write_proc;
		}
		err = 0;
	}

	if (err)
		printk(PRINT_PREF "error %d occurred\n", err);
	printk(KERN_INFO "=================================================\n");
	return err;
}
module_init(mtd_dumpall_init);

static void __exit mtd_dumpall_exit(void)
{
	remove_proc_entry( "mtd_dumpall", NULL);
	put_mtd_device(mtd);
	if (iobuf) kfree(iobuf);
	return;
}
module_exit(mtd_dumpall_exit);

MODULE_DESCRIPTION("Dump MTD module");
MODULE_AUTHOR("Marc Hellwig");
MODULE_LICENSE("GPL");