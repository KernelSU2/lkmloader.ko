#include "linux/kallsyms.h"
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/cpu.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <asm-generic/errno-base.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "mylkm: " fmt
#endif

int __init __nocfi ko_init(void) {
    pr_info("kallsyms_lookup_name: 0x%lx\n", (unsigned long) kallsyms_lookup_name);
    pr_info("init_mm: 0x%lx\n", (unsigned long) &init_mm);
    pr_info("kern_path: 0x%lx\n", (unsigned long) kern_path);
    return 0;
}

void ko_exit(void) {
	pr_info("mylkm exit\n");
}

module_init(ko_init);
module_exit(ko_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("5ec1cff");
MODULE_DESCRIPTION("LKM Test");
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
