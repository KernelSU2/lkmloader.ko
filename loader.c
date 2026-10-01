#include "linux/elf.h"
#include "linux/fs.h"
#include "linux/mman.h"
#include "linux/ptrace.h"
#include <linux/cred.h>
#include <linux/cpu.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <asm/syscall.h>
#include <asm-generic/errno-base.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/mman.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include "kernel/module/internal.h"
#else
#include "kernel/module-internal.h"
#endif

/* kernels without CFI_CLANG (e.g. 4.x/5.x vendor trees) do not define __nocfi */
#ifndef __nocfi
#define __nocfi
#endif

/* arm64 gained __naked far later than arm; the hand-written asm below
   requires a naked function to keep its own stack frame */
#ifndef __naked
#define __naked __attribute__((naked))
#endif

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "lkmloader: " fmt
#endif

static char *module_path = NULL;
module_param(module_path, charp, 0644);

/* insmod params forwarded verbatim to the module being loaded
 * (e.g. "allow_shell=1 bundled=1"), empty by default */
static char *module_params = NULL;
module_param(module_params, charp, 0644);

unsigned long (*kallsyms_lookup_name_fn)(const char*);
struct pt_regs tmp_regs;
syscall_fn_t *syscall_table;

#if 0
long __nocfi load_module_user() {
    struct pt_regs *regs = current_pt_regs();
    memcpy(&tmp_regs, regs, sizeof(struct pt_regs));
    long res;
    int fd;
    size_t len, file_size;
    len = strlen(module_path) + 1;


    // 1. call openat(AT_FDCWD, module_path, O_RDONLY|O_CLOEXEC)
    tmp_regs.regs[0] = AT_FDCWD;
    tmp_regs.regs[1] = tmp_regs.sp - len;
    res = copy_to_user(tmp_regs.regs[1], module_path, len);
    if (res != 0) {
        pr_err("copy path to user stack: %ld\n", res);
        res = -EFAULT;
        goto out_exit;
    }
    tmp_regs.regs[2] = O_RDONLY | O_CLOEXEC;

    res = syscall_table[__NR_openat](&tmp_regs);
    if (res < 0) {
        pr_err("open in userspace failed: %ld\n", res);
        goto out_exit;
    }

    fd = res;
    pr_info("opened fd: %d\n", fd);

    // 2. call lseek(fd, 0, SEEK_END)
    tmp_regs.regs[0] = fd;
    tmp_regs.regs[1] = 0;
    tmp_regs.regs[2] = SEEK_END;
    res = syscall_table[__NR_lseek](&tmp_regs);
    if (res < 0) {
        pr_err("seek failed: %ld\n", res);
        goto out_close_fd;
    }

    file_size = res;
    pr_info("file size: %zu\n", file_size);

    // 3. call mmap()
    // addr
    tmp_regs.regs[0] = 0;
    // size
    tmp_regs.regs[1] = file_size;
    // prot
    tmp_regs.regs[2] = PROT_READ | PROT_WRITE;
    // flags
    tmp_regs.regs[3] = MAP_PRIVATE;
    // fd
    tmp_regs.regs[4] = fd;
    // off
    tmp_regs.regs[5] = 0;
    res = syscall_table[__NR_mmap](&tmp_regs);
    if (res < 0) {
        pr_err("mmap failed: %ld\n", res);
        goto out_close_fd;
    }

    pr_info("mmapped address 0x%lx\n", res);

out_close_fd:
    tmp_regs.regs[0] = fd;
    res = syscall_table[__NR_close](&tmp_regs);
    if (res < 0) {
        pr_err("close fd failed: %ld\n", res);
    }

out_exit:

    return res;
}
#endif

struct lookup_symbol_context {
    unsigned long result;
    const char *sym_name;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int (*kallsyms_on_each_match_symbol_fn)(int (*fn)(void *, unsigned long),
    const char *name, void *data) = NULL;
static int kallsyms_on_each_match_symbol_cb(void *data, unsigned long addr) {
    ((struct lookup_symbol_context *) data)->result = addr;
    return 0;
}
#endif

int (*kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *, 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6, 1, 0)
    struct module *,
#endif
    unsigned long),
    void *data);
static int kallsyms_on_each_symbol_cb(void *data, const char *name, 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6, 1, 0)
    struct module *unused_mod,
#endif
    unsigned long addr) {
    struct lookup_symbol_context *ctx = data;
    if (strcmp(name, ctx->sym_name) == 0) {
        *(unsigned long *) data = addr;
        return 1;
    }
    return 0;
}

// We only need kernel's symbol, not modules'
static unsigned long __nocfi resolve_kernel_symbol(const char *name) {
    struct lookup_symbol_context ctx = {
        .result = 0,
        .sym_name = name
    };
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    if (likely(kallsyms_on_each_match_symbol_fn)) {
        kallsyms_on_each_match_symbol_fn(
            kallsyms_on_each_match_symbol_cb,
            name, &ctx
        );
        return ctx.result;
    }
#endif

    if (likely(kallsyms_on_each_symbol_fn)) {
        kallsyms_on_each_symbol_fn(
            kallsyms_on_each_symbol_cb,
            &ctx
        );
        return ctx.result;
    }

    // TODO: exclude modules' symbols
    return kallsyms_lookup_name_fn(name);
}

static int __nocfi patch_module(void *buf, size_t len) {
    int ret = 0;
    if (len <= sizeof(Elf64_Ehdr)) {
        pr_err("module too small: %zu < %zu\n", len, sizeof(Elf64_Ehdr));
        return -EINVAL;
    }
    Elf64_Ehdr *eh = buf;
    if (eh->e_shentsize != sizeof(Elf64_Shdr)) {
        pr_err("invalid shentsize: %zu != %zu", (size_t) eh->e_shentsize, sizeof(Elf64_Shdr));
        return -EINVAL;
    }
    if (eh->e_shoff > len) {
        pr_err("shoff > len: %zu > %zu\n", (size_t) eh->e_shoff, len);
        return -EINVAL;
    }
    size_t shend_off = eh->e_shoff + eh->e_shentsize * eh->e_shnum;
    if (shend_off > len) {
        pr_err("shoff end > len: %zu > %zu\n", shend_off, len);
        return -EINVAL;
    }
    Elf64_Shdr *sh = buf + eh->e_shoff, *shend = buf + shend_off;
    Elf64_Sym *symtab = NULL, *symtab_end = NULL;
    char *strtab = NULL, *strtab_end = NULL;
    int idx = 0, symstr_idx = -1;
    for (; sh < shend; sh++, idx++) {
        if (sh->sh_type == SHT_SYMTAB && !symtab) {
            if (sh->sh_entsize != sizeof(Elf64_Sym)) {
                pr_err("symtab %d wrong entsize\n", idx);
                continue;
            }
            if (sh->sh_size % sizeof(Elf64_Sym) != 0) {
                pr_err("symtab %d not aligned\n", idx);
                continue;
            }
            if (sh->sh_offset >= len || sh->sh_offset + sh->sh_size > len) {
                pr_err("out of bound symtab %d\n", idx);
                continue;
            }
            symtab = buf + sh->sh_offset;
            symtab_end = (void *) symtab + sh->sh_size;
            symstr_idx = sh->sh_link;
            pr_info("symtab at section %d (str=%d)\n", idx, symstr_idx);
        } else if (sh->sh_type == SHT_STRTAB && symstr_idx == idx && !strtab) {
            if (sh->sh_offset >= len || sh->sh_offset + sh->sh_size > len) {
                pr_err("out of bound strtab %d\n", idx);
                continue;
            }
            strtab = buf + sh->sh_offset;
            strtab_end = strtab + sh->sh_size;
            pr_info("strtab at section %d\n", idx);
        }
    }
    if (symtab == NULL) {
        pr_err("symtab not found\n");
        return -EINVAL;
    }
    if (strtab == NULL) {
        pr_err("strtab not found (idx=%d)\n", symstr_idx);
        return -EINVAL;
    }

    Elf64_Sym *s;
    idx = 0;

    for (s = symtab; s < symtab_end; s++, idx++) {
        if (s->st_shndx == SHN_UNDEF) {
            char *name = strtab + s->st_name;
            if (name >= strtab_end || name < strtab) {
                pr_err("invalid sym %d name > len", idx);
                continue;
            }
            if (!*name) {
                continue;
            }
            unsigned long sym = resolve_kernel_symbol(name);
            if (!sym) {
                pr_warn("not found: sym %d name %s\n", idx, name);
            } else {
                pr_info("patch sym %d name %s -> 0x%lx", idx, name, sym);
                s->st_value = sym;
                s->st_shndx = SHN_ABS;
            }
        }
    }

    return ret;
}

static long __nocfi load_module(const char __user * params) {
    int (*load_module_fn)(struct load_info *info, const char __user *uargs, int flags)
        = kallsyms_lookup_name_fn("load_module");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    ssize_t (*kernel_read_file_fn)(struct file *file, loff_t offset, void **buf,
            size_t buf_size, size_t *file_size,
            enum kernel_read_file_id id) = kallsyms_lookup_name_fn("kernel_read_file");
#else
    int (*kernel_read_file_fn)(struct file *file, void **buf, loff_t *size,
            loff_t max_size, enum kernel_read_file_id id) = kallsyms_lookup_name_fn("kernel_read_file");
#endif
    struct file *(*filp_open_fn)(const char *, int, umode_t) = kallsyms_lookup_name_fn("filp_open");
    void (*filp_close_fn)(struct file *, fl_owner_t id) = kallsyms_lookup_name_fn("filp_close");
    if (!load_module_fn) {
        pr_err("no load_module found!\n");
        return -ENOSYS;
    }
    if (!kernel_read_file_fn) {
        pr_err("no kernel_read_file found!\n");
        return -ENOSYS;
    }
    if (!filp_open_fn) {
        pr_err("no filp_open found!\n");
        return -ENOSYS;
    }
    if (!filp_close_fn) {
        pr_err("no filp_close found!\n");
        return -ENOSYS;
    }

    struct load_info info = { };
	void *buf = NULL;
	int len;
    long ret = 0;
    struct file *f;
    f = filp_open_fn(module_path, O_RDONLY, 0);
    if (IS_ERR_OR_NULL(f)) {
        pr_err("open module failed: %ld\n", PTR_ERR(f));
        return PTR_ERR(f);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	len = kernel_read_file_fn(f, 0, &buf, INT_MAX, NULL, READING_MODULE);
#else
	{
		loff_t size = 0;
		int r;
		/* Huawei 4.19 kernel_read_file returns 0 on success and only
		 * stores the byte count in *size (upstream returns pos) */
		r = kernel_read_file_fn(f, &buf, &size, INT_MAX, READING_MODULE);
		len = (r < 0) ? r : (int)size;
	}
#endif
    if (len < 0) {
        pr_err("read module failed: %d\n", len);
        ret = len;
        goto out_close_file;
    }
    info.hdr = buf;
    info.len = len;

    ret = patch_module(buf, len);
    pr_info("patch_module result: %ld\n", ret);

    ret = load_module_fn(&info, params, 0);
    pr_info("load_module result: %ld\n", ret);

out_close_file:
    filp_close_fn(f, NULL);

    return ret;
}

unsigned long __nocfi do_in_task_work_c() {
    struct pt_regs *regs = current_pt_regs();
    size_t params_len = (module_params ? strlen(module_params) : 0) + 1;
    char __user *params = (char __user *)regs->sp - params_len;
    long ret;
    ret = copy_to_user(params, module_params ? module_params : "", params_len);
    if (ret != 0) {
        pr_err("create user params: %ld\n", ret);
    } else {
        ret = load_module(params);
        if (ret) {
            pr_err("load_module failed: %ld\n", ret);
        } else {
            pr_info("load_module success\n");
        }
    }

    unsigned long del_mod = syscall_table[__NR_delete_module];
    pr_info("del_mod: 0x%lx\n", del_mod);
    if (!del_mod) {
        pr_err("could not del self\n");
        regs->regs[0] = -ENOSYS;
        return 0;
    }
    memcpy(&tmp_regs, regs, sizeof(struct pt_regs));
    tmp_regs.regs[0] = tmp_regs.sp - sizeof("lkmloader");
    tmp_regs.regs[1] = 0;
    ret = copy_to_user(tmp_regs.regs[0], "lkmloader", sizeof("lkmloader"));
    if (ret != 0) {
        pr_err("copy mod name failed: %ld\n", ret);
        return 0;
    }
    return del_mod;
}

void __naked do_in_task_work(struct callback_head *head) {
    asm(
        "stp x29, x30, [sp, #-0x10]!;\n"
        "bl do_in_task_work_c;\n"
        "cmp x0, #0;\n"
        "b.eq failed;\n"
        "mov x17, x0;\n"
        ".extern tmp_regs;\n"
        "ldr x0, =tmp_regs;\n"
        "ldp x29, x30, [sp], #0x10;\n"
        "br x17;\n"
        "failed:\n"
        "ret;\n"
    );
}

struct callback_head my_task_work = {
    .func = do_in_task_work
};

int __init __nocfi ko_init(void) {
	pr_info("lkmloader init\n");

    if (!module_path) {
        pr_err("please specify module_path in cmdline!\n");
        return -ENOENT;
    }
    pr_info("module to load: %s\n", module_path);

    char buf[256];
    unsigned long addr, sz, found = 0, sprintf_addr;

    asm("ldr %0, =sprint_symbol":"=r"(sprintf_addr));
    char *s;
    int ntry = 0;
    int maxtry = 1000000;
    addr = sprintf_addr - 4;
    bool is_found = false;
    // search backward
    for (;;) {
        sprintf(buf, "%pSb", (void*) addr);
        s = strchr(buf, '+');
        if (!s) {
            pr_err("no + found before addr-1\n");
            break;
        }
        *s = 0;
        if (strcmp(buf, "kallsyms_lookup_name") == 0) {
            pr_info("found kallsyms_lookup_name before %d\n", ntry);
            is_found = true;
        }
        s++;
        if (sscanf(s, "%lx", &sz) != 1) {
            pr_err("no off before sym\n");
            break;
        }
        if (is_found) {
            found = addr - sz;
            break;
        }
        addr -= sz + 4;
        ++ntry;
        --maxtry;
        if (maxtry == 0) {
            break;
        }
    }

    // search forward
    if (unlikely(!found && maxtry)) {
        pr_info("no kallsyms_lookup_name found before %d\n", ntry);
        ntry = 0;
        addr = sprintf_addr;
        // search forward
        for (;;) {
            sprintf(buf, "%pSb", (void*) addr);
            s = strchr(buf, '+');
            if (!s) {
                pr_err("no + found after %d syms\n", ntry);
                break;
            }
            *s = 0;
            // pr_info("after %d: %s\n", ntry, buf);
            if (strcmp(buf, "kallsyms_lookup_name") == 0) {
                pr_info("found kallsyms_lookup_name: after %d\n", ntry);
                found = addr;
                break;
            }
            if (strcmp(buf, "_end") == 0) {
                pr_err("hit _end after %d\n", ntry);
                break;
            }
            ++s;
            s = strchr(s, '/');
            if (!s) {
                pr_err("no / found after %d syms\n", ntry);
                break;
            }
            s++;
            if (sscanf(s, "%lx", &sz) != 1) {
                break;
            }
            if (sz == 0) {
                pr_warn("no size!\n");
                sz = 4;
            }
            addr += sz;
            ++ntry;
            --maxtry;
            if (maxtry == 0) {
                break;
            }
        }
    }
    if (!found) {
        pr_err("not found, remain try: %d\n", maxtry);
        return -ENOSYS;
    } else {
        pr_info("found kallsyms_lookup_name: 0x%lx!!!!!\n", found);
    }
    
    kallsyms_lookup_name_fn = (void*) found;
    unsigned long a;
    a = kallsyms_lookup_name_fn("task_work_add");
    pr_info("kallsyms_lookup_name task_work_add: 0x%lx\n", a);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    int (*task_work_add_fn)(struct task_struct *task, struct callback_head *twork,
			enum task_work_notify_mode mode) = a;
#else
    int (*task_work_add_fn)(struct task_struct *task, struct callback_head *twork,
			bool notify) = a;
#endif
    a = kallsyms_lookup_name_fn("sys_call_table");
    pr_info("kallsyms_lookup_name sys_call_table: 0x%lx\n", a);
    syscall_table = a;

    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    a = kallsyms_lookup_name_fn("kallsyms_on_each_match_symbol");
    pr_info("kallsyms_lookup_name kallsyms_on_each_match_symbol: 0x%lx\n", a);
    kallsyms_on_each_match_symbol_fn = a;
#endif

    a = kallsyms_lookup_name_fn("kallsyms_on_each_symbol");
    pr_info("kallsyms_lookup_name kallsyms_on_each_symbol: 0x%lx\n", a);
    kallsyms_on_each_symbol_fn = a;

    if (!task_work_add_fn || !syscall_table) {
        pr_err("some symbol not found!\n");
        return -ENOSYS;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    int ret = task_work_add_fn(current, &my_task_work, TWA_RESUME);
#else
    int ret = task_work_add_fn(current, &my_task_work, true);
#endif
    if (ret) {
        pr_err("task_work_add failed: %d\n", ret);
        return -ENOSYS;
    }

    return 0;
}

void ko_exit(void) {
	pr_info("lkmloader exit\n");
}

module_init(ko_init);
module_exit(ko_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("5ec1cff");
MODULE_DESCRIPTION("LKM Loader");
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
