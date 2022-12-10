#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "include/resolve_kallsyms.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute#0440");
MODULE_DESCRIPTION("overwrite sys_call_table write protect via setting cr0");
MODULE_VERSION("0.01");

extern unsigned long __force_order ;
inline void mywrite_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}

void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

static int __init cr0_init(void)
{
    printk(KERN_INFO "cr0: loaded\n");
    char **text = kallsyms_lookup_name_("_text");
    disable_write_protection();
    text[0] = 0x90;
    enable_write_protection();
    return 0;
}

static void __exit cr0_exit(void)
{
    printk(KERN_INFO "cr0: unloaded\n");
}

module_init(cr0_init);
module_exit(cr0_exit);
