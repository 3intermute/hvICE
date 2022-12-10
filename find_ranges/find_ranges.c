#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <asm/io.h>
#include "include/resolve_kallsyms.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute#0440");
MODULE_DESCRIPTION("find kernel code start/end");
MODULE_VERSION("0.01");

static int __init find_ranges_init(void) {
    printk(KERN_INFO "ICE: kernel module loaded");
    printk(KERN_INFO "ICE: kernel code start @ GVA %llx\n", kallsyms_lookup_name_("_text"));
    printk(KERN_INFO "                       @ GPA %llx\n", virt_to_phys(kallsyms_lookup_name_("_text")));
    printk(KERN_INFO "ICE: kernel code end @ GVA %llx\n",  kallsyms_lookup_name_("_etext"));
    printk(KERN_INFO "                       @ GPA %llx\n", virt_to_phys(kallsyms_lookup_name_("_etext")));


    // adapted from libvmi offset finder
    struct task_struct *p = NULL;
    unsigned long commOffset;
    unsigned long tasksOffset;
    unsigned long mmOffset;
    unsigned long pidOffset;
    unsigned long pgdOffset;
    unsigned long addrOffset;

    p = current;

    if (p != NULL) {
        commOffset = (unsigned long) (&(p->comm)) - (unsigned long) (p);
        tasksOffset =
            (unsigned long) (&(p->tasks)) - (unsigned long) (p);
        mmOffset = (unsigned long) (&(p->mm)) - (unsigned long) (p);
        pidOffset = (unsigned long) (&(p->pid)) - (unsigned long) (p);
        pgdOffset =
            (unsigned long) (&(p->mm->pgd)) - (unsigned long) (p->mm);
        addrOffset =
            (unsigned long) (&(p->mm->start_code)) -
            (unsigned long) (p->mm);

        printk(KERN_INFO "ICE: generated libvmi config...");
        printk(KERN_INFO "[domain name] {\n");
        printk(KERN_INFO "    ostype = \"Linux\";\n");
        printk(KERN_INFO "    sysmap = \"[insert path here]\";\n");
        printk(KERN_INFO "    linux_name = 0x%x;\n",
               (unsigned int) commOffset);
        printk(KERN_INFO "    linux_tasks = 0x%x;\n",
               (unsigned int) tasksOffset);
        printk(KERN_INFO "    linux_mm = 0x%x;\n",
               (unsigned int) mmOffset);
        printk(KERN_INFO "    linux_pid = 0x%x;\n",
               (unsigned int) pidOffset);
        printk(KERN_INFO "    linux_pgd = 0x%x;\n",
               (unsigned int) pgdOffset);
        printk(KERN_INFO "}\n");
    } else {
        printk(KERN_INFO
               "ICE: found no process to populate task_struct.\n");
    }

    return 0;

    return 0;
}

static void __exit find_ranges_exit(void) {
    printk(KERN_INFO "ICE: kernel module unloaded\n");
}

module_init(find_ranges_init);
module_exit(find_ranges_exit);
