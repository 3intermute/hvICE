// paging mode compatability mode, libvmi brute forces https://github.com/libvmi/libvmi/blob/master/libvmi/os/linux/core.c
//  - spoof brute force

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/vmalloc.h>
#include <asm/io.h>

#include "include/resolve_kallsyms.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute#0440");
MODULE_DESCRIPTION("spoof libvmi KASLR offset");
MODULE_VERSION("0.1");

#define KERNEL_TEXT_START 0xffffffff81000000
#define SPOOFED_KASLR_OFFSET 0x00
#define SPOOFED_KERNEL_TEXT_START KERNEL_TEXT_START + SPOOFED_KASLR_OFFSET

struct mm_struct *init_mm_ptr;

// int (*__pte_alloc_)(struct mm_struct *mm, pmd_t *pmd);
//
// #define pte_alloc_map(mm, pmd, address)			\
// 	(__pte_alloc_(mm, pmd) ? NULL : pte_offset_map(pmd, address))

int (*__pmd_alloc_)(struct mm_struct *mm, pud_t *pud, unsigned long address);
int (*__pud_alloc_)(struct mm_struct *mm, p4d_t *p4d, unsigned long address);
int (*__p4d_alloc_)(struct mm_struct *mm, pgd_t *pgd, unsigned long address);

static inline p4d_t *p4d_alloc_(struct mm_struct *mm, pgd_t *pgd,
		unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __p4d_alloc_(mm, pgd, address)) ?
		NULL : p4d_offset(pgd, address);
}

static inline pud_t *pud_alloc_(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && __pud_alloc_(mm, p4d, address)) ?
		NULL : pud_offset(p4d, address);
}

static inline pmd_t *pmd_alloc_(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __pmd_alloc_(mm, pud, address)) ?
		NULL: pmd_offset(pud, address);
}

static int __init icebreaker_init(void)
{
    struct mm_struct *init_mm_ptr = kallsyms_lookup_name_("init_mm");
    // __pte_alloc_ = kallsyms_lookup_name_("__pte_alloc");
    __pmd_alloc_ = kallsyms_lookup_name_("__pmd_alloc");
    __pud_alloc_ = kallsyms_lookup_name_("__pud_alloc");
    __p4d_alloc_ = kallsyms_lookup_name_("__p4d_alloc");

    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(init_mm_ptr, SPOOFED_KERNEL_TEXT_START);

    printk("got here 0\n");

    p4d = p4d_alloc_(init_mm_ptr, pgd, SPOOFED_KERNEL_TEXT_START);
    if (!p4d) {
        printk(KERN_INFO "ICEBREAKER: failed to allocate p4d");
        return -ENOMEM;
    }

    pud = pud_alloc_(init_mm_ptr, p4d, SPOOFED_KERNEL_TEXT_START);
    if (!pud) {
        printk(KERN_INFO "ICEBREAKER: failed to allocate pud");
        return -ENOMEM;
    }

    pmd = pmd_alloc_(init_mm_ptr, pud, SPOOFED_KERNEL_TEXT_START);
    if (!pmd) {
        printk(KERN_INFO "ICEBREAKER: failed to allocate pmd");
        return -ENOMEM;
    }

    ptep = pte_offset_map(pmd, SPOOFED_KERNEL_TEXT_START);
    printk("ICEBREAKER: spoofed kernel text start ptep @ %llx\n", ptep);

    uint64_t dummy_page = vmalloc(PAGE_SIZE);

    pte_t new_pte = pfn_pte(virt_to_phys(dummy_page) >> PAGE_SHIFT, PAGE_KERNEL);
    set_pte(ptep, new_pte);

    // if (pte_alloc_map(init_mm_ptr, pmd, SPOOFED_KERNEL_TEXT_START)) {
    //     printk(KERN_INFO "ICEBREAKER: failed to allocate pte");
    //     return -ENOMEM;
    // }

    printk("ICEBREAKER: spoofed kernel KASLR offset to %llx, spoofed kernel text start @ %llx", SPOOFED_KASLR_OFFSET, SPOOFED_KERNEL_TEXT_START);

    return 0;
}

static void __exit icebreaker_exit(void)
{
    printk(KERN_INFO "ICEBREAKER: module unloaded\n");
}

module_init(icebreaker_init);
module_exit(icebreaker_exit);
