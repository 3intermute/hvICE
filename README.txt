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

featured on tmp.0ut vol3: https://tmpout.sh/3/

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

internals:
libvmi exposes a simple but powerful API, first hvICE initializes libvmi and pauses the guest vm:

``
        if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*) domain_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, &mode)) {
            goto error_exit;
        }
        if (VMI_FAILURE == vmi_init_complete(&vmi, (void*) domain_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
            goto error_exit;
        }

        page_mode_t page_mode = vmi_init_paging(vmi, 0);

        if (VMI_FAILURE ==  vmi_pause_vm(vmi)) {
            goto error_exit;
        }

``

the libvmi function vmi_translate_ksym2v ** finds the guest virtual address of a kernel symbol and,
the libvmi function vmi_translate_kv2p translates a guest virtual address to a guest physical address,
hvICE can use these functions to find:
    - the start and end addresses of kernel text (via the _text and _etext symbols)
    - the start and end addresses of kernel rodata (via the __start_rodata and __end_rodata symbols).

``
        addr_t kernel_text_start_GVA;
        addr_t kernel_text_end_GVA;
        addr_t kernel_text_start_GPA;
        addr_t kernel_text_end_GPA;

        vmi_translate_ksym2v(vmi, "_text", &kernel_text_start_GVA);
        vmi_translate_kv2p(vmi, kernel_text_start_GVA, &kernel_text_start_GPA);

        vmi_translate_ksym2v(vmi, "_etext", &kernel_text_end_GVA);
        vmi_translate_kv2p(vmi, kernel_text_end_GVA, &kernel_text_end_GPA);

        addr_t kernel_rodata_start_GVA;
        addr_t kernel_rodata_end_GVA;
        addr_t kernel_rodata_start_GPA;
        addr_t kernel_rodata_end_GPA;

        vmi_translate_ksym2v(vmi, "__start_rodata", &kernel_rodata_start_GVA);
        vmi_translate_kv2p(vmi, kernel_text_start_GVA, &kernel_rodata_start_GPA);

        vmi_translate_ksym2v(vmi, "__end_rodata", &kernel_rodata_end_GVA);
        vmi_translate_kv2p(vmi, kernel_text_end_GVA, &kernel_rodata_end_GPA);
``

** it is possible to spoof vmi_translate_ksym2v, see icebreaker

hvICE then initializes a singlestep event and mem event:
if a protected page is written to, an EPT violation occurs and libvmi calls the mem_cb callback.
to handle kernel self patching, mem_cb checks if the write came from within kernel text,
and if it did, it relaxes the permissions on the protected page
then toggles singlestep on, calling the singlestep_cb callback which allows the instruction that caused the violation to execute,
then resets the permissions on the protected page to prevent writes once more and toggles single step off:

``
        SETUP_SINGLESTEP_EVENT(&singlestep_event, VMI_BIT_MASK(0, vmi_get_num_vcpus(vmi) - 1), singlestep_cb, false);
        if (VMI_FAILURE == vmi_register_event(vmi, &singlestep_event)) {
            goto error_exit;
        }

        mem_event.data = (void *) &singlestep_event;
        SETUP_MEM_EVENT(&mem_event, ~0ULL, VMI_MEMACCESS_W, mem_cb, true);
        if (VMI_FAILURE == vmi_register_event(vmi, &mem_event)) {
            return 1;
        }
``
...
``
        event_response_t mem_cb(vmi_instance_t vmi, vmi_event_t *event) {
            if (event->x86_regs->rip > kernel_text_start_GVA & event->x86_regs->rip < kernel_text_end_GVA) {
                if (vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0) == VMI_FAILURE) {
                }
                vmi_event_t *singlestep_event_ptr = (vmi_event_t *) event->data;
                singlestep_event_ptr->data = GSIZE_TO_POINTER(event->mem_event.gfn);

                return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
            }
            else {
                vmi_pause_vm(vmi);
            }

            return VMI_EVENT_RESPONSE_NONE;
        }
``
...
``
        event_response_t singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {
            addr_t gfn = GPOINTER_TO_SIZE(event->data);
            if (vmi_set_mem_event(vmi, gfn, VMI_MEMACCESS_W, 0) == VMI_FAILURE) {
            }

            return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
        }
``

libvmi then registers memory events on the range of pages from _text to _etext and __start_rodata to __end_rodata:
as kernel text is contiguous in guest physical memory, it is possible to find the gfns needed by-
simply iterating through every gfn between the start and end gfn:


``
        if (register_mem_event_range(vmi, kernel_text_start_GVA, kernel_text_end_GVA, VMI_MEMACCESS_W, mem_cb)
            != 0) {
            goto error_exit;
        }

        if (register_mem_event_range(vmi, kernel_rodata_start_GVA, kernel_rodata_end_GVA, VMI_MEMACCESS_W, mem_cb)
            != 0) {
            goto error_exit;
        }
``
...
``
        int register_mem_event_range(vmi_instance_t vmi, addr_t GVA_start, addr_t GVA_end, vmi_mem_access_t access_type, void *cb) {
                GVA_start = (GVA_start >> PAGE_SHIFT) << PAGE_SHIFT;
                GVA_end = (GVA_end >> PAGE_SHIFT) << PAGE_SHIFT;

                addr_t GPA_start;
                addr_t GPA_end;
                vmi_translate_kv2p(vmi, GVA_start, &GPA_start);
                vmi_translate_kv2p(vmi, GVA_end, &GPA_end);

                uint64_t gfn_start = GPA_start >> PAGE_SHIFT;
                uint64_t gfn_end = GPA_end >> PAGE_SHIFT;

                uint64_t n_frames = (GVA_end - GVA_start) / PAGESIZE;

                for (uint64_t i = gfn_start; i < gfn_end; i++) {
                    if (VMI_FAILURE == vmi_set_mem_event(vmi, i, access_type, 0)) {
                        return 1;
                    }
                }

                return 0;
        }
``

hvICE then resumes the vm and waits for a violation:
``
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        goto error_exit;
    }

    while (!interrupted) {
        vmi_events_listen(vmi,500);
    }
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
    - icebreaker: libvmi brute-forces KASLR offset or uses init_task to calculate it (DONE)
    - protect rodata (DONE)
    - protect important structures via sub-page write protection


compilation:
    gcc ICE.c -o ICE -lvmi -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -g

usage:
    sudo ./ICE <domain name>
