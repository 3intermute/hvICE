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

                HVCIce
                intrusion countermeasure electronics v0.4

HVCIce is a proof of concept implementation of hypervisor enforced code integrity for the linux kernel using xen and libvmi.
it requires no modification to the guest OS.
HVCIce achieves this via setting an event listening for writes on all pages between _text and _etext, as well as all of kernel rodata,
then pausing the VM and logging the violation if an attempted write did not come from within kernel text.


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


todo:
    - icebreaker: libvmi brute-forces KASLR offset or uses init_task to calculate it, very easy to spoof
    - protect rodata (DONE)
    - protect important structures via sub-page write protection


compilation:
    gcc ICE.c -o ICE -lvmi -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -g

usage:
    sudo ./ICE <domain name>
