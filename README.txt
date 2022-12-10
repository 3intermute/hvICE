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
        ICE: pausing vm... done
        ICE: kernel text start @ GVA ffffffffa8400000
                           @ GPA 56800000
        ICE: kernel text end @ GVA ffffffffa9402520
                         @ GPA 57802520
        ICE: registering mem_event on GVA range (ffffffffa8400000 -> ffffffffa9402520)
        ICE: range aligned to page boundaries (ffffffffa8400000 -> ffffffffa9402000), 4098 frames
        ICE: registered mem_event on GVA range (ffffffffa8400000 -> ffffffffa9402000)
        ICE: VM resumed
        ICE: EPT write protection set on GVA range (ffffffffa8400000 -> ffffffffa9402520), waiting for violations...
        ICE; %RIP GVA ffffffffa91a0bf6 in kernel text, ignoring violation...
        ICE: !! EPT WRITE VIOLATION @ GFN 56800
        ICE:                        @ GPA 56800000
        ICE:                        @ %RIP GVA ffffffffc08be02a
        ICE: pausing vm...
``


todo:
    - icebreaker: trick libvmi by relocating kernel or modifying kernel symbol table
        - instead of using System.map, scan memory directly
    - protect rodata
    - protect important structures via sub-page write protection


compilation:
    gcc ICE.c -o ICE -lvmi -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -g

usage:
    sudo ./ICE <domain name>
