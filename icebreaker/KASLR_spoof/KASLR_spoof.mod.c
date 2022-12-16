#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xf704969, "module_layout" },
	{ 0xc512626a, "__supported_pte_mask" },
	{ 0xd38cd261, "__default_kernel_pte_mask" },
	{ 0x8a35b432, "sme_me_mask" },
	{ 0x4c9d28b0, "phys_base" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0x1d19f77b, "physical_mask" },
	{ 0x4c55f5ef, "pv_ops" },
	{ 0xdad13544, "ptrs_per_p4d" },
	{ 0xa92ec74, "boot_cpu_data" },
	{ 0xa648e561, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x72d79d83, "pgdir_shift" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x92997ed8, "_printk" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "29D0B4303B117914AD7680F");
