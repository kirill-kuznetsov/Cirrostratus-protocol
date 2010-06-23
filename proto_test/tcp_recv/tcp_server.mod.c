#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xec5ba0f9, "module_layout" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xee0fcf9, "sock_release" },
	{ 0x37a0cba, "kfree" },
	{ 0x4661e311, "__tracepoint_kmalloc" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0xd1d548fb, "init_net" },
	{ 0x1a75caa3, "_read_lock" },
	{ 0xd1f91bcd, "dev_base_lock" },
	{ 0x777c8517, "kernel_accept" },
	{ 0x101c6ff, "kernel_listen" },
	{ 0x413a38d9, "kernel_bind" },
	{ 0xf7097dd5, "sock_create" },
	{ 0x7d11c268, "jiffies" },
	{ 0x61637199, "kernel_recvmsg" },
	{ 0xb72397d5, "printk" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EAFF4828B5E77AB4512D54E");
