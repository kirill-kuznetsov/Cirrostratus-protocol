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
	{ 0xe0789338, "blk_init_queue" },
	{ 0x370ece2a, "bus_register" },
	{ 0x3d31d0ee, "kmem_cache_destroy" },
	{ 0x51815275, "device_remove_file" },
	{ 0xb281b25f, "per_cpu__current_task" },
	{ 0x28849590, "kmalloc_caches" },
	{ 0xdf3c19ec, "cn_add_callback" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xf9a482f9, "msleep" },
	{ 0xd2a941d4, "sg_init_table" },
	{ 0xc12a0469, "alloc_disk" },
	{ 0x8dbf4e8a, "blk_cleanup_queue" },
	{ 0x9464d1d2, "bio_alloc_bioset" },
	{ 0x8955b6ab, "kernel_sendmsg" },
	{ 0x6980fe91, "param_get_int" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x71356fba, "remove_wait_queue" },
	{ 0xee0fcf9, "sock_release" },
	{ 0x4661e311, "__tracepoint_kmalloc" },
	{ 0xff708fd3, "mempool_destroy" },
	{ 0xee421be0, "init_timer_key" },
	{ 0x381c4bb1, "cancel_delayed_work_sync" },
	{ 0x8fcbb584, "mutex_unlock" },
	{ 0xff964b25, "param_set_int" },
	{ 0x712aa29b, "_spin_lock_irqsave" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0xd37caff6, "__alloc_pages_nodemask" },
	{ 0x7d11c268, "jiffies" },
	{ 0xff5a8cfe, "cn_del_callback" },
	{ 0xfbe27a1c, "rb_first" },
	{ 0xffc7c184, "__init_waitqueue_head" },
	{ 0x183fa88b, "mempool_alloc_slab" },
	{ 0xa28a38c3, "blk_queue_max_phys_segments" },
	{ 0xa9cd2065, "crypto_alloc_ablkcipher" },
	{ 0xc2ae26d2, "bio_free" },
	{ 0xe7489074, "device_register" },
	{ 0xcf40a52a, "__mutex_init" },
	{ 0xb72397d5, "printk" },
	{ 0x7eef101, "kthread_stop" },
	{ 0xdfaae2da, "del_gendisk" },
	{ 0xd6f401d2, "bio_add_page" },
	{ 0x1775cec7, "kunmap" },
	{ 0xc0580937, "rb_erase" },
	{ 0x9f344210, "blk_queue_max_hw_segments" },
	{ 0xc24b2ca4, "mutex_lock" },
	{ 0x71a50dbc, "register_blkdev" },
	{ 0x4b07e779, "_spin_unlock_irqrestore" },
	{ 0xc6ddc509, "generic_make_request" },
	{ 0x8a99a016, "mempool_free_slab" },
	{ 0xdacc4109, "bus_unregister" },
	{ 0xfd67b5ae, "contig_page_data" },
	{ 0x8507ede3, "bio_endio" },
	{ 0xb8ac3b0e, "bio_put" },
	{ 0xb10d55bc, "cn_netlink_send" },
	{ 0xb29bc8bd, "idr_remove" },
	{ 0xe49c0959, "device_create_file" },
	{ 0xb5a459dc, "unregister_blkdev" },
	{ 0xd996d859, "idr_pre_get" },
	{ 0x30b71f99, "open_by_devnum" },
	{ 0x142c23f8, "kmem_cache_alloc" },
	{ 0x56ae3e61, "__free_pages" },
	{ 0x473da1fa, "blkdev_put" },
	{ 0x6466a1e6, "mempool_alloc" },
	{ 0xdfef653d, "kernel_sendpage" },
	{ 0x8cb89943, "path_lookup" },
	{ 0x8e4a0f04, "kmap" },
	{ 0xcbdc8530, "sync_blockdev" },
	{ 0xcd6fa15a, "blk_queue_make_request" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x91009452, "schedule_delayed_work" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x108e8985, "param_get_uint" },
	{ 0x4292364c, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0x60bbe20b, "put_disk" },
	{ 0xf8b30e93, "mempool_create" },
	{ 0xdb0b9cff, "bioset_create" },
	{ 0xa44ad274, "wait_for_completion_interruptible_timeout" },
	{ 0x498a5e3d, "crypto_destroy_tfm" },
	{ 0x26cd9b20, "wake_up_process" },
	{ 0x49d48e9, "path_put" },
	{ 0xa56f1315, "mempool_free" },
	{ 0xa6dcc773, "rb_insert_color" },
	{ 0xc17d27e4, "kmem_cache_create" },
	{ 0x61637199, "kernel_recvmsg" },
	{ 0x642e54ac, "__wake_up" },
	{ 0xd2965f6f, "kthread_should_stop" },
	{ 0x650fb346, "add_wait_queue" },
	{ 0x37a0cba, "kfree" },
	{ 0xd21d7ffe, "kthread_create" },
	{ 0x801678, "flush_scheduled_work" },
	{ 0x33d92f9a, "prepare_to_wait" },
	{ 0x3285cc48, "param_set_uint" },
	{ 0x8392c535, "add_disk" },
	{ 0xf7097dd5, "sock_create" },
	{ 0x413a38d9, "kernel_bind" },
	{ 0x9ccb2622, "finish_wait" },
	{ 0xbdf5c25c, "rb_next" },
	{ 0x1bf6215a, "device_unregister" },
	{ 0xe456bd3a, "complete" },
	{ 0x701d0ebd, "snprintf" },
	{ 0x5c57c2a6, "dev_set_name" },
	{ 0xd471bba0, "crypto_alloc_base" },
	{ 0x8416e09a, "bioset_free" },
	{ 0xb9b03cee, "bdget_disk" },
	{ 0x120507ac, "idr_get_new" },
	{ 0x2af51259, "bdput" },
	{ 0x77998ed5, "set_disk_ro" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A1A6B53E957A2BAC4AB036C");