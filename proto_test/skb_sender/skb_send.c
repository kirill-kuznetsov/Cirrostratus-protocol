#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/hdreg.h>
#include <linux/blkdev.h>
#include <linux/netdevice.h>
#include <linux/genhd.h>
#include <linux/moduleparam.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <net/net_namespace.h>
#include <asm/unaligned.h>
#include <linux/uio.h>
#include <linux/jiffies.h>

MODULE_LICENSE("Dual BSD/GPL");

static spinlock_t txlock;
static struct sk_buff_head skbtxq;
static wait_queue_head_t txwq;
static struct net_device *ifp;

unsigned char g_msg[] = "HELLO WORLD!";


static struct sk_buff *new_skb(int pkt_size, struct net_device *ifp)
{	
	struct sk_buff *skb;
//	char *dest_addr = "0800270e6c6c"; //test
	unsigned char *data = NULL;
	unsigned char mac[6] = {0x08, 0x00, 0x27, 0xb7, 0x1e, 0xa0};
	
	
	/*create new skb
	*/
	skb = dev_alloc_skb ( pkt_size );
	if (skb) {
		skb->protocol = __constant_htons(ETH_P_ALL);
		skb->priority = 0;
		skb->next = skb->prev = NULL;
		skb->dev = ifp;
		skb->ip_summed = CHECKSUM_NONE;
		skb_set_network_header(skb,0);
		
		//filling data
		data = skb_put ( skb, pkt_size);
		memcpy (data, g_msg, sizeof( g_msg ));	

		// filling ethhdr
		struct ethhdr *eth = (struct ethhdr *)skb_push(skb,sizeof(*eth));
		eth->h_proto = htons(ETH_P_ALL);
		
		memcpy (eth->h_dest, mac, ETH_ALEN);
		memcpy (eth->h_source, skb->dev->dev_addr, ETH_ALEN);
	}
	return skb;
}

/*
send skb
*/
static void tx(void)
{
	struct sk_buff *skb;
	spin_lock_irq(&txlock);
	int i = 0;
	while ((skb = skb_dequeue(&skbtxq))) {	
		spin_unlock_irq(&txlock);
		if (dev_queue_xmit(skb) == NET_XMIT_DROP && net_ratelimit())
			printk(KERN_INFO
				"packet could not be sent on %s.  %s\n",
				skb->dev ? skb->dev->name : "netif",
				"consider increasing tx_queue_len");
		else {
//			printk(KERN_INFO "package send sucessful");
			i++;
		}
		spin_lock_irq(&txlock);
	}
	printk(KERN_INFO "packets send %d", i);
	spin_unlock_irq(&txlock);
}

/*
put in queue
*/
static void test_xmit(struct sk_buff *sl)
{
	struct sk_buff *skb;
	ulong flags;

	while ((skb = sl)) {
		sl = sl->next;
		skb->next = skb->prev = NULL;
		spin_lock_irqsave(&txlock, flags);
		skb_queue_tail(&skbtxq, skb);
		spin_unlock_irqrestore(&txlock, flags);
		wake_up(&txwq);
	}
}

/*
initialize
*/
int __init test_init(void)
{	
	skb_queue_head_init(&skbtxq);
	init_waitqueue_head(&txwq);
	spin_lock_init(&txlock);
	return 0;
}


/*
intialize module
*/
static int hello_init(void)
{
	int ret, i, j, iter = 100000, buf_max = 20000; //на 10000 пакетов отправка шла только дл€ первых 20000+ ( оограничение очереди скб?) 
																			//поэтому в очередь отправки добавл€етс€ по 20к пакетов, затем они передаютс€, добавл€ютс€ след 20к и тд
	unsigned long begin = 0;
	printk(KERN_INFO "Hello, world\n");

	ret = test_init();               // initialize

	//find netdevice
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, ifp) {
		if (!strcmp(ifp->name, "eth0")){
			printk(KERN_INFO "device name: %s %d", ifp->name, ifp->ifindex);
			break;
		}
	}
	read_unlock(&dev_base_lock);
	
	// create new skb and put it in queue
	if(iter < buf_max)
		buf_max = iter;
	for(i = 0, j = 0, begin = jiffies; i <  iter; )
	{	
		for( j = 0; j < buf_max; j++, i++)
			test_xmit(new_skb(ifp-> mtu, ifp));
		tx(); 
	}                          
	
//	tx(); 
	printk(KERN_INFO "time: %ld", jiffies - begin);

	return 0;
}

static void hello_exit(void)
{
	printk(KERN_INFO "Goodbye, cruel world\n");
}

module_init(hello_init);
module_exit(hello_exit);