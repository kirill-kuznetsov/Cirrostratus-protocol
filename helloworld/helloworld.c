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
//#include <linux/etherdevice.h>

MODULE_LICENSE("Dual BSD/GPL");

#define SNULL_RX_INTR 0x0001
#define SNULL_TX_INTR 0x0002

static spinlock_t txlock;
static struct sk_buff_head skbtxq;
static wait_queue_head_t txwq;

unsigned char g_msg[] = "HELLO WORLD!";

static int digit2int(char d)
{
if (d <= 'F' && d >= 'A') {
return d - 'A' + 10;
}
if (d <= 'f' && d >= 'a') {
return d - 'a' + 10;
}
if (d <= '9' && d >= '0') {
return d - '0';
}        
return -1;
}

static unsigned char* hex2int(char *s, unsigned char* mac)
{
        int res;
        int tmp;
        int i, j;
     
        if (strlen(s) != ETH_ALEN * 2) {
return NULL;
}

for (i = 0, j = 0; i < ETH_ALEN * 2; i++, j++) {               
            tmp = digit2int(s[i]);
            if (tmp < 0) {
return NULL;
}            
res = digit2int(s[++i]);
if (res < 0) {
return NULL;
}

tmp = tmp * 16 + res;
printk(KERN_INFO "tmp: %d", tmp);
mac[j] = (unsigned char)tmp;
}
return mac;
}

static struct sk_buff *
new_skb(ulong len)
{    
    int result;
    int i;
    struct sk_buff *skb;
    struct net_device *ifp;
    char *src_addr = "0800279d88a6"; //test
    char *dest_addr = "0800270e6c6c"; //test
    unsigned char *data = NULL;
    unsigned char mac[6];
    read_lock(&dev_base_lock);
    for_each_netdev(&init_net, ifp) {
        if (strncmp(ifp->name, "eth0", 4) == 0) {
            printk(KERN_INFO "device name: %s", ifp->name);
            break;
        }
    }
    read_unlock(&dev_base_lock);

    printk(KERN_INFO "device name: %s", ifp->name);
    
    /*create new skb
    */
    //skb = alloc_skb(len, GFP_ATOMIC);
    skb = dev_alloc_skb(sizeof(g_msg));
    if (skb) {
        //skb_reset_network_header(skb);
        //skb_reset_mac_header(skb);
        skb->protocol = __constant_htons(ETH_P_802_3);
        skb->priority = 0;
        skb->next = skb->prev = NULL;
        //skb_set_mac_header(skb, 14);
        skb->dev = ifp;
        //skb->mac_len = 14;
        //skb->data = "";
        data = skb_put(skb, sizeof(g_msg));
        memcpy(data, g_msg, sizeof(g_msg));
        /* tell the network layer not to perform IP checksums
         * or to get the NIC to do it
         */
        
        skb->ip_summed = CHECKSUM_NONE;
        skb_set_network_header(skb, 0);
        struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);
        eth->h_proto = htons(ETH_P_802_3);
        /*hex2int(src_addr, &mac[0]);
        for(i=0;i<6;i++){
            printk(KERN_INFO "mac %d", mac[i]);
        }
        memcpy(eth->h_source, mac, ifp->addr_len);

        hex2int(dest_addr, &mac[0]);
        for(i=0;i<6;i++){
            printk(KERN_INFO "mac %d", mac[i]);
        }
        memcpy(eth->h_dest, mac, ifp->addr_len);
        
        for(i=0;i<6;i++){
            printk(KERN_INFO "h_source %d", eth->h_source[i]);
        }
        for(i=0;i<6;i++){
            printk(KERN_INFO "h_dest %d", eth->h_dest[i]);
        }*/
        memset(eth->h_dest, 0xFF, ETH_ALEN);
        memcpy(eth->h_source, skb->dev->dev_addr, ETH_ALEN);
        //eth->h_dest[ETH_ALEN-1] ^= 0x01;    
    }
    return skb;
}

/*
send skb
*/

static void
tx(void)
{
    struct sk_buff *skb;

    __set_current_state(TASK_UNINTERRUPTIBLE);
    spin_lock_irq(&txlock);

    while ((skb = skb_dequeue(&skbtxq))) {    
        spin_unlock_irq(&txlock);
        if (dev_queue_xmit(skb) == NET_XMIT_DROP && net_ratelimit()) {
            printk(KERN_INFO
                "packet could not be sent on %s.  %s\n",
                skb->dev ? skb->dev->name : "netif",
                "consider increasing tx_queue_len");
} else {
printk(KERN_INFO "package send sucessful");
}
        spin_lock_irq(&txlock);
    }

    spin_unlock_irq(&txlock);
    __set_current_state(TASK_INTERRUPTIBLE);
}


/*
put in queue
*/
void
test_xmit(struct sk_buff *sl)
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
int __init
test_init(void)
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
    int ret;
    printk(KERN_INFO "Hello, world\n");

    ret = test_init();               // initialize

    test_xmit(new_skb(ETH_ZLEN));      // create new skb and put it in                            // queue
    tx();                            // send skb  

    return 0;
}

static void hello_exit(void)
{
    printk(KERN_INFO "Goodbye, cruel world\n");
}

module_init(hello_init);
module_exit(hello_exit);
