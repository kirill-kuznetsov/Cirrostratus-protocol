#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <asm/param.h>

MODULE_LICENSE("Dual BSD/GPL");

unsigned inline int dst_state_poll(struct socket *sock)
{
	unsigned int revents = POLLHUP | POLLERR;
	revents = sock->ops->poll(NULL, sock, NULL);
	return revents;
}

int inline await(struct socket *sock){
	unsigned int revents = 0;
	unsigned int err_mask = POLLERR | POLLHUP | POLLRDHUP;
	unsigned int mask = err_mask | POLLIN;
	revents = dst_state_poll(sock);
	if (!(revents & mask)) {
		for (;;){			
			revents = dst_state_poll(sock);
			if (revents & mask){
				break;
			}	
		}
	}
	return revents;
}

int inline eth_recv_packet(void *buffer, int size, struct socket *sock )
{	
	unsigned int revents = 0;
	struct msghdr msg;
	struct kvec iov;
	int err = 0;
	iov.iov_base = buffer;
	iov.iov_len = size;
	msg.msg_iov = (struct iovec*)&iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = MSG_DONTWAIT;   /* non-blocking */
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	
	do{
		revents = await(sock);//wait for incoming packet
		if(revents & POLLIN){
			err = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
		}
	} while ( err < 0);
//	printk(KERN_INFO "mark %d ", *(unsigned char *)(buffer + 14));
	return err;	
}

void recv_all(void *buffer, int block_size, int mtu, struct socket *sock)
{
	int i,  iter = 1000, err, packets;
	unsigned long begin, result;
	
	packets = iter*block_size/mtu + 1;
	printk(KERN_INFO "packets packets %d", packets);
	
	for(i = 0; i < packets; i++)
	{
		eth_recv_packet(buffer, mtu, sock);
		if(i == 0)			
			begin = jiffies;
//		printk(KERN_INFO "jiffies  %lu", jiffies - begin);
//		printk(KERN_INFO "iteration: %d, num: %u", i, *(unsigned int*)(buffer+14));
	}
	result = jiffies-begin;
	printk(KERN_INFO "time %lu\n",(result))	; //receiving time
}

static int test_init(void)
{

        void *buffer;
	int mtu,err,ifindex = 0, block_size, inc = 2, max_block_size = 1024*1024;
	struct sockaddr_ll addr;
	struct socket *sock;
	struct net_device *ifp;
	unsigned char src_mac[6] = {0x08, 0x00, 0x27, 0xb7, 0x1e, 0xa0};
	
	 /* find device by index */
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, ifp) {
		if (!strcmp(ifp->name,"eth0")){
			ifindex = ifp->ifindex;
	    		break;
		}
	}
	read_unlock(&dev_base_lock);
	
	err = sock_create(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL), &sock);
	if(err < 0)
	        printk(KERN_INFO "sock_create error");

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifindex;
	addr.sll_hatype = ARPHRD_ETHER;
	addr.sll_pkttype = PACKET_OTHERHOST;
	addr.sll_halen = ETH_ALEN;
	
	/*MAC*/
	memcpy(addr.sll_addr, src_mac, ETH_ALEN);
	addr.sll_addr[6]  = 0x00;/*not used*/
	addr.sll_addr[7]  = 0x00;/*not used*/
	
	err = kernel_bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
	if( err	< 0)
	        printk(KERN_INFO "kernel_bind error");
	        
        buffer = kmalloc(9000 + ETH_HLEN, GFP_KERNEL);
        if(err){
        	printk(KERN_INFO "%d" ,err);
        }else{  
        	recv_all(buffer, 2048, 1500, sock);//test
 	} 
        kfree(buffer);
        sock_release(sock);
        printk(KERN_INFO "buff freed");

        return 0;
}





static void test_exit(void)
{
	printk(KERN_INFO "Goodbye, cruel world\n");
}

module_init(test_init);
module_exit(test_exit);
