#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

MODULE_LICENSE("Dual BSD/GPL");

int inline dst_state_poll(struct socket *sock)
{
	unsigned int revents = POLLHUP | POLLERR;
	revents = sock->ops->poll(NULL, sock, NULL);
	return revents;
}

int inline send_packet(void *buffer, int size, struct socket *sock, struct sockaddr_ll *dest_addr )
{	
	struct msghdr msg;
	struct kvec iov;

	iov.iov_base = buffer;
	iov.iov_len = size;

	msg.msg_iov = (struct iovec*)&iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = MSG_DONTWAIT;   /* non-blocking */
	msg.msg_name = dest_addr;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	
	return kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);			
}

int send_all(void *buffer, int block_size, int mtu, struct socket *sock, struct sockaddr_ll *dest_addr)
{
	int i,err, iter = 1000, packets;
	unsigned long begin, result;
//	int *ptr = (int*)(buffer + 14);
	packets = block_size*iter/mtu + 1;
	
	
	for(i = 0; i < packets*2; ){// sending extra packets to cover packets loss
//		*ptr = i;
		err = send_packet(buffer, mtu, sock, dest_addr );
		if( i == 0)
			begin = jiffies;
		if(err>0)
			i++;
//		printk(KERN_INFO "err %d\n",(err));	
//		printk(KERN_INFO "jiffies  %lu, %d", jiffies - begin, *ptr);
	}
	result = jiffies-begin;
	printk(KERN_INFO "time %lu\n",(result))	; 	//productivity in kbps ((block_size*iter*HZ)/)
	return 0;
}


static int client_init(void)
{
	int err, mtu, block_size, max_block_size = 1024*1024, inc = 2;
	struct sockaddr_ll addr, dest_addr;
	struct socket *sock;
	struct net_device *ifp;
	int ifindex = 2;
	
	void* buffer;
	unsigned char* etherhead;
	unsigned char* data;
	struct ethhdr *eh;	
	
	/*our MAC address*/
	unsigned char src_mac[6] = {0x08, 0x00, 0x27, 0x91, 0x34, 0x51};
	/*other host MAC address*/
	unsigned char dest_mac[6] = {0x08, 0x00, 0x27, 0xb7, 0x1e, 0xa0};	
		
	 /* find device by index */
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, ifp) {
		if (ifp->ifindex == ifindex){
	    		break;
		}
	}
	read_unlock(&dev_base_lock);
	
	/*buffer for ethernet frame*/
	buffer = kmalloc( 9000 + ETH_HLEN, GFP_KERNEL);
	
	/*create socket*/
	err = sock_create(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL), &sock);
	if( err < 0){
		printk(KERN_INFO "socket create err %d", err);
	}
	
	/*fill src sockaddr_ll*/
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = 2;
	addr.sll_hatype = ARPHRD_ETHER;
	addr.sll_pkttype = PACKET_OTHERHOST;
	addr.sll_halen = ETH_ALEN;
	/*MAC*/
	memcpy(addr.sll_addr, src_mac, ETH_ALEN);
	addr.sll_addr[6]  = 0x00;/*not used*/
	addr.sll_addr[7]  = 0x00;/*not used*/
	
	/*fill dest sockaddr_ll*/
	dest_addr.sll_family = AF_PACKET;
	dest_addr.sll_protocol = htons(ETH_P_ALL);
	dest_addr.sll_ifindex = 2;
	dest_addr.sll_hatype = ARPHRD_ETHER;
	dest_addr.sll_pkttype = PACKET_OTHERHOST;
	dest_addr.sll_halen = ETH_ALEN;
	/*MAC*/
	memcpy(dest_addr.sll_addr, dest_mac, ETH_ALEN);
	dest_addr.sll_addr[6]  = 0x00;/*not used*/
	dest_addr.sll_addr[7]  = 0x00;/*not used*/	
	
	
	err = kernel_bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if( err < 0)
	        printk(KERN_INFO "socket bind err %d", err);	
	else {
		send_all ( buffer, 2048, ifp->mtu, sock, &dest_addr);//test
	}
	kfree(buffer);
	sock_release(sock);
		
	return 0;
}

static void client_exit(void)
{
	printk(KERN_INFO "Goodbye, cruel world\n");
}

module_init(client_init);
module_exit(client_exit);
