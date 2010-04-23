##include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

MODULE_LICENSE("Dual BSD/GPL");

char hello[] = "Goodbuy, cruel world!";

static int client_init(void)
{
	int sender, err;
	struct sockaddr_ll addr;
	struct socket *sock;
	struct msghdr msg;
	struct kvec iov;
	
	/*buffer for ethernet frame*/
	void* buffer = kmalloc(ETH_ZLEN, GFP_KERNEL);
	/*pointer to ethenet header*/
	unsigned char* etherhead = buffer;
	/*userdata in ethernet frame*/
	unsigned char* data = buffer + 14;
	/*another pointer to ethernet header*/
	struct ethhdr *eh = (struct ethhdr *)etherhead;	
	
	/*our MAC address*/
	unsigned char src_mac[6] = {0x08, 0x00, 0x27, 0x9d, 0x88, 0xa6};
	/*other host MAC address*/
	unsigned char dest_mac[6] = {0x08, 0x00, 0x27, 0x0e, 0x6c, 0x6c};	
	
	/*set the frame header*/
	memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
	eh->h_proto = htons(ETH_P_802_3);
	
	memcpy(data, hello,sizeof(hello));

	/*create socket*/
	sender = sock_create(AF_PACKET, SOCK_RAW, htons(ETH_P_802_3), &sock);
	if(sender < 0)
	        return sender;
	else
		printk(KERN_INFO "socket created");
	
	/*fill sockaddr_ll*/
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_802_3);
	addr.sll_ifindex = 2;
	addr.sll_hatype = ARPHRD_ETHER;
	addr.sll_pkttype = PACKET_OTHERHOST;
	addr.sll_halen = ETH_ALEN;
	
	/*MAC - begin*/
	addr.sll_addr[0]  = 0x08;		
	addr.sll_addr[1]  = 0x00;		
	addr.sll_addr[2]  = 0x27;
	addr.sll_addr[3]  = 0x0e;
	addr.sll_addr[4]  = 0x6c;
	addr.sll_addr[5]  = 0x6c;
	/*MAC - end*/
	addr.sll_addr[6]  = 0x00;/*not used*/
	addr.sll_addr[7]  = 0x00;/*not used*/
	
	/*fill iov*/
	iov.iov_base = buffer;
	iov.iov_len = ETH_ZLEN;

	/*fill msg*/
	memset(&msg, 0x00, sizeof(msg));
	msg.msg_iov = (struct iovec *)&iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;    //(struct sockaddr*)&addr;
	msg.msg_namelen = 0;     //sizeof(addr);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0 | MSG_DONTWAIT | MSG_NOSIGNAL;
	
	if(kernel_bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	        return -1;	

	err = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	if(err == -EPIPE) {
	            printk("broken pipe\n");
	} else {
	            printk("send %d bytes\n", err);
        }

	return 0;
}

static void client_exit(void)
{
	printk(KERN_INFO "Goodbye, cruel world\n");
}

module_init(client_init);
module_exit(client_exit);
