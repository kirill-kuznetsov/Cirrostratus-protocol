#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

MODULE_LICENSE("Dual BSD/GPL");

char message[] = "Hello there!\n";
char msgbuf[1024];

static int test_init(void)
{
	int s, listener, lis;
	int err;
	int bytes_read;
	struct sockaddr_ll addr;
	struct socket *sock;
	struct socket *newsocket = NULL;
	struct kiocb *iocb = NULL;
	void* buffer = kmalloc(ETH_ZLEN, GFP_KERNEL);

	// for kernel_recv and kernel_send
	struct msghdr msg;
	struct kvec iov;
	
	printk(KERN_INFO "Hello, world\n");

	iov.iov_base = buffer;
	iov.iov_len = ETH_ZLEN;	

	msg.msg_iov = (struct iovec *)&iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_DONTWAIT;	


	listener = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);
	if(listener < 0)
	        printk(KERN_INFO "sock_create error");

	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
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
	
	if(kernel_bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	        printk(KERN_INFO "kernel_bind error");
	
	while(1){
		bytes_read = kernel_recvmsg(sock, &msg, &iov, 					1, iov.iov_len, msg.msg_flags);
		if(bytes_read >= 0) {
				printk(KERN_INFO "packet recived");
				break;
			}
	}

	return 0;
}

static void test_exit(void)
{
	printk(KERN_INFO "Goodbye, cruel world\n");
}

module_init(test_init);
module_exit(test_exit);
