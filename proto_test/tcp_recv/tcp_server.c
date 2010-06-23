#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <asm/msr.h>
#include <linux/jiffies.h>
#include <asm/param.h>

MODULE_LICENSE("Dual BSD/GPL");

void tcp_receive(int block_size, void *buffer, struct socket *sock){
	struct msghdr msg;
	struct kvec iov;
	int err, i = 0, iter = 1000, kilo = 1024;
	unsigned long begin = 0, end, result;	
	
	while(i < iter){
		iov.iov_base = buffer;
		iov.iov_len = block_size;	

		msg.msg_iov = (struct iovec *)&iov;
		msg.msg_iovlen = 1;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = MSG_WAITALL;	
			
		err = kernel_recvmsg( sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
		if(i==0)
			begin = jiffies;
		if(err >= 0) {
			i++;
//			printk(KERN_INFO "%d %d", bytes_read, i);	
		}	
//		printk(KERN_INFO "jiffies  %lu", jiffies - begin);
	}
	end = jiffies;
	result = (end - begin);
	printk(KERN_INFO "result: %lu", result );	
//	printk(KERN_INFO "%ld", (block_size*iter)/(kilo));///(result*1024) 

}
static int test_init(void)
{
	int block_size = 512, inc = 2, mtu;
	int err;
	struct net_device *ifp;
	int ifindex = 3;

	struct sockaddr_in addr;
	struct socket *sock, *acpt_sock;
	void* buffer;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	unsigned char src_ip[4] = {0xc0, 0xa8, 0x38, 0x65};

	memcpy(&(addr.sin_addr.s_addr), &src_ip, 4);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(666);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);	

	err = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if(err < 0)
	        printk(KERN_INFO "sock_create error");	
	printk(KERN_INFO "create");
	
	if(kernel_bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)))
	        printk(KERN_INFO "kernel_bind error");
	printk(KERN_INFO "bind");
		
	err = kernel_listen(sock, 1024);
	if(err)
	        printk(KERN_INFO "kernel_listen error");
	printk(KERN_INFO "kernel_listen");
	err = kernel_accept(sock, &acpt_sock, 0);
	if(err)		
		printk(KERN_INFO "kernel_accept error");
	printk(KERN_INFO "accept");


	if(err)
		return -1;
	 /* find device by index */
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, ifp) {
		if (!strcmp(ifp->name,"eth0")){
			ifindex = ifp->ifindex;
	    		break;
		}
	}
	printk(KERN_INFO "index :%d", ifindex);
	read_unlock(&dev_base_lock);
	buffer = kmalloc(1024*1024, GFP_KERNEL);
	tcp_receive(2048, buffer, acpt_sock);
/*	for(ifp->mtu = 1500; ifp->mtu <= 9000; ifp->mtu += 500 )
	{	
		block_size = 512;
		while( block_size <= 1024*1024)
		{
			printk(KERN_INFO "Mtu: %d, block size: %d", ifp->mtu, block_size);
			tcp_receive(block_size, buffer, acpt_sock);
//			if(block_size == 4*1024)
//				inc *= 2;
			block_size *= inc;
		}	
	}*/
	kfree(buffer);		
	sock_release(acpt_sock);
	sock_release(sock);
	
	return 0;
}



static void test_exit(void)
{
	printk(KERN_INFO "Goodbye, cruel world\n");
}

module_init(test_init);
module_exit(test_exit);
