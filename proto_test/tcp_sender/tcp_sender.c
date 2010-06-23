#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

MODULE_LICENSE("Dual BSD/GPL");

void tcp_send(int block_size, void *buffer, struct socket *sock){
	struct msghdr msg;
	struct kvec iov;
	int err, i, iter = 1000; 

	for(i = 0; i < iter;){
		iov.iov_base = buffer;
		iov.iov_len =  block_size;

		msg.msg_iov = (struct iovec *)&iov;
		msg.msg_iovlen = 1;
		msg.msg_name = NULL;    
		msg.msg_namelen = 0;     
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = MSG_WAITALL;
		err = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
		if(err > 0){
			 i++;
//			printk(KERN_INFO "%d %d", err,i);
		}
	}	
}

static int client_init(void)
{
	int err, step = 512, block_size, inc = 2;
	struct sockaddr_in addr;
	struct socket *sock;
	struct net_device *ifp;
	int ifindex = 2;
		
	unsigned char dest_ip[4] = {0xc0, 0xa8, 0x38, 0x65};
	void* buffer; 
	
	memset(&addr, 0, sizeof(struct sockaddr_in));

	memcpy( &(addr.sin_addr.s_addr), (void *)dest_ip, 4);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(666);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	 /* find device by index */
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, ifp) {
		if (ifp->ifindex == ifindex){
			ifp->mtu = 1500;
	    		break;
		}
	}
	read_unlock(&dev_base_lock);


	err = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if(err)
	        printk(KERN_INFO "create err");
	
	err = kernel_connect(sock, (struct sockaddr *)&addr,sizeof(struct sockaddr_in), 0);
	if(err)
		printk(KERN_INFO "connect err %d ", err);
	if(err)
		return 0;
	buffer = kmalloc( 1024*1024, GFP_KERNEL);
	
	tcp_send(2048, buffer, sock);/* for test
	for(; ifp->mtu <= 9000; ifp->mtu += 500 )
	{
		block_size = 512;
		while( block_size <= 1024*1024)
		{	
		
//			printk("mtu:%d size: %d\n", ifp->mtu, block_size);
			tcp_send(block_size, buffer, sock);
//			if(block_size == 4*1024){
//				inc *= 2;
//			}
			block_size *= inc;
//			if(block_size >= step * 8)
//				step *= 8;
//			block_size += step;
		
		}
	
	}*/
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
