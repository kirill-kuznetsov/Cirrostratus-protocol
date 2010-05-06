/*
 * 2007+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/connector.h>
#include <linux/dst.h>
#include <linux/device.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/slab.h>

#include <net/sock.h>

//my diff
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

/*
 * Polling machinery.
 */

struct dst_poll_helper
{
	poll_table 		pt;
	struct dst_state	*st;
};

static int dst_queue_wake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	//printk(KERN_INFO "WAKIN' UP QUEUE");
	struct dst_state *st = container_of(wait, struct dst_state, wait);

	wake_up(&st->thread_wait);
	return 1;
}

static void dst_queue_func(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt)
{
	printk(KERN_INFO "QUEUE FUNC");
	struct dst_state *st = container_of(pt, struct dst_poll_helper, pt)->st;

	st->whead = whead;
	init_waitqueue_func_entry(&st->wait, dst_queue_wake);
	add_wait_queue(whead, &st->wait);
}

void dst_poll_exit(struct dst_state *st)
{
	if (st->whead) {
		remove_wait_queue(st->whead, &st->wait);
		st->whead = NULL;
	}
}

int dst_poll_init(struct dst_state *st)
{

	struct dst_poll_helper ph;

	ph.st = st;
	init_poll_funcptr(&ph.pt, &dst_queue_func);

	st->socket->ops->poll(NULL, st->socket, &ph.pt);
	return 0;
}

/*
 * Header receiving function - may block.
 */
static int dst_data_recv_header(struct socket *sock,
		void *data, unsigned int size, int block)
{
	printk(KERN_INFO "RECV HEADER");
	struct msghdr msg;
	struct kvec iov;
	int err;

	iov.iov_base = data;
	iov.iov_len = size;

	msg.msg_iov = (struct iovec *)&iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = (block)?MSG_WAITALL:MSG_DONTWAIT;

	err = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len,
			msg.msg_flags);
	if (err != size)
		return -1;

	return 0;
}

/*
 * Header sending function - may block.
 */
int dst_data_send_header(struct dst_state *st,
		void *data, unsigned int size, int more)
{
	//printk(KERN_INFO "SEND HEADER");
	struct msghdr msg;
	struct kvec iov;
	int err;
	struct socket *sock = st->socket;	
	
	/*buffer for ethernet frame*/
	void* buffer = kmalloc(ETH_ZLEN + size, GFP_KERNEL);
	struct ethhdr *eh = (struct ethhdr *)buffer;	
	
	/*set the frame header*/
	memcpy((void*)buffer, (void*)st->dest_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)st->src_mac, ETH_ALEN);
	eh->h_proto = htons(ETH_P_ALL);
	/*set data*/
	memcpy((void*)(buffer + ETH_HLEN), data, (int)size);	
	
	iov.iov_base = buffer;
	iov.iov_len = size + ETH_HLEN;

	msg.msg_iov = (struct iovec *)&iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_WAITALL | (more)?MSG_MORE:0;

	err = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	if (err != size + ETH_HLEN) {
		printk(KERN_INFO "kernel_sendmsg error!!!!!!!!!! %d\n", err);
		dprintk("%s: size: %u, more: %d, err: %d.\n",
				__func__, size, more, err);
		return -1;
	}

	return 0;
}

ssize_t cs_sendpage(struct dst_state *st, struct page *page, int offset, size_t size, int flags)
{
        ssize_t res;
	int send_size = 0;
        struct msghdr msg = {.msg_flags = flags};
        struct kvec iov;
        char *kaddr = kmap(page);
	void* buffer;
	struct ethhdr *eh; 
	struct socket *sock = st->socket;

	kaddr = kaddr + offset;
	while(size != 0){
		
		if(size >= ETH_DATA_LEN)
			send_size = ETH_DATA_LEN;
		else
			send_size = size;

		buffer = kmalloc(send_size + ETH_HLEN, GFP_KERNEL);
		eh = (struct ethhdr *)buffer;
		iov.iov_base = buffer;
        	iov.iov_len = send_size + ETH_HLEN;
		
		/*set the frame header*/
		memcpy((void*)buffer, (void*)st->dest_mac, ETH_ALEN);
		memcpy((void*)(buffer+ETH_ALEN), (void*)st->src_mac, ETH_ALEN);
		eh->h_proto = htons(ETH_P_ALL);
		/*set data*/
		memcpy((void*)(buffer+ETH_HLEN), kaddr, send_size);
		
		res = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
		if(res > 0)
			size -= send_size;
		else {
			return res;
			printk(KERN_INFO "res: %d\n", res);
		}
		kaddr += send_size;
		printk(KERN_INFO "size after: %d\n", size);
		kfree(buffer);
	}
        kunmap(page);
        return size;
}


/*
 * Block autoconfiguration: request size of the storage and permissions.
 */
static int dst_request_remote_config(struct dst_state *st)
{
	printk(KERN_INFO "BLOCK AUTOCONF REQUEST");
	struct dst_node *n = st->node;
	int err = -EINVAL;
	struct dst_cmd *cmd = st->data;
	//void *buf = kmalloc( 62, GFP_KERNEL);
	
	memset(cmd, 0, sizeof(struct dst_cmd));
	cmd->cmd = DST_CFG;

	dst_convert_cmd(cmd);
	printk(KERN_INFO "SEND HEADER AUTOCONF");
	err = dst_data_send_header(st, cmd, sizeof(struct dst_cmd), 0);
	if (err){
		printk(KERN_INFO "dst_data_send_header error");
		goto out;
	}
	printk(KERN_INFO "RECEIVE HEADER AUTOCONF");
	//err = dst_data_recv_header(st->socket, cmd, sizeof(struct dst_cmd), 1);
	st->read_socket = st->socket;
	err = dst_data_recv( st, cmd, sizeof(struct dst_cmd));
	if (err){
		printk(KERN_INFO "dst_data_recv_header error");
		goto out;
	}
	//memcpy((void*)cmd, (void*)(buf+14), sizeof(struct dst_cmd));
	dst_convert_cmd(cmd);

	if (cmd->cmd != DST_CFG) {
		err = -EINVAL;
		dprintk("%s: checking result: cmd: %d, size reported: %llu.\n",
			__func__, cmd->cmd, cmd->sector);
		goto out;
	}

	if (n->size != 0)
		n->size = min_t(loff_t, n->size, cmd->sector);
	else
		n->size = cmd->sector;

	n->info->size = n->size;
	st->permissions = cmd->rw;

out:
	dprintk("%s: n: %p, err: %d, size: %llu, permission: %x.\n",
			__func__, n, err, n->size, st->permissions);
	return err;
}

/*
 * Socket machinery.
 */

#define DST_DEFAULT_TIMEO	20000

int dst_state_socket_create(struct dst_state *st)
{
	int err;
	struct socket *sock;
	struct dst_network_ctl *ctl = &st->ctl;

	err = sock_create(ctl->addr.sa_family, ctl->type, ctl->proto, &sock);
	if (err < 0)
		return err;

	sock->sk->sk_sndtimeo = sock->sk->sk_rcvtimeo =
		msecs_to_jiffies(DST_DEFAULT_TIMEO);
	sock->sk->sk_allocation = GFP_NOIO;

	st->socket = st->read_socket = sock;
	return 0;
}

void dst_state_socket_release(struct dst_state *st)
{
	dprintk("%s: st: %p, socket: %p, n: %p.\n",
			__func__, st, st->socket, st->node);
	if (st->socket) {
		sock_release(st->socket);
		st->socket = NULL;
		st->read_socket = NULL;
	}
}

void dst_dump_addr(struct socket *sk, struct sockaddr *sa, char *str)
{
	//my diff
	if (sk->ops->family == AF_PACKET) {
		struct sockaddr_ll *sin = (struct sockaddr_ll*)sa;
	//	printk(KERN_INFO "%s %u.%u.%u.%u:%d.\n",
	//		str, NIPQUAD(sin->sin_addr.s_addr), ntohs(sin->sin_port));
	} else if (sk->ops->family == AF_INET6) {
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
		printk(KERN_INFO "%s %pi6:%d",
			str, &sin->sin6_addr, ntohs(sin->sin6_port));
	}
}

void dst_state_exit_connected(struct dst_state *st)
{
	if (st->socket) {
		dst_poll_exit(st);
		st->socket->ops->shutdown(st->socket, 2);

		dst_dump_addr(st->socket, (struct sockaddr *)&st->ctl.addr,
				"Disconnected peer");
		dst_state_socket_release(st);
	}
}

static int dst_state_init_connected(struct dst_state *st)
{
	int err;
	struct dst_network_ctl *ctl = &st->ctl;
	
	printk(KERN_INFO "state_init_connected");
	err = dst_state_socket_create(st);
	if (err)
		goto err_out_exit;
	//my diff
	/*err = kernel_connect(st->socket, (struct sockaddr *)&st->ctl.addr,
			st->ctl.addr.sa_data_len, 0);
	if (err)
		goto err_out_release;*/
	err = kernel_bind(st->socket, (struct sockaddr *)&ctl->addr,
			ctl->addr.sa_data_len);
	if(!err){
		printk(KERN_INFO "BIND OK!!!!");
	}
	if (err){
		printk(KERN_INFO "NO BIND!!!!");
	}
	err = dst_poll_init(st);
	if (err)
		goto err_out_release;

	dst_dump_addr(st->socket, (struct sockaddr *)&ctl->addr,
			"Connected to peer");

	return 0;

err_out_release:
	dst_state_socket_release(st);
err_out_exit:
	return err;
}

/*
 * State reset is used to reconnect to the remote peer.
 * May fail, but who cares, we will try again later.
 */
static void inline dst_state_reset_nolock(struct dst_state *st)
{
	dst_state_exit_connected(st);
	dst_state_init_connected(st);
}

static void inline dst_state_reset(struct dst_state *st)
{
	dst_state_lock(st);
	dst_state_reset_nolock(st);
	dst_state_unlock(st);
}

/*
 * Basic network sending/receiving functions.
 * Blocked mode is used.
 */
static int dst_data_recv_raw(struct dst_state *st, void *buf, u64 size)
{
	//printk(KERN_INFO "RECV RAW");
	struct msghdr msg;
	struct kvec iov;
	int err;

	BUG_ON(!size);

	iov.iov_base = buf;
	iov.iov_len = size;

	msg.msg_iov = (struct iovec *)&iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_DONTWAIT;

	err = kernel_recvmsg(st->socket, &msg, &iov, 1, iov.iov_len,
			msg.msg_flags);
	if (err <= 0) {
		dprintk("%s: failed to recv data: size: %llu, err: %d.\n",
				__func__, size, err);
		if (err == 0)
			err = -ECONNRESET;

		dst_state_exit_connected(st);
	}

	return err;
}

/*
 * Ping command to early detect failed nodes.
 */
static int dst_send_ping(struct dst_state *st)
{
	printk(KERN_INFO "PING TO DETECT FAILED");
	struct dst_cmd *cmd = st->data;
	int err = -ECONNRESET;

	dst_state_lock(st);
	if (st->socket) {
		memset(cmd, 0, sizeof(struct dst_cmd));

		cmd->cmd = __cpu_to_be32(DST_PING);

		err = dst_data_send_header(st, cmd, sizeof(struct dst_cmd), 0);
	}
	dprintk("%s: st: %p, socket: %p, err: %d.\n", __func__, st, st->socket, err);
	dst_state_unlock(st);

	return err;
}

int check_mac(struct dst_state *st,unsigned char *ch_mac)
{	
	int i, j, contains;
	struct mac_list *m_list;
	unsigned char *mac;
	contains = 0;
	list_for_each_entry(m_list, &st->ac_macs, mac_entry)
	{	
		mac = &m_list->mac;		
		contains = !memcmp(mac, ch_mac, ETH_ALEN);
		if(contains)
			break;			
	}
	//dst_print_mac( mac );
	printk(KERN_INFO "contains: %d", contains);	
	return contains;
}

/*
 * Receiving function, which should either return error or read
 * whole block request. If there was no traffic for a one second,
 * send a ping, since remote node may die.
 */
int dst_data_recv(struct dst_state *st, void *data, unsigned int size)
{
	//printk(KERN_INFO "DATA RCV");
	unsigned int revents = 0;
	unsigned int err_mask = POLLERR | POLLHUP | POLLRDHUP;
	unsigned int mask = err_mask | POLLIN;
	struct dst_node *n = st->node;
	int err = 0, our_packet = 0;
	void *buf = kmalloc(size + ETH_HLEN, GFP_KERNEL);
	//printk(KERN_INFO "size+ETH_HLEN = %d\n", size + ETH_HLEN);	

	while (size && !err && !our_packet) {
			revents = dst_state_poll(st);

			if (!(revents & mask)) {
				DEFINE_WAIT(wait);

				for (;;) {
					prepare_to_wait(&st->thread_wait, &wait,
							TASK_INTERRUPTIBLE);
					if (!n->trans_scan_timeout || st->need_exit)
						break;

					revents = dst_state_poll(st);

					if (revents & mask)
						break;

					if (signal_pending(current))
						break;

					if (!schedule_timeout(HZ)) {
						//err = dst_send_ping(st);
						if (err)
							return err;
					}

					continue;
				}
				finish_wait(&st->thread_wait, &wait);
			}

			err = -ECONNRESET;
			dst_state_lock(st);

			if (st->socket && (st->read_socket == st->socket) && (revents & POLLIN)) 
			{
				err = dst_data_recv_raw(st, buf, size + ETH_HLEN);
				
				if(st-> type == LISTENING){

					printk(KERN_INFO "listening");
					memcpy(st->dest_mac, buf + 6, ETH_ALEN);
					printk(KERN_INFO "dest after");
					dst_print_mac(st->dest_mac);
					if(!check_mac(st, st->dest_mac)){
						//our_packet = 1;
						memcpy(data, buf+ETH_HLEN, size);
						printk(KERN_INFO "listening, our_packet");
					}
				}
				else if( !memcmp( st-> dest_mac, buf + 6, ETH_ALEN))
				{
					//our_packet = 1;
					memcpy(data, buf+ETH_HLEN, size);
					//printk(KERN_INFO "our packet ");
				} 
				else 
				{
					//printk(KERN_INFO "not our packet ");
				}
				// if we need receve many packets
				if (err > 0) {
						data += (err-ETH_HLEN);
						size -= (err-ETH_HLEN);
						err = 0;
				}
			}

			if (revents & err_mask || !st->socket) {
				dprintk("%s: revents: %x, socket: %p, size: %u, err: %d.\n",
						__func__, revents, st->socket, size, err);
				err = -ECONNRESET;
			}

			dst_state_unlock(st);

			if (!n->trans_scan_timeout)
				err = -ENODEV;
		}
	kfree(buf);
	return err;
}

/*
 * Send block autoconf reply.
 */
int dst_process_cfg(struct dst_state *st)//static
{
	//printk(KERN_INFO "PROCESS CFG: SEND AUTOCONF REPLY");
	struct dst_node *n = st->node;
	struct dst_cmd *cmd = st->data;
	int err;
	//printk(KERN_INFO "node size %d", n->size);
	cmd->sector = n->size;
	cmd->rw = st->permissions;

	dst_convert_cmd(cmd);

	dst_state_lock(st);
	err = dst_data_send_header(st, cmd, sizeof(struct dst_cmd), 0);
	dst_state_unlock(st);
	return err;
}

/*
 * Receive block IO from the network.
 */
static int dst_recv_bio(struct dst_state *st, struct bio *bio, unsigned int total_size)
{
	printk(KERN_INFO "RCV BIO");
	struct bio_vec *bv;
	int i, err;
	void *data;
	unsigned int sz;

	bio_for_each_segment(bv, bio, i) {
		sz = min(total_size, bv->bv_len);

		dprintk("%s: bio: %llu/%u, total: %u, len: %u, sz: %u, off: %u.\n",
			__func__, (u64)bio->bi_sector, bio->bi_size, total_size,
			bv->bv_len, sz, bv->bv_offset);

		data = kmap(bv->bv_page) + bv->bv_offset;
		err = dst_data_recv(st, data, sz);
		kunmap(bv->bv_page);

		bv->bv_len = sz;

		if (err)
			return err;

		total_size -= sz;
		if (total_size == 0)
			break;
	}

	return 0;
}

/*
 * Our block IO has just completed and arrived: get it.
 */
static int dst_process_io_response(struct dst_state *st)
{
	printk(KERN_INFO "DST PROCESS IO RESPONSE");
	struct dst_node *n = st->node;
	struct dst_cmd *cmd = st->data;
	struct dst_trans *t;
	int err = 0;
	struct bio *bio;

	mutex_lock(&n->trans_lock);
	t = dst_trans_search(n, cmd->id);
	mutex_unlock(&n->trans_lock);

	if (!t)
		goto err_out_exit;

	bio = t->bio;

	dprintk("%s: bio: %llu/%u, cmd_size: %u, csize: %u, dir: %lu.\n",
		__func__, (u64)bio->bi_sector, bio->bi_size, cmd->size,
		cmd->csize, bio_data_dir(bio));

	if (bio_data_dir(bio) == READ) {
		if (bio->bi_size != cmd->size - cmd->csize)
			goto err_out_exit;

		if (dst_need_crypto(n)) {
			err = dst_recv_cdata(st, t->cmd.hash);
			if (err)
				goto err_out_exit;
		}

		err = dst_recv_bio(st, t->bio, bio->bi_size);
		if (err)
			goto err_out_exit;

		if (dst_need_crypto(n))
			return dst_trans_crypto(t);
	} else {
		err = -EBADMSG;
		if (cmd->size || cmd->csize)
			goto err_out_exit;
	}

	dst_trans_remove(t);
	dst_trans_put(t);

	return 0;

err_out_exit:
	return err;
}

/*
 * Receive crypto data.
 */

int dst_recv_cdata(struct dst_state *st, void *cdata)
{
	printk(KERN_INFO "RECV CRYPTO DATA");
	struct dst_cmd *cmd = st->data;
	struct dst_node *n = st->node;
	struct dst_crypto_ctl *c = &n->crypto;
	int err;

	if (cmd->csize != c->crypto_attached_size) {
		dprintk("%s: cmd: cmd: %u, sector: %llu, size: %u, "
				"csize: %u != digest size %u.\n",
				__func__, cmd->cmd, cmd->sector, cmd->size,
				cmd->csize, c->crypto_attached_size);
		err = -EINVAL;
		goto err_out_exit;
	}

	err = dst_data_recv(st, cdata, cmd->csize);
	if (err)
		goto err_out_exit;

	cmd->size -= cmd->csize;
	return 0;

err_out_exit:
	return err;
}

/*
 * Receive the command and start its processing.
 */
static int dst_recv_processing(struct dst_state *st)
{
	//printk(KERN_INFO "RECV PROCESSING");
	int err = -EINTR;
	struct dst_cmd *cmd = st->data;

	/*
	 * If socket will be reset after this statement, then
	 * dst_data_recv() will just fail and loop will
	 * start again, so it can be done without any locks.
	 *
	 * st->read_socket is needed to prevents state machine
	 * breaking between this data reading and subsequent one
	 * in protocol specific functions during connection reset.
	 * In case of reset we have to read next command and do
	 * not expect data for old command to magically appear in
	 * new connection.
	 */
	st->read_socket = st->socket;
	
	err = dst_data_recv(st, cmd, sizeof(struct dst_cmd));
	if (err)
		goto out_exit;

	dst_convert_cmd(cmd);

	dprintk("%s: cmd: %u, size: %u, csize: %u, id: %llu, "
			"sector: %llu, flags: %llx, rw: %llx.\n",
			__func__, cmd->cmd, cmd->size,
			cmd->csize, cmd->id, cmd->sector,
			cmd->flags, cmd->rw);

	/*
	 * This should catch protocol breakage and random garbage instead of commands.
	 */
	if (unlikely(cmd->csize > st->size - sizeof(struct dst_cmd))) {
		err = -EBADMSG;
		goto out_exit;
	}

	err = -EPROTO;
	switch (cmd->cmd) {
		case DST_IO_RESPONSE:
			err = dst_process_io_response(st);
			break;
		case DST_IO:
			err = dst_process_io(st);
			break;
		case DST_CFG:
			err = dst_process_cfg(st);
			break;
		case DST_PING:
			err = 0;
			break;
		default:
			break;
	}

out_exit:
	return err;
}

/*
 * Receiving thread. For the client node we should try to reconnect,
 * for accepted client we just drop the state and expect it to reconnect.
 */
static int dst_recv(void *init_data, void *schedule_data)
{
	printk(KERN_INFO "DST RECV");
	struct dst_state *st = schedule_data;
	struct dst_node *n = init_data;
	int err = 0;

	dprintk("%s: start st: %p, n: %p, scan: %lu, need_exit: %d.\n",
			__func__, st, n, n->trans_scan_timeout, st->need_exit);

	while (n->trans_scan_timeout && !st->need_exit) {
		err = dst_recv_processing(st);
		if (err < 0) {
			/*if (!st->ctl.type)
				break;

			if (!n->trans_scan_timeout || st->need_exit)
				break;
			printk(KERN_INFO "dst_recv err < 0; call dst_state_reset, err = %d\n" , err);
			dst_state_reset(st);
			msleep(1000);*/
		}
	}

	st->need_exit = 1;
	wake_up(&st->thread_wait);

	dprintk("%s: freeing receiving socket st: %p.\n", __func__, st);
	dst_state_lock(st);
	dst_state_exit_connected(st);
	dst_state_unlock(st);
	dst_state_put(st);

	dprintk("%s: freed receiving socket st: %p.\n", __func__, st);

	return err;
}

/*
 * Network state dies here and borns couple of lines below.
 * This object is the main network state processing engine:
 * sending, receiving, reconnections, all network related
 * tasks are handled on behalf of the state.
 */
static void dst_state_free(struct dst_state *st)
{
	dprintk("%s: st: %p.\n", __func__, st);
	if (st->cleanup)
		st->cleanup(st);
	kfree(st->data);
	//todo : clean up mac_list	
	kfree(st);
}

struct dst_state *dst_state_alloc(struct dst_node *n, int type)
{
	struct dst_state *st;
	int err = -ENOMEM;

	st = kzalloc(sizeof(struct dst_state), GFP_KERNEL);
	if (!st)
		goto err_out_exit;

	st->node = n;
	st->need_exit = 0;

	st->size = PAGE_SIZE;
	st->data = kmalloc(st->size, GFP_KERNEL);
	if (!st->data)
		goto err_out_free;

	spin_lock_init(&st->request_lock);
	INIT_LIST_HEAD(&st->request_list);
	

	mutex_init(&st->state_lock);
	init_waitqueue_head(&st->thread_wait);

	INIT_LIST_HEAD(&st->ac_macs);

	/*
	 * One for processing thread, another one for node itself.
	 */
	atomic_set(&st->refcnt, 2);

	dprintk("%s: st: %p, n: %p.\n", __func__, st, st->node);
	
	if(type == LISTENING)
	{
		st->type = LISTENING;
		printk(KERN_INFO "state type: listening" );
	}else{
		st->type = COMMON;
		printk(KERN_INFO "state type: common" );
	}		

	return st;

err_out_free:
	kfree(st);
err_out_exit:
	return ERR_PTR(err);
}

int dst_state_schedule_receiver(struct dst_state *st)
{
	return thread_pool_schedule_private(st->node->pool, dst_thread_setup,
			dst_recv, st, MAX_SCHEDULE_TIMEOUT, st->node);
}

/*
 * Initialize client's connection to the remote peer: allocate state,
 * connect and perform block IO autoconfiguration.
 */
int dst_node_init_connected(struct dst_node *n, struct dst_network_ctl *r)
{
	printk(KERN_INFO "INIT CONNECT");
	struct dst_state *st;
	int err = -ENOMEM;
	struct sockaddr_ll* sa;
	struct net_device *ifp;
	st = dst_state_alloc(n, COMMON);
	if (IS_ERR(st)) {
		err = PTR_ERR(st);
		goto err_out_exit;
	}
	memcpy(&st->ctl, r, sizeof(struct dst_network_ctl));
	sa = (struct sockaddr_ll*)&(st->ctl.addr);

	/* find device by index */
	read_lock(&dev_base_lock);
		for_each_netdev(&init_net, ifp) {
			if (ifp->ifindex == sa->sll_ifindex){
				printk(KERN_INFO "number of interface %d\n", ifp->ifindex);
				break;
			}
		}
	read_unlock(&dev_base_lock);

	memcpy(st->src_mac, ifp->dev_addr, ETH_ALEN);    // copy src_mac to new state
	printk(KERN_INFO "dest before");
	dst_print_mac(st->dest_mac);
	memcpy(st->dest_mac, sa->sll_addr, ETH_ALEN);   // copy dest_mac to new state	
	printk(KERN_INFO "dest after");
	dst_print_mac(st->dest_mac);

	err = dst_state_init_connected(st);
	if (err){
		printk(KERN_INFO "dst_state_init_connected error\n");
		goto err_out_free_data;
	}

	err = dst_request_remote_config(st);
	if (err){
		printk(KERN_INFO "dst_request_remote_config error\n");
		goto err_out_exit_connected;
	}
	n->state = st;

	err = dst_state_schedule_receiver(st);
	if (err){
		printk(KERN_INFO "dst_state_scheldure_receiver error\n");
		goto err_out_exit_connected;
	}
	return 0;

err_out_exit_connected:
	dst_state_exit_connected(st);
err_out_free_data:
	dst_state_free(st);
err_out_exit:
	n->state = NULL;
	return err;
}

void dst_state_put(struct dst_state *st)
{
	dprintk("%s: st: %p, refcnt: %d.\n",
			__func__, st, atomic_read(&st->refcnt));
	if (atomic_dec_and_test(&st->refcnt))
		dst_state_free(st);
}

/*
 * Send block IO to the network one by one using zero-copy ->sendpage().
 */
int dst_send_bio(struct dst_state *st, struct dst_cmd *cmd, struct bio *bio)
{
	printk(KERN_INFO "SEND BIO ONE BY ONE");
	struct bio_vec *bv;
	struct dst_crypto_ctl *c = &st->node->crypto;
	int err, i = 0;
	int flags = MSG_WAITALL;

	err = dst_data_send_header(st, cmd,
		sizeof(struct dst_cmd) + c->crypto_attached_size, bio->bi_vcnt);
	if (err)
		goto err_out_exit;

	/*bio_for_each_segment(bv, bio, i) {
		if (i < bio->bi_vcnt - 1)
			flags |= MSG_MORE;

		//err = kernel_sendpage(st->socket, bv->bv_page, bv->bv_offset,
			//	bv->bv_len, flags);
		if (err <= 0)
			goto err_out_exit;
	}*/

	bio_for_each_segment(bv, bio, i) {
		if (i < bio->bi_vcnt - 1)
			flags |= MSG_MORE;

		err = cs_sendpage(st, bv->bv_page, bv->bv_offset,
				bv->bv_len, flags);
		if (err <= 0)
			goto err_out_exit;
	}

	return 0;

err_out_exit:
	dprintk("%s: %d/%d, flags: %x, err: %d.\n",
			__func__, i, bio->bi_vcnt, flags, err);
	return err;
}

/*
 * Send transaction to the remote peer.
 */
int dst_trans_send(struct dst_trans *t)
{
	printk(KERN_INFO "SEND TRANSACTION");
	int err;
	struct dst_state *st = t->n->state;
	struct bio *bio = t->bio;

	dst_convert_cmd(&t->cmd);

	dst_state_lock(st);
	if (!st->socket) {
		err = dst_state_init_connected(st);
		if (err)
			goto err_out_unlock;
	}

	if (bio_data_dir(bio) == WRITE) {
		err = dst_send_bio(st, &t->cmd, t->bio);
	} else {
		err = dst_data_send_header(st, &t->cmd,
				sizeof(struct dst_cmd), 0);
	}
	if (err)
		goto err_out_reset;

	dst_state_unlock(st);
	return 0;

err_out_reset:
	dst_state_reset_nolock(st);
err_out_unlock:
	dst_state_unlock(st);

	return err;
}
