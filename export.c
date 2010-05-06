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

#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/dst.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/socket.h>

#include <net/sock.h>

/*
 * Export bioset is used for server block IO requests.
 */
static struct bio_set *dst_bio_set;

int __init dst_export_init(void)
{
	int err = -ENOMEM;

	dst_bio_set = bioset_create(32, sizeof(struct dst_export_priv));
	if (!dst_bio_set)
		goto err_out_exit;

	return 0;

err_out_exit:
	return err;
}

void dst_export_exit(void)
{
	bioset_free(dst_bio_set);
}

/*
 * When client connects and autonegotiates with the server node,
 * its permissions are checked in a security attributes and sent
 * back.
 */
static unsigned int dst_check_permissions(struct dst_state *main, unsigned char *mac)
{
	struct dst_node *n = main->node;
	struct dst_secure *sentry;
	struct dst_secure_user *s;
	//struct saddr *sa = &st->ctl.addr;
	unsigned int perm = 0;
	
	mutex_lock(&n->security_lock);
	list_for_each_entry(sentry, &n->security_list, sec_entry) {
		s = &sentry->sec;
		/*
		if (s->addr.sa_family != sa->sa_family)
			continue;

		if (s->addr.sa_data_len != sa->sa_data_len)
			continue;

		/*
		 * This '2' below is a port field. This may be very wrong to do
		 * in atalk for example though. If there will be any need to extent
		 * protocol to something else, I can create per-family helpers and
		 * use them instead of this memcmp.
		 */
		if (memcmp(s->addr.sa_data + 10, mac, ETH_ALEN))
			continue;
		perm = s->permissions;
	}
	mutex_unlock(&n->security_lock);

	return 3;
}
/*
 *Checks if mac contains in accepted macs list.
 */ 
void dst_print_mac(unsigned char *mac)
{
	int i;
	printk(KERN_INFO "mac: ");
	printk(KERN_INFO "%d:%d:%d:%d:%d:%d", mac[0],mac[1], mac[2], mac[3], mac[4], mac[5]);
	
}

/*
 * Accept new client: allocate appropriate network state and check permissions.
 */
static struct dst_state *dst_accept_client(struct dst_state *st)
{
	unsigned int revents = 0;
	unsigned int err_mask = POLLERR | POLLHUP | POLLRDHUP;
	unsigned int mask = err_mask | POLLIN;
	struct dst_node *n = st->node;
	int err = 0;
	struct socket *sock = NULL;
	struct dst_state *new;
	printk(KERN_INFO "dst_accept_client");
	struct dst_network_ctl *ctl = &st->ctl;
	/*
	while (!err && !sock) {
		revents = dst_state_poll(st);

		if (!(revents & mask)) {
			DEFINE_WAIT(wait);

			for (;;) {
				prepare_to_wait(&st->thread_wait,
						&wait, TASK_INTERRUPTIBLE);
				if (!n->trans_scan_timeout || st->need_exit)
					break;

				revents = dst_state_poll(st);

				if (revents & mask)
					break;

				if (signal_pending(current))
					break;

				/*
				 * Magic HZ? Polling check above is not safe in
				 * all cases (like socket reset in BH context),
				 * so it is simpler just to postpone it to the
				 * process context instead of implementing special
				 * locking there.
				 */
				/*schedule_timeout(HZ);
			}
			finish_wait(&st->thread_wait, &wait);
		}
		err = -ECONNRESET;
		dst_state_lock(st);

		dprintk("%s: st: %p, revents: %x [err: %d, in: %d].\n",
			__func__, st, revents, revents & err_mask,
			revents & POLLIN);

		if (revents & err_mask) {
			dprintk("%s: revents: %x, socket: %p, err: %d.\n",
					__func__, revents, st->socket, err);
			err = -ECONNRESET;
		}

		if (!n->trans_scan_timeout || st->need_exit)
			err = -ENODEV;
		//my diff
		if (st->socket && (revents & POLLIN)){
				sock = st->socket;
				err = 0;
				}
		//err = kernel_accept(st->socket, &sock, 0);
		//my diff
		dst_state_unlock(st);
	}
	//printk(KERN_INFO "after while");

	if (err)
		goto err_out_exit;
	*/
	new = dst_state_alloc(st->node, COMMON); //allocates new state for ne client
	if (!new) {
		printk(KERN_INFO "state alloc err %d", err);
		err = -ENOMEM;
		goto err_out_exit;
	}
	memcpy(&new->ctl, &st->ctl, sizeof(struct dst_network_ctl));
	err = dst_state_socket_create(new);//creates socket for new state
	if (err){
		printk(KERN_INFO "sock create err %d", err);
		goto err_out_exit;
	}

	st->socket->sk->sk_reuse = 1;

	err = kernel_bind(new->socket, (struct sockaddr *)&ctl->addr,
			ctl->addr.sa_data_len);//bind socket with eth interface
	if(!err){
		printk(KERN_INFO "BIND OK!!!!");
	}
	if (err){
		printk(KERN_INFO "NO BIND!!!!");
		goto err_out_release;
	}
	
	new->ctl.addr.sa_data_len = sizeof(struct sockaddr_ll);//mydiff sockaddr
	
	printk(KERN_INFO "%d,\n", err);
	
	err = dst_poll_init(new);
	if (err)
		goto err_out_put;
	printk(KERN_INFO "poll init");
	dst_dump_addr(new -> socket, (struct sockaddr *)&new->ctl.addr,
			"Connected client");
	printk(KERN_INFO "connected client");
	return new;

err_out_put:
	dst_state_put(new);
err_out_release:
	sock_release(new->socket);//wtf?
err_out_exit:
	return ERR_PTR(err);
}

/*
 * Check client's mac and compare one with list of client's mac,
 * then if mac already exists - drop packet, else check command in data and
 * if command is DST_CFG then add mac to list and call dst_accept_client.
 */
struct dst_state *dst_check_client_mac(struct dst_state *st){
	struct dst_cmd *cmd = st->data;
	int i, err, contains, permissions;
	unsigned char *test_mac;
	struct dst_state *new;
	struct mac_list *m_list;
	struct sockaddr_ll* sa;

	sa = (struct sockaddr_ll*)&(st->ctl.addr);
	
	st->read_socket = st->socket;

	err = dst_data_recv(st, cmd, sizeof(struct dst_cmd));

	if(err > 0) {
		printk(KERN_INFO "no recieve message");	
	}		
	
	permissions = dst_check_permissions( st, st->dest_mac);
	printk(KERN_INFO "permissions: %d", permissions);		
	if( permissions <= 0)
		err = -ENOMEM; //todo
	else
	{	
		dst_convert_cmd(cmd);
		switch (cmd->cmd) {
			case DST_CFG:
				printk(KERN_INFO "mac to accept(dest_mac)");
				dst_print_mac(st->dest_mac);	
				new = dst_accept_client(st);
				new->permissions = permissions;
				m_list = kmalloc(sizeof(struct mac_list), GFP_KERNEL);	
				memcpy(m_list->mac, st->dest_mac, ETH_ALEN);
					
				dst_print_mac(m_list->mac);				

				memcpy(new->dest_mac, st->dest_mac, ETH_ALEN);   	// copy dest_mac to new state
				memcpy(new->src_mac, sa->sll_addr, ETH_ALEN);   	// copy src_mac to new state
				list_add_tail(&m_list->mac_entry, &st->ac_macs); 	//adding new connected mac to list of accepted ones
				
				list_for_each_entry(m_list, &st->ac_macs, mac_entry)
					{	
						test_mac = &m_list->mac;
						printk(KERN_INFO "test print mac: /n");		
						dst_print_mac(test_mac);			
					}
				memcpy(new->data, st->data, sizeof(struct dst_cmd));
				err = dst_process_cfg(new);
				printk(KERN_INFO "DST_PROC_CFG %d/n",err);
				break;
			default:
				printk(KERN_INFO "DST CMD ERR");
				err = -ENOMEM; //todo
				break;
		}
	}
	
	//kfree(buf);
	if(err){
		new = ERR_PTR(err);
	}
	return new;
}



/*
 * Each server's block request sometime finishes.
 * Usually it happens in hard irq context of the appropriate controller,
 * so to play good with all cases we just queue BIO into the queue
 * and wake up processing thread, which gets completed request and
 * send (encrypting if needed) it back to the client (if it was a read
 * request), or sends back reply that writing succesfully completed.
 */
static int dst_export_process_request_queue(struct dst_state *st)
{
	unsigned long flags;
	struct dst_export_priv *p = NULL;
	struct bio *bio;
	int err = 0;

	while (!list_empty(&st->request_list)) {
		spin_lock_irqsave(&st->request_lock, flags);
		if (!list_empty(&st->request_list)) {
			p = list_first_entry(&st->request_list,
				struct dst_export_priv, request_entry);
			list_del(&p->request_entry);
		}
		spin_unlock_irqrestore(&st->request_lock, flags);

		if (!p)
			break;

		bio = p->bio;

		if (dst_need_crypto(st->node) && (bio_data_dir(bio) == READ))
			err = dst_export_crypto(st->node, bio);
		else
			err = dst_export_send_bio(bio);

		if (err)
			break;
	}

	return err;
}

/*
 * Cleanup export state.
 * It has to wait until all requests are finished,
 * and then free them all.
 */
static void dst_state_cleanup_export(struct dst_state *st)
{
	struct dst_export_priv *p;
	unsigned long flags;

	/*
	 * This loop waits for all pending bios to be completed and freed.
	 */
	while (atomic_read(&st->refcnt) > 1) {
		dprintk("%s: st: %p, refcnt: %d, list_empty: %d.\n",
				__func__, st, atomic_read(&st->refcnt),
				list_empty(&st->request_list));
		wait_event_timeout(st->thread_wait,
				(atomic_read(&st->refcnt) == 1) ||
				!list_empty(&st->request_list),
				HZ/2);

		while (!list_empty(&st->request_list)) {
			p = NULL;
			spin_lock_irqsave(&st->request_lock, flags);
			if (!list_empty(&st->request_list)) {
				p = list_first_entry(&st->request_list,
					struct dst_export_priv, request_entry);
				list_del(&p->request_entry);
			}
			spin_unlock_irqrestore(&st->request_lock, flags);

			if (p)
				bio_put(p->bio);

			dprintk("%s: st: %p, refcnt: %d, list_empty: %d, p: %p.\n",
				__func__, st, atomic_read(&st->refcnt),
				list_empty(&st->request_list), p);
		}
	}

	dst_state_put(st);
}

/*
 * Client accepting thread.
 * Not only accepts new connection, but also schedules receiving thread
 * and performs request completion described above.
 */
static int dst_accept(void *init_data, void *schedule_data)
{
	struct dst_state *main_st = schedule_data;
	struct dst_node *n = init_data;
	struct dst_state *st;
	int err,i;
	
	i = 0;
	printk(KERN_INFO "dst_accept");
	while (n->trans_scan_timeout && !main_st->need_exit) {
		dprintk("%s: main_st: %p, n: %p.\n", __func__, main_st, n);
		printk(KERN_INFO "dst_accept_middle(before dst_check_client_mac)");
		st = dst_check_client_mac(main_st);
		if (IS_ERR(st))
			continue;

		err = dst_state_schedule_receiver(st);
		if (!err) {
			printk(KERN_INFO "dst_accept_middle(in if)");
			while (n->trans_scan_timeout) {
				err = wait_event_interruptible_timeout(st->thread_wait,
						!list_empty(&st->request_list) ||
						!n->trans_scan_timeout ||
						st->need_exit,
					HZ);

				if (!n->trans_scan_timeout || st->need_exit)
				{	
					printk(KERN_INFO "first if");
					break;
				}
				if (list_empty(&st->request_list))
				{
					printk(KERN_INFO "second if");
					continue;
				}
				err = dst_export_process_request_queue(st);
				if (err){
					printk(KERN_INFO "third if");
					break;
				}
			}

			st->need_exit = 1;
			wake_up(&st->thread_wait);
		}

		dst_state_cleanup_export(st);
	}

	dprintk("%s: freeing listening socket st: %p.\n", __func__, main_st);

	dst_state_lock(main_st);
	dst_poll_exit(main_st);
	dst_state_socket_release(main_st);
	dst_state_unlock(main_st);
	dst_state_put(main_st);
	dprintk("%s: freed listening socket st: %p.\n", __func__, main_st);
	printk(KERN_INFO "dst_accept exit");
	return 0;
}

int dst_start_export(struct dst_node *n)
{
	if (list_empty(&n->security_list)) {
		printk(KERN_ERR "You are trying to export node '%s' without security attributes.\n"
				"No clients will be allowed to connect. Exiting.\n", n->name);
		return -EINVAL;
	}
	return dst_node_trans_init(n, sizeof(struct dst_export_priv));
}

/*
 * Initialize listening state and schedule accepting thread.
 */
int dst_node_init_listened(struct dst_node *n, struct dst_export_ctl *le)
{	
	struct dst_state *st;
	int err = -ENOMEM;
	struct dst_network_ctl *ctl = &le->ctl;

	memcpy(&n->info->net, ctl, sizeof(struct dst_network_ctl));

	st = dst_state_alloc(n, LISTENING);
	if (IS_ERR(st)) {
		err = PTR_ERR(st);
		goto err_out_exit;
	}
	memcpy(&st->ctl, ctl, sizeof(struct dst_network_ctl));

	err = dst_state_socket_create(st);
	if (err)
		goto err_out_put;

	st->socket->sk->sk_reuse = 1;

	err = kernel_bind(st->socket, (struct sockaddr *)&ctl->addr,
			ctl->addr.sa_data_len);
	if(!err){
		printk(KERN_INFO "BIND OK!!!!");
	}
	if (err){
		printk(KERN_INFO "NO BIND!!!!");
		goto err_out_socket_release;
	}

/*	err = kernel_listen(st->socket, 1024);
	if (err)
		goto err_out_socket_release;*/
	n->state = st;

	err = dst_poll_init(st);
	if (err)
		goto err_out_socket_release;

	dst_state_get(st);

	err = thread_pool_schedule(n->pool, dst_thread_setup,
			dst_accept, st, MAX_SCHEDULE_TIMEOUT);
	if (err)
		goto err_out_poll_exit;

	return 0;

err_out_poll_exit:
	dst_poll_exit(st);
err_out_socket_release:
	dst_state_socket_release(st);
err_out_put:
	dst_state_put(st);
err_out_exit:
	n->state = NULL;
	return err;
}

/*
 * Free bio and related private data.
 * Also drop a reference counter for appropriate state,
 * which waits when there are no more block IOs in-flight.
 */
static void dst_bio_destructor(struct bio *bio)
{
	struct bio_vec *bv;
	struct dst_export_priv *priv = bio->bi_private;
	int i;

	bio_for_each_segment(bv, bio, i) {
		if (!bv->bv_page)
			break;

		__free_page(bv->bv_page);
	}

	if (priv)
		dst_state_put(priv->state);
	bio_free(bio, dst_bio_set);
}

/*
 * Block IO completion. Queue request to be sent back to
 * the client (or just confirmation).
 */
static void dst_bio_end_io(struct bio *bio, int err)
{
	struct dst_export_priv *p = bio->bi_private;
	struct dst_state *st = p->state;
	unsigned long flags;

	spin_lock_irqsave(&st->request_lock, flags);
	list_add_tail(&p->request_entry, &st->request_list);
	spin_unlock_irqrestore(&st->request_lock, flags);

	wake_up(&st->thread_wait);
}

/*
 * Allocate read request for the server.
 */
static int dst_export_read_request(struct bio *bio, unsigned int total_size)
{
	unsigned int size;
	struct page *page;
	int err;

	while (total_size) {
		err = -ENOMEM;
		page = alloc_page(GFP_KERNEL);
		if (!page)
			goto err_out_exit;

		size = min_t(unsigned int, PAGE_SIZE, total_size);

		err = bio_add_page(bio, page, size, 0);
		dprintk("%s: bio: %llu/%u, size: %u, err: %d.\n",
				__func__, (u64)bio->bi_sector, bio->bi_size,
				size, err);
		if (err <= 0)
			goto err_out_free_page;

		total_size -= size;
	}

	return 0;

err_out_free_page:
	__free_page(page);
err_out_exit:
	return err;
}

/*
 * Allocate write request for the server.
 * Should not only get pages, but also read data from the network.
 */
static int dst_export_write_request(struct dst_state *st,
		struct bio *bio, unsigned int total_size)
{
	unsigned int size;
	struct page *page;
	void *data;
	int err;

	while (total_size) {
		err = -ENOMEM;
		page = alloc_page(GFP_KERNEL);
		if (!page)
			goto err_out_exit;

		data = kmap(page);
		if (!data)
			goto err_out_free_page;

		size = min_t(unsigned int, PAGE_SIZE, total_size);

		err = dst_data_recv(st, data, size);
		if (err)
			goto err_out_unmap_page;

		err = bio_add_page(bio, page, size, 0);
		if (err <= 0)
			goto err_out_unmap_page;

		kunmap(page);

		total_size -= size;
	}

	return 0;

err_out_unmap_page:
	kunmap(page);
err_out_free_page:
	__free_page(page);
err_out_exit:
	return err;
}
/*
 * Groovy, we've gotten an IO request from the client.
 * Allocate BIO from the bioset, private data from the mempool
 * and lots of pages for IO.
 */
int dst_process_io(struct dst_state *st)
{
	struct dst_node *n = st->node;
	struct dst_cmd *cmd = st->data;
	struct bio *bio;
	struct dst_export_priv *priv;
	int err = -ENOMEM;

	if (unlikely(!n->bdev)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	bio = bio_alloc_bioset(GFP_KERNEL,
			PAGE_ALIGN(cmd->size) >> PAGE_SHIFT,
			dst_bio_set);
	if (!bio)
		goto err_out_exit;

	priv = (struct dst_export_priv *)(((void *)bio) - sizeof (struct dst_export_priv));

	priv->state = dst_state_get(st);
	priv->bio = bio;

	bio->bi_private = priv;
	bio->bi_end_io = dst_bio_end_io;
	bio->bi_destructor = dst_bio_destructor;
	bio->bi_bdev = n->bdev;

	/*
	 * Server side is only interested in two low bits:
	 * uptodate (set by itself actually) and rw block
	 */
	bio->bi_flags |= cmd->flags & 3;

	bio->bi_rw = cmd->rw;
	bio->bi_size = 0;
	bio->bi_sector = cmd->sector;

	dst_bio_to_cmd(bio, &priv->cmd, DST_IO_RESPONSE, cmd->id);

	priv->cmd.flags = 0;
	priv->cmd.size = cmd->size;

	if (bio_data_dir(bio) == WRITE) {
		err = dst_recv_cdata(st, priv->cmd.hash);
		if (err)
			goto err_out_free;

		err = dst_export_write_request(st, bio, cmd->size);
		if (err)
			goto err_out_free;

		if (dst_need_crypto(n))
			return dst_export_crypto(n, bio);
	} else {
		err = dst_export_read_request(bio, cmd->size);
		if (err)
			goto err_out_free;
	}

	dprintk("%s: bio: %llu/%u, rw: %lu, dir: %lu, flags: %lx, phys: %d.\n",
			__func__, (u64)bio->bi_sector, bio->bi_size,
			bio->bi_rw, bio_data_dir(bio),
			bio->bi_flags, bio->bi_phys_segments);

	generic_make_request(bio);

	return 0;

err_out_free:
	bio_put(bio);
err_out_exit:
	return err;
}

/*
 * Ok, block IO is ready, let's send it back to the client...
 */
int dst_export_send_bio(struct bio *bio)
{
	printk(KERN_INFO "EXPORT SEND BIO");
	struct dst_export_priv *p = bio->bi_private;
	struct dst_state *st = p->state;
	struct dst_cmd *cmd = &p->cmd;
	int err;

	dprintk("%s: id: %llu, bio: %llu/%u, csize: %u, flags: %lu, rw: %lu.\n",
			__func__, cmd->id, (u64)bio->bi_sector, bio->bi_size,
			cmd->csize, bio->bi_flags, bio->bi_rw);

	dst_convert_cmd(cmd);

	dst_state_lock(st);
	if (!st->socket) {
		err = -ECONNRESET;
		goto err_out_unlock;
	}

	if (bio_data_dir(bio) == WRITE) {
		/* ... or just confirmation that writing has completed. */
		cmd->size = cmd->csize = 0;
		err = dst_data_send_header(st, cmd,
				sizeof(struct dst_cmd), 0);
		if (err)
			goto err_out_unlock;
	} else {
		err = dst_send_bio(st, cmd, bio);
		if (err)
			goto err_out_unlock;
	}

	dst_state_unlock(st);

	bio_put(bio);
	return 0;

err_out_unlock:
	dst_state_unlock(st);

	bio_put(bio);
	return err;
}
