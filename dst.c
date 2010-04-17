/*
 * 2007+ Copyright (c) Evgeniy Polyakov <johnpol@2ka.mipt.ru>
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
 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/poll.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <netdb.h>

#include <asm/byteorder.h>

#include "linux/dst.h"
#include "linux/connector.h"

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define SOL_NETLINK    270

#define ulog(f, a...) fprintf(stderr, f, ##a)
#define ulog_err(f, a...) ulog(f ": %s [%d].\n", ##a, strerror(errno), errno)

static unsigned int dst_seq;

static int digit2int(char d)
{
	//ulog("call digit2int\n");
        switch(d) {
        case 'F':
        case 'E':
        case 'D':
        case 'C':
        case 'B':
        case 'A':
                return d - 'A' + 10;
        case 'f':
        case 'e':
        case 'd':
        case 'c':
        case 'b':
        case 'a':
                return d - 'a' + 10;
        case '9':
        case '8':
        case '7':
        case '6':
        case '5':
        case '4':
        case '3':
        case '2':
        case '1':
        case '0':
                return d - '0';
        }
        return -1;
}

static unsigned char* hex2int(char *s, unsigned char* mac)
{
        int res;
        int tmp;
	int i,j;
 	ulog("call hex2int\n");    
        if (strlen(s) != 12)
                return NULL;

	for(i = 0, j = 0; i <  12; i++, j++){
       		
        	tmp = digit2int(s[i]);
        	if (tmp < 0)
                	return NULL;
        	
               	res = digit2int(s[++i]);
              	if (res < 0)
                        return NULL;

                tmp = tmp * 16 + res;
        	mac[j] = (unsigned char)tmp;
	}
}

static int dst_recv_ack(int s)
{
	struct pollfd pfd;
	char buf[4096];
	struct dst_ctl_ack *ack;
	struct nlmsghdr *nlh;
	int err;
	ulog("call dst_recv_ack\n");
	pfd.fd = s;
	pfd.events = POLLIN;
	pfd.revents = 0;

	switch (poll(&pfd, 1, 1000)) {
		case 0:
			ulog("Timed out polling for ack\n");
			return -1;
		case -1:
			ulog_err("Error polling for ack\n");
			return -1;
	}

	memset(buf, 0, sizeof(buf));

	err = recv(s, buf, sizeof(buf), 0);
	if (err == -1) {
		ulog_err("recv from cn failed\n");
		return -1;
	}

	nlh = (struct nlmsghdr *)buf;

	switch (nlh->nlmsg_type) {
		case NLMSG_ERROR:
			ulog("Received error message rather than ack.\n");
			return -1;
		case NLMSG_DONE:
			ack = (struct dst_ctl_ack *)NLMSG_DATA(nlh);

			/*
			 * XXX: worry about matching acks to the right request
			 * and resending if we don't get an ack.
			 */
			if (ack->msg.seq != dst_seq-1) {
				ulog("Uh oh... received ack for wrong seqnum (got %d, expected %d)"
					" - bail for now\n", ack->msg.seq, dst_seq-1);
				return -1;
			}

			if (ack->msg.ack != 1) {
				ulog("Uh oh... received wrong ack (got %d, expected %d)"
					" for right seqnum - bail for now\n", ack->msg.ack, 1);
				return -1;
			}

			ulog("Reply: %d.\n", ack->error);

			errno = -ack->error;

			return errno ? -1 : 0;
		default:
			ulog("Received unrecognised message type %d rather than ack\n", nlh->nlmsg_type);
			return -1;
	}

	return -1;
}

static int dst_netlink_send(int s, struct dst_ctl *ctl, unsigned int len)
{
	struct nlmsghdr *nlh;
	unsigned int size;
	int err;
	char buf[4096];
	struct cn_msg *m;
	
	ulog("call dst_netlink_send\n");
	size = NLMSG_SPACE(sizeof(struct cn_msg) + len);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_seq = dst_seq++;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_len = NLMSG_LENGTH(size - sizeof(*nlh));
	nlh->nlmsg_flags = 0;

	m = NLMSG_DATA(nlh);

	m->id.idx = CN_DST_IDX;
	m->id.val = CN_DST_VAL;

	m->seq = nlh->nlmsg_seq;
	m->ack = 0;
	m->len = len;
	m->flags = 0;

	memcpy(m->data, ctl, len);

	err = send(s, nlh, size, 0);
	if (err == -1) {
		ulog("Failed to send: %s [%d].\n",
			strerror(errno), errno);
		return err;
	}

	return dst_recv_ack(s);
}

//static int dst_sock_init(struct sockaddr_in *sa, char *addr, unsigned short port)
static int dst_sock_init(struct sockaddr_ll *sa, char *addr, unsigned short port)
{
	/*struct hostent *h;
	
	h = gethostbyname(addr);
	if (!h) {
		ulog_err("%s: Failed to get address of '%s'.\n", __func__, addr);
		return -1;
	}
	
	memcpy(&(sa->sin_addr.s_addr), h->h_addr_list[0], 4);
	sa->sin_port = htons(port);
	sa->sin_family = AF_INET;*/
	
	unsigned char mac[6];
	hex2int(addr, &mac[0]);
	memcpy(&(sa->sll_addr), mac, 6);
	ulog("call dst_sock_init\n");
	sa->sll_family = AF_PACKET;
	sa->sll_protocol = htons(ETH_P_ALL);
	sa->sll_ifindex = 2;
	sa->sll_hatype = ARPHRD_ETHER;
	sa->sll_pkttype = PACKET_OTHERHOST;
	sa->sll_halen = ETH_ALEN;
	
	return 0;
}

static int dst_setup_remote_ctl(struct dst_network_ctl *rc, char *addr, int port)
{
	/*int err;
	struct sockaddr_in sa;

	err = dst_sock_init(&sa, addr, port);
	if (err)
		return err;

	memcpy(&rc->addr, &sa, sizeof(sa));
	rc->addr.sa_data_len = sizeof(sa);
	rc->type = SOCK_STREAM;
	rc->proto = IPPROTO_TCP;
	return 0;*/
	
	int err;
	struct sockaddr_ll sa;
	ulog("call dst_setup_remote_ctl\n");
	err = dst_sock_init(&sa, addr, port);
	if (err)
		return err;

	memcpy(&rc->addr, &sa, sizeof(sa));
	rc->addr.sa_data_len = sizeof(sa);
	rc->type = SOCK_RAW;
	rc->proto = ETH_P_ALL;

	return 0;
}

static char *get_next_item(char *p)
{
	int found = 0;
	ulog("call get_next_item\n");
	while (p && *p && !isspace(*p)) {
		p++;
	}

	while (p && *p && isspace(*p)) {
		*p = 0;
		p++;
		found = 1;
	}

	if (!found)
		p = NULL;
	return p;
}

static int dst_security(int fd, struct dst_ctl *ctl, char *sec_file)
{
	/*FILE *f;
	char buf[128], *addr;
	struct sockaddr_ll sin;
	struct dst_secure_user *s = (struct dst_secure_user *)(ctl + 1);
	int err = -EINVAL;

	f = fopen(sec_file, "r");
	if (!f)
		return -1;

	while (1) {
		if (!fgets(buf, sizeof(buf), f))
			break;

		addr = get_next_item(buf);
		if (!addr)
			break;
		get_next_item(addr);

		memset(s, 0, sizeof(struct dst_secure_user));
		memset(&sin, 0, sizeof(struct sockaddr_in));

		s->permissions = strtoul(buf, NULL, 0) & 0xffffffff;

		err = dst_sock_init(&sin, addr, 0);
		if (err)
			break;

		memcpy(&s->addr, &sin, sizeof(struct sockaddr_in));
		s->addr.sa_data_len = sizeof(struct sockaddr_in);

		ulog("%s: client: %s, perm: %x.\n", 
			__func__, addr, s->permissions);
		
		err = dst_netlink_send(fd, ctl, sizeof(struct dst_secure_user) + sizeof(struct dst_ctl));
		if (err)
			break;
	}

	fclose(f);

	return err;*/
		
	FILE *f;
	char buf[128], *addr;
	struct sockaddr_ll sa;
	struct dst_secure_user *s = (struct dst_secure_user *)(ctl + 1);
	int err = -EINVAL;
	ulog("call dst_security\n");
	f = fopen(sec_file, "r");
	if (!f)
		return -1;

	while (1) {
		if (!fgets(buf, sizeof(buf), f))
			break;

		addr = get_next_item(buf);
		if (!addr)
			break;
		get_next_item(addr);

		memset(s, 0, sizeof(struct dst_secure_user));
		memset(&sa, 0, sizeof(struct sockaddr_ll));

		s->permissions = strtoul(buf, NULL, 0) & 0xffffffff;

		err = dst_sock_init(&sa, addr, 0);
		if (err)
			break;

		memcpy(&s->addr, &sa, sizeof(struct sockaddr_ll));
		s->addr.sa_data_len = sizeof(struct sockaddr_ll);

		ulog("%s: client: %s, perm: %x.\n", 
			__func__, addr, s->permissions);
		
		err = dst_netlink_send(fd, ctl, sizeof(struct dst_secure_user) + sizeof(struct dst_ctl));
		if (err)
			break;
	}

	fclose(f);

	return err;
}

static int dst_add_local_export(int fd, struct dst_ctl *ctl, char *disk,
		char *addr, int port)
{
	struct dst_export_ctl *le;
	int err;
	ulog("call dst_add_local_export\n");

	le = (struct dst_export_ctl *)(ctl + 1);

	err = dst_setup_remote_ctl(&le->ctl, addr, port);
	if (err)
		return err;
	
	snprintf(le->device, sizeof(le->device), "%s", disk);

	return dst_netlink_send(fd, ctl, sizeof(struct dst_export_ctl) + sizeof(struct dst_ctl));
}

static int dst_add_remote(int fd, struct dst_ctl *ctl, char *addr, int port)
{
	struct dst_network_ctl *rc;
	int err;
	ulog("call dst_add_remote\n");
	rc = (struct dst_network_ctl *)(ctl + 1);

	err = dst_setup_remote_ctl(rc, addr, port);
	if (err)
		return err;

	return dst_netlink_send(fd, ctl, sizeof(struct dst_ctl) + sizeof(struct dst_network_ctl));
}

static int dst_fill_crypto_key(char *file, void *key)
{
	int fd, err, max_keysize = 1024;
	ulog("call dst_fill_crypto_key\n");
	fd = open(file, O_RDONLY);
	if (fd == -1) {
		ulog_err("Failed to open cipher key file '%s'", file);
		goto err_out_exit;
	}

	err = read(fd, key, max_keysize);
	if (err <= 0) {
		ulog_err("Failed to read cipher key from '%s'", file);
		goto err_out_close;
	}

	close(fd);

	return err;

err_out_close:
	close(fd);
err_out_exit:
	return -1;
}

static int dst_crypto(int fd, struct dst_ctl *ctl, char *cipher, char *cipher_file, char *hash, char *hash_file, int thread_num)
{
	struct dst_crypto_ctl *c = (struct dst_crypto_ctl *)(ctl + 1);
	void *key = c + 1;
	int err;
	
	ulog("call dst_crypto\n");
	memset(c, 0, sizeof(struct dst_crypto_ctl));

	if (cipher && cipher_file) {
		snprintf(c->cipher_algo, sizeof(c->cipher_algo), "%s", cipher);
		err = dst_fill_crypto_key(cipher_file, key);
		if (err <= 0)
			return -1;

		c->cipher_keysize = err;
		key += err;
	}
	
	if (hash && hash_file) {
		snprintf(c->hash_algo, sizeof(c->hash_algo), "%s", hash);
		err = dst_fill_crypto_key(hash_file, key);
		if (err <= 0)
			return -1;

		c->hash_keysize = err;
		key += err;
	}

	c->thread_num = thread_num;

	return dst_netlink_send(fd, ctl, sizeof(struct dst_ctl) + sizeof(struct dst_crypto_ctl) +
			c->cipher_keysize + c->hash_keysize);
}

static void dst_usage(char *p)
{
	ulog("Usage: %s <options>\n"
		"-n storage_name 		: name of the storage: Default: (must provide).\n"
		"-S size 			: size of the storage in bytes: Default: 0 (determined automatically).\n"
		"-d local_disk 			: this disk will be exported: Default: (must provide).\n"
		"-a addr 			: address to connect to or to listen at (if local disk is specified). Default: (must provide).\n"
		"-p port			: port to connect or to listen at. Default: (must provide).\n"
		"-s security_attribute_file	: security attribute file for the exported node: Default: (must provide).\n"
		"-D <del node>			: remove given node. Default: no.\n"
		"-R <start node>		: start given node. Default: no.\n"
		"-c cipher			: cipher algorithm. Default: (must provide).\n"
		"-C cipher_file			: file with cipher key. Default: (must provide).\n"
		"-x hash			: hash algorithm. Default: (must provide).\n"
		"-H hash_file			: file with hash key. Default: (must provide).\n"
		"-t thread_num			: number of crypto threads. Default: 3.\n"
		"-m max_pages			: maximum number of pages in single block IO request. Default: 2.\n"
		"-T trans_scan_timeout		: number of milliseconds between scanning for transactions to resent: Defaukt: 10000.\n"
		"-h <help>			: this help\n"
		, p);
}


int main(int argc, char *argv[])
{
	int ch, port, err, s, del, run, thread_num, max_pages, trans_scan_timeout;
	char *addr, *disk, *st, *sec_file, *cipher_file, *hash_file, *hash, *cipher;
	__u64 size;
	char buf[4096]; /* Should be big enough to contain keys and needed structures */
	struct dst_ctl *ctl;
	struct sockaddr_nl l_local;

	addr = NULL;
	port = -1;
	disk = NULL;
	size = 0;
	st = NULL;
	del = 0;
	sec_file = NULL;
	run = 0;
	cipher_file = NULL;
	hash_file = NULL;
	hash = NULL;
	cipher = NULL;
	thread_num = 3;
	max_pages = 2;
	trans_scan_timeout = 10000;

	while ((ch = getopt(argc, argv, "T:m:t:x:c:C:H:Dn:S:d:a:p:s:hR")) > 0) {
		switch (ch) {
			case 't':
				thread_num = atoi(optarg);
				break;
			case 'c':
				cipher = optarg;
				break;
			case 'C':
				cipher_file = optarg;
				break;
			case 'x':
				hash = optarg;
				break;
			case 'H':
				hash_file = optarg;
				break;
			case 's':
				sec_file = optarg;
				break;
			case 'D':
				del = 1;
				break;
			case 'R':
				run = 1;
				break;
			case 'n':
				st = optarg;
				break;
			case 'S':
				size = strtoull(optarg, NULL, 0);
				break;
			case 'd':
				disk = optarg;
				break;
			case 'a':
				addr = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'm':
				max_pages = atoi(optarg);
				break;
			case 'T':
				trans_scan_timeout = atoi(optarg);
				break;
			default:
				dst_usage(argv[0]);
				return -1;
		}
	}

	if (!st) {
		ulog("Wrong parameters: you have to provide device name.\n");
		dst_usage(argv[0]);
		return -1;
	}

	if (!del && !run) {
		if (!addr || port == -1) {
			ulog("Wrong parameters: addr: %p, port: %d.\n", addr, port);
			dst_usage(argv[0]);
			return -1;
		}
	}

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (s == -1) {
		perror("socket");
		return -1;
	}

	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = 1<<CN_DST_IDX; /* bitmask of requested groups */
	l_local.nl_pid = getpid();

	if (bind(s, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1) {
		perror("bind");
		close(s);
		return -1;
	}

	l_local.nl_groups = CN_DST_IDX;
	if (setsockopt(s, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		&l_local.nl_groups, sizeof(l_local.nl_groups))) {
		perror("setsockopt");
		close(s);
		return -1;
	}

	memset(buf, 0, sizeof(buf));

	ctl = (struct dst_ctl *)buf;

	ctl->max_pages = max_pages;
	ctl->trans_scan_timeout = trans_scan_timeout;
	ctl->size = size;
	snprintf(ctl->name, sizeof(ctl->name), "%s", st);

	ulog("Node: storage: %s, size: 0x%llx.\n", st, size);

	if (del) {
		ctl->cmd = DST_DEL_NODE;
		return dst_netlink_send(s, ctl, sizeof(struct dst_ctl));
	}

	if (disk) {
		ulog("Adding local export node: %s -> %s:%d.", disk, addr, port);
		if (!sec_file)
			ulog(" Warning: no security file, no clients will be allowed to connect.");
		ulog("\n");

		ctl->cmd = DST_ADD_EXPORT;
		err = dst_add_local_export(s, ctl, disk, addr, port);
	} else if (addr) {
		ulog("Adding remote node: %s:%d.\n", addr, port);
		ctl->cmd = DST_ADD_REMOTE;
		err = dst_add_remote(s, ctl, addr, port);
	}

	if (sec_file) {
		ctl->cmd = DST_SECURITY;
		err = dst_security(s, ctl, sec_file);
	}

	if ((cipher && cipher_file) || (hash && hash_file)) {
		ctl->cmd = DST_CRYPTO;
		err = dst_crypto(s, ctl, cipher, cipher_file, hash, hash_file, thread_num);
	}

	if (run) {
		ctl->cmd = DST_START;
		return dst_netlink_send(s, ctl, sizeof(struct dst_ctl));
	}

	ulog_err("Operation completed, err: %d", err);

	close(s);

	return err;
}
