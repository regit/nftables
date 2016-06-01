/*
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <libmnl/libmnl.h>
#include <libnftnl/common.h>
#include <libnftnl/ruleset.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <libnftnl/batch.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <mnl.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <utils.h>
#include <nftables.h>

uint32_t mnl_seqnum_alloc(nft_context_t *nft_ctx)
{
	return nft_ctx->seq++;
}

/* The largest nf_tables netlink message is the set element message, which
 * contains the NFTA_SET_ELEM_LIST_ELEMENTS attribute. This attribute is
 * a nest that describes the set elements. Given that the netlink attribute
 * length (nla_len) is 16 bits, the largest message is a bit larger than
 * 64 KBytes.
 */
#define NFT_NLMSG_MAXSIZE (UINT16_MAX + getpagesize())

static int
nft_mnl_recv(struct mnl_socket *nf_sock, uint32_t seqnum, uint32_t portid,
	     int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	char buf[NFT_NLMSG_MAXSIZE];
	int ret;

	ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seqnum, portid, cb, cb_data);
		if (ret <= 0)
			goto out;

		ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	}
out:
	if (ret < 0 && errno == EAGAIN)
		return 0;

	return ret;
}

static int
nft_mnl_talk(nft_context_t *nft_ctx, const void *data, unsigned int len,
	     int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	uint32_t portid = mnl_socket_get_portid(nft_ctx->nf_sock);

#ifdef DEBUG
	if (debug_level & DEBUG_MNL)
		mnl_nlmsg_fprintf(stdout, data, len, sizeof(struct nfgenmsg));
#endif

	if (mnl_socket_sendto(nft_ctx->nf_sock, data, len) < 0)
		return -1;

	return nft_mnl_recv(nft_ctx->nf_sock, nft_ctx->seq, portid, cb, cb_data);
}

/*
 * Rule-set consistency check across several netlink dumps
 */
static uint16_t nft_genid;

static int genid_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfh = mnl_nlmsg_get_payload(nlh);

	nft_genid = ntohs(nfh->res_id);

	return MNL_CB_OK;
}

void mnl_genid_get(nft_context_t *nft_ctx)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETGEN, AF_UNSPEC, 0, nft_ctx->seq);
	/* Skip error checking, old kernels sets res_id field to zero. */
	nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, genid_cb, NULL);
}

static int check_genid(const struct nlmsghdr *nlh)
{
	struct nfgenmsg *nfh = mnl_nlmsg_get_payload(nlh);

	if (nft_genid != ntohs(nfh->res_id)) {
		errno = EINTR;
		return -1;
	}
	return 0;
}

/*
 * Batching
 */

/* selected batch page is 256 Kbytes long to load ruleset of
 * half a million rules without hitting -EMSGSIZE due to large
 * iovec.
 */
#define BATCH_PAGE_SIZE getpagesize() * 32

void mnl_batch_init(nft_context_t *nft_ctx)
{
	nft_ctx->batch = nftnl_batch_alloc(BATCH_PAGE_SIZE, NFT_NLMSG_MAXSIZE);
	if (nft_ctx->batch == NULL)
		memory_allocation_error();
}

static void mnl_nft_batch_continue(nft_context_t *nft_ctx)
{
	if (nftnl_batch_update(nft_ctx->batch) < 0)
		memory_allocation_error();
}

uint32_t mnl_batch_begin(nft_context_t *nft_ctx)
{
	uint32_t seq = mnl_seqnum_alloc(nft_ctx);

	nftnl_batch_begin(nftnl_batch_buffer(nft_ctx->batch), seq);
	mnl_nft_batch_continue(nft_ctx);

	return seq;
}

void mnl_batch_end(nft_context_t *nft_ctx)
{
	nftnl_batch_end(nftnl_batch_buffer(nft_ctx->batch), mnl_seqnum_alloc(nft_ctx));
	mnl_nft_batch_continue(nft_ctx);
}

bool mnl_batch_ready(nft_context_t *nft_ctx)
{
	/* Check if the batch only contains the initial and trailing batch
	 * messages. In that case, the batch is empty.
	 */
	return nftnl_batch_buffer_len(nft_ctx->batch) !=
	       (NLMSG_HDRLEN + sizeof(struct nfgenmsg)) * 2;
}

void mnl_batch_reset(nft_context_t *nft_ctx)
{
	nftnl_batch_free(nft_ctx->batch);
}

static void mnl_err_list_node_add(struct list_head *err_list, int error,
				  int seqnum)
{
	struct mnl_err *err = xmalloc(sizeof(struct mnl_err));

	err->seqnum = seqnum;
	err->err = error;
	list_add_tail(&err->head, err_list);
}

void mnl_err_list_free(struct mnl_err *err)
{
	list_del(&err->head);
	xfree(err);
}

static int nlbuffsiz;

static void mnl_set_sndbuffer(nft_context_t *nft_ctx)
{
	int newbuffsiz;

	if (nftnl_batch_iovec_len(nft_ctx->batch) * BATCH_PAGE_SIZE <= nlbuffsiz)
		return;

	newbuffsiz = nftnl_batch_iovec_len(nft_ctx->batch) * BATCH_PAGE_SIZE;

	/* Rise sender buffer length to avoid hitting -EMSGSIZE */
	if (setsockopt(mnl_socket_get_fd(nft_ctx->nf_sock), SOL_SOCKET,
		       SO_SNDBUFFORCE,
		       &newbuffsiz, sizeof(socklen_t)) < 0)
		return;

	nlbuffsiz = newbuffsiz;
}

static ssize_t mnl_nft_socket_sendmsg(nft_context_t *nft_ctx)
{
	static const struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK
	};
	uint32_t iov_len = nftnl_batch_iovec_len(nft_ctx->batch);
	struct iovec iov[iov_len];
	struct msghdr msg = {
		.msg_name	= (struct sockaddr *) &snl,
		.msg_namelen	= sizeof(snl),
		.msg_iov	= iov,
		.msg_iovlen	= iov_len,
	};
#ifdef DEBUG
	uint32_t i;
#endif

	mnl_set_sndbuffer(nft_ctx);
	nftnl_batch_iovec(nft_ctx->batch, iov, iov_len);

#ifdef DEBUG
	for (i = 0; i < iov_len; i++) {
		if (debug_level & DEBUG_MNL) {
			mnl_nlmsg_fprintf(stdout,
					  iov[i].iov_base, iov[i].iov_len,
					  sizeof(struct nfgenmsg));
		}
	}
#endif

	return sendmsg(mnl_socket_get_fd(nft_ctx->nf_sock), &msg, 0);
}

int mnl_batch_talk(nft_context_t *nft_ctx, struct list_head *err_list)
{
	int ret, fd = mnl_socket_get_fd(nft_ctx->nf_sock);
	int portid = mnl_socket_get_portid(nft_ctx->nf_sock);
	char rcv_buf[MNL_SOCKET_BUFFER_SIZE];
	fd_set readfds;
	struct timeval tv = {
		.tv_sec		= 0,
		.tv_usec	= 0
	};

	ret = mnl_nft_socket_sendmsg(nft_ctx);
	if (ret == -1)
		return -1;

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	/* receive and digest all the acknowledgments from the kernel. */
	ret = select(fd+1, &readfds, NULL, NULL, &tv);
	if (ret == -1)
		return -1;

	while (ret > 0 && FD_ISSET(fd, &readfds)) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)rcv_buf;

		ret = mnl_socket_recvfrom(nft_ctx->nf_sock, rcv_buf,
					  sizeof(rcv_buf));
		if (ret == -1)
			return -1;

		ret = mnl_cb_run(rcv_buf, ret, 0, portid, NULL, NULL);
		/* Continue on error, make sure we get all acknowledgments */
		if (ret == -1)
			mnl_err_list_node_add(err_list, errno, nlh->nlmsg_seq);

		ret = select(fd+1, &readfds, NULL, NULL, &tv);
		if (ret == -1)
			return -1;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
	}
	return ret;
}

int mnl_nft_rule_batch_add(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
			   unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_rule_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY),
			NLM_F_CREATE | flags, seqnum);

	nftnl_rule_nlmsg_build_payload(nlh, nlr);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

int mnl_nft_rule_batch_replace(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
			       unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_rule_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY),
			NLM_F_REPLACE | flags, seqnum);

	nftnl_rule_nlmsg_build_payload(nlh, nlr);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

int mnl_nft_rule_batch_del(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
			   unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_rule_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_DELRULE,
			nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY),
			0, seqnum);

	nftnl_rule_nlmsg_build_payload(nlh, nlr);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

/*
 * Rule
 */
int mnl_nft_rule_add(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
		     unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY),
			NLM_F_ACK | NLM_F_CREATE | flags, nft_ctx->seq);
	nftnl_rule_nlmsg_build_payload(nlh, nlr);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_rule_delete(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
			unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_DELRULE,
			nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY),
			NLM_F_ACK, nft_ctx->seq);
	nftnl_rule_nlmsg_build_payload(nlh, nlr);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

static int rule_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_rule_list *nlr_list = data;
	struct nftnl_rule *r;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	r = nftnl_rule_alloc();
	if (r == NULL)
		memory_allocation_error();

	if (nftnl_rule_nlmsg_parse(nlh, r) < 0)
		goto err_free;

	nftnl_rule_list_add_tail(r, nlr_list);
	return MNL_CB_OK;

err_free:
	nftnl_rule_free(r);
	return MNL_CB_OK;
}

struct nftnl_rule_list *mnl_nft_rule_dump(nft_context_t *nft_ctx, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nftnl_rule_list *nlr_list;
	int ret;

	nlr_list = nftnl_rule_list_alloc();
	if (nlr_list == NULL)
		memory_allocation_error();

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
				       NLM_F_DUMP, nft_ctx->seq);

	ret = nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, rule_cb, nlr_list);
	if (ret < 0)
		goto err;

	return nlr_list;
err:
	nftnl_rule_list_free(nlr_list);
	return NULL;
}

/*
 * Chain
 */
int mnl_nft_chain_add(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
		      unsigned int flags)

{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN,
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY),
			NLM_F_CREATE | NLM_F_ACK | flags, nft_ctx->seq);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_chain_batch_add(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
			    unsigned int flags, uint32_t seqnum)

{
	struct nlmsghdr *nlh;

	nlh = nftnl_chain_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_NEWCHAIN,
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY),
			NLM_F_CREATE | flags, seqnum);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

int mnl_nft_chain_delete(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
			 unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_DELCHAIN,
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY),
			NLM_F_ACK, nft_ctx->seq);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_chain_batch_del(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
			    unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_chain_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_DELCHAIN,
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY),
			NLM_F_ACK, seqnum);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

static int chain_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_chain_list *nlc_list = data;
	struct nftnl_chain *c;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	c = nftnl_chain_alloc();
	if (c == NULL)
		memory_allocation_error();

	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		goto err_free;

	nftnl_chain_list_add_tail(c, nlc_list);
	return MNL_CB_OK;

err_free:
	nftnl_chain_free(c);
	return MNL_CB_OK;
}

struct nftnl_chain_list *mnl_nft_chain_dump(nft_context_t *nft_ctx, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nftnl_chain_list *nlc_list;
	int ret;

	nlc_list = nftnl_chain_list_alloc();
	if (nlc_list == NULL)
		memory_allocation_error();

	nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, family,
					NLM_F_DUMP, nft_ctx->seq);

	ret = nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, chain_cb, nlc_list);
	if (ret < 0)
		goto err;

	return nlc_list;
err:
	nftnl_chain_list_free(nlc_list);
	return NULL;
}

static int chain_get_cb(const struct nlmsghdr *nlh, void *data)
{
	nftnl_chain_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

int mnl_nft_chain_get(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN,
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY),
			NLM_F_ACK | flags, nft_ctx->seq);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, chain_get_cb, nlc);
}

/*
 * Table
 */
int mnl_nft_table_add(nft_context_t *nft_ctx, struct nftnl_table *nlt,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE,
			nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY),
			NLM_F_ACK | flags, nft_ctx->seq);
	nftnl_table_nlmsg_build_payload(nlh, nlt);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_table_batch_add(nft_context_t *nft_ctx, struct nftnl_table *nlt,
			    unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_table_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_NEWTABLE,
			nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY),
			flags, seqnum);
	nftnl_table_nlmsg_build_payload(nlh, nlt);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

int mnl_nft_table_delete(nft_context_t *nft_ctx, struct nftnl_table *nlt,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_DELTABLE,
			nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY),
			NLM_F_ACK, nft_ctx->seq);
	nftnl_table_nlmsg_build_payload(nlh, nlt);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_table_batch_del(nft_context_t *nft_ctx, struct nftnl_table *nlt,
			    unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_table_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_DELTABLE,
			nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY),
			NLM_F_ACK, seqnum);
	nftnl_table_nlmsg_build_payload(nlh, nlt);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

static int table_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_table_list *nlt_list = data;
	struct nftnl_table *t;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	t = nftnl_table_alloc();
	if (t == NULL)
		memory_allocation_error();

	if (nftnl_table_nlmsg_parse(nlh, t) < 0)
		goto err_free;

	nftnl_table_list_add_tail(t, nlt_list);
	return MNL_CB_OK;

err_free:
	nftnl_table_free(t);
	return MNL_CB_OK;
}

struct nftnl_table_list *mnl_nft_table_dump(nft_context_t *nft_ctx, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nftnl_table_list *nlt_list;
	int ret;

	nlt_list = nftnl_table_list_alloc();
	if (nlt_list == NULL)
		memory_allocation_error();

	nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, family,
					NLM_F_DUMP, nft_ctx->seq);

	ret = nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, table_cb, nlt_list);
	if (ret < 0)
		goto err;

	return nlt_list;
err:
	nftnl_table_list_free(nlt_list);
	return NULL;
}

static int table_get_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_table *t = data;

	nftnl_table_nlmsg_parse(nlh, t);
	return MNL_CB_OK;
}

int mnl_nft_table_get(nft_context_t *nft_ctx, struct nftnl_table *nlt,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE,
					nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY),
					NLM_F_ACK, nft_ctx->seq);
	nftnl_table_nlmsg_build_payload(nlh, nlt);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, table_get_cb, nlt);
}

/*
 * Set
 */
static int set_add_cb(const struct nlmsghdr *nlh, void *data)
{
	nftnl_set_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

int mnl_nft_set_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
		    unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_NEWSET,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			NLM_F_CREATE | NLM_F_ACK | flags, nft_ctx->seq);
	nftnl_set_nlmsg_build_payload(nlh, nls);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, set_add_cb, nls);
}

int mnl_nft_set_delete(nft_context_t *nft_ctx, struct nftnl_set *nls,
		       unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_DELSET,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			flags|NLM_F_ACK, nft_ctx->seq);
	nftnl_set_nlmsg_build_payload(nlh, nls);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_set_batch_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
			  unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_set_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_NEWSET,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			NLM_F_CREATE | flags, seqnum);
	nftnl_set_nlmsg_build_payload(nlh, nls);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

int mnl_nft_set_batch_del(nft_context_t *nft_ctx, struct nftnl_set *nls,
			  unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_set_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_DELSET,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			flags, seqnum);
	nftnl_set_nlmsg_build_payload(nlh, nls);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

static int set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_set_list *nls_list = data;
	struct nftnl_set *s;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	s = nftnl_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	if (nftnl_set_nlmsg_parse(nlh, s) < 0)
		goto err_free;

	nftnl_set_list_add_tail(s, nls_list);
	return MNL_CB_OK;

err_free:
	nftnl_set_free(s);
	return MNL_CB_OK;
}

struct nftnl_set_list *
mnl_nft_set_dump(nft_context_t *nft_ctx, int family, const char *table)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nftnl_set *s;
	struct nftnl_set_list *nls_list;
	int ret;

	s = nftnl_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET, family,
				      NLM_F_DUMP|NLM_F_ACK, nft_ctx->seq);
	if (table != NULL)
		nftnl_set_set(s, NFTNL_SET_TABLE, table);
	nftnl_set_nlmsg_build_payload(nlh, s);
	nftnl_set_free(s);

	nls_list = nftnl_set_list_alloc();
	if (nls_list == NULL)
		memory_allocation_error();

	ret = nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, set_cb, nls_list);
	if (ret < 0)
		goto err;

	return nls_list;
err:
	nftnl_set_list_free(nls_list);
	return NULL;
}

static int set_get_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_set *s = data;

	nftnl_set_nlmsg_parse(nlh, s);
	return MNL_CB_OK;
}

int mnl_nft_set_get(nft_context_t *nft_ctx, struct nftnl_set *nls)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			NLM_F_ACK, nft_ctx->seq);
	nftnl_set_nlmsg_build_payload(nlh, nls);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, set_get_cb, nls);
}

/*
 * Set elements
 */
int mnl_nft_setelem_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
			unsigned int flags)
{
	char buf[NFT_NLMSG_MAXSIZE];
	struct nlmsghdr *nlh;
	struct nftnl_set_elems_iter *iter;
	int ret, err;

	iter = nftnl_set_elems_iter_create(nls);
	if (iter == NULL)
		memory_allocation_error();

	do {
		nlh = nftnl_set_elem_nlmsg_build_hdr(buf, NFT_MSG_NEWSETELEM,
				nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
				NLM_F_CREATE | NLM_F_ACK | flags, nft_ctx->seq);
		ret = nftnl_set_elems_nlmsg_build_payload_iter(nlh, iter);
		err = nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
	} while (ret > 0 && err >= 0);

	nftnl_set_elems_iter_destroy(iter);

	return err;
}

int mnl_nft_setelem_delete(nft_context_t *nft_ctx, struct nftnl_set *nls,
			   unsigned int flags)
{
	char buf[NFT_NLMSG_MAXSIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_set_elem_nlmsg_build_hdr(buf, NFT_MSG_DELSETELEM,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			NLM_F_ACK, nft_ctx->seq);
	nftnl_set_elems_nlmsg_build_payload(nlh, nls);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, NULL, NULL);
}

static int set_elem_cb(const struct nlmsghdr *nlh, void *data)
{
	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	nftnl_set_elems_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

int mnl_nft_setelem_batch_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
			      unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;
	struct nftnl_set_elems_iter *iter;
	int ret;

	iter = nftnl_set_elems_iter_create(nls);
	if (iter == NULL)
		memory_allocation_error();

	do {
		nlh = nftnl_set_elem_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
				NFT_MSG_NEWSETELEM,
				nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
				NLM_F_CREATE | flags, seqnum);
		ret = nftnl_set_elems_nlmsg_build_payload_iter(nlh, iter);
		mnl_nft_batch_continue(nft_ctx);
	} while (ret > 0);

	nftnl_set_elems_iter_destroy(iter);

	return 0;
}

int mnl_nft_setelem_batch_del(nft_context_t *nft_ctx, struct nftnl_set *nls,
			      unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_set_elem_nlmsg_build_hdr(nftnl_batch_buffer(nft_ctx->batch),
			NFT_MSG_DELSETELEM,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			0, seqnum);
	nftnl_set_elems_nlmsg_build_payload(nlh, nls);
	mnl_nft_batch_continue(nft_ctx);

	return 0;
}

int mnl_nft_setelem_get(nft_context_t *nft_ctx, struct nftnl_set *nls)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_set_elem_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM,
			nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
			NLM_F_DUMP|NLM_F_ACK, nft_ctx->seq);
	nftnl_set_nlmsg_build_payload(nlh, nls);

	return nft_mnl_talk(nft_ctx, nlh, nlh->nlmsg_len, set_elem_cb, nls);
}

/*
 * ruleset
 */
struct nftnl_ruleset *mnl_nft_ruleset_dump(nft_context_t *nft_ctx,
					 uint32_t family)
{
	struct nftnl_ruleset *rs;
	struct nftnl_table_list *t;
	struct nftnl_chain_list *c;
	struct nftnl_set_list *sl;
	struct nftnl_set_list_iter *i;
	struct nftnl_set *s;
	struct nftnl_rule_list *r;
	int ret = 0;

	rs = nftnl_ruleset_alloc();
	if (rs == NULL)
		memory_allocation_error();

	t = mnl_nft_table_dump(nft_ctx, family);
	if (t == NULL)
		goto err;

	nftnl_ruleset_set(rs, NFTNL_RULESET_TABLELIST, t);

	c = mnl_nft_chain_dump(nft_ctx, family);
	if (c == NULL)
		goto err;

	nftnl_ruleset_set(rs, NFTNL_RULESET_CHAINLIST, c);

	sl = mnl_nft_set_dump(nft_ctx, family, NULL);
	if (sl == NULL)
		goto err;

	i = nftnl_set_list_iter_create(sl);
	s = nftnl_set_list_iter_next(i);
	while (s != NULL) {
		ret = mnl_nft_setelem_get(nft_ctx, s);
		if (ret < 0)
			goto err;

		s = nftnl_set_list_iter_next(i);
	}
	nftnl_set_list_iter_destroy(i);

	nftnl_ruleset_set(rs, NFTNL_RULESET_SETLIST, sl);

	r = mnl_nft_rule_dump(nft_ctx, family);
	if (r == NULL)
		goto err;

	nftnl_ruleset_set(rs, NFTNL_RULESET_RULELIST, r);

	return rs;
err:
	nftnl_ruleset_free(rs);
	return NULL;
}

/*
 * events
 */
#define NFTABLES_NLEVENT_BUFSIZ	(1 << 24)

int mnl_nft_event_listener(struct mnl_socket *nf_sock,
			   int (*cb)(const struct nlmsghdr *nlh, void *data),
			   void *cb_data)
{
	/* Set netlink socket buffer size to 16 Mbytes to reduce chances of
 	 * message loss due to ENOBUFS.
	 */
	unsigned int bufsiz = NFTABLES_NLEVENT_BUFSIZ;
	char buf[NFT_NLMSG_MAXSIZE];
	int ret;

	ret = setsockopt(mnl_socket_get_fd(nf_sock), SOL_SOCKET, SO_RCVBUFFORCE,
			 &bufsiz, sizeof(socklen_t));
        if (ret < 0) {
		/* If this doesn't work, try to reach the system wide maximum
		 * (or whatever the user requested).
		 */
                ret = setsockopt(mnl_socket_get_fd(nf_sock), SOL_SOCKET,
				 SO_RCVBUF, &bufsiz, sizeof(socklen_t));
		printf("# Cannot set up netlink socket buffer size to %u bytes, falling back to %u bytes\n",
		       NFTABLES_NLEVENT_BUFSIZ, bufsiz);
	}

	while (1) {
		ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
		if (ret < 0) {
			if (errno == ENOBUFS) {
				printf("# ERROR: We lost some netlink events!\n");
				continue;
			}
			fprintf(stdout, "# ERROR: %s\n", strerror(errno));
			break;
		}
		ret = mnl_cb_run(buf, ret, 0, 0, cb, cb_data);
		if (ret <= 0)
			break;
	}
	return ret;
}

static void nft_mnl_batch_put(char *buf, uint16_t type, uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = NFNL_SUBSYS_NFTABLES;
}

bool mnl_batch_supported(nft_context_t *nft_ctx)
{
	struct mnl_nlmsg_batch *b;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret;

	b = mnl_nlmsg_batch_start(buf, sizeof(buf));

	nft_mnl_batch_put(mnl_nlmsg_batch_current(b), NFNL_MSG_BATCH_BEGIN,
			  nft_ctx->seq++);
	mnl_nlmsg_batch_next(b);

	nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
				NFT_MSG_NEWSET, AF_INET,
				NLM_F_ACK, nft_ctx->seq++);
	mnl_nlmsg_batch_next(b);

	nft_mnl_batch_put(mnl_nlmsg_batch_current(b), NFNL_MSG_BATCH_END,
			  nft_ctx->seq++);
	mnl_nlmsg_batch_next(b);

	ret = mnl_socket_sendto(nft_ctx->nf_sock, mnl_nlmsg_batch_head(b),
				mnl_nlmsg_batch_size(b));
	if (ret < 0)
		goto err;

	mnl_nlmsg_batch_stop(b);

	ret = mnl_socket_recvfrom(nft_ctx->nf_sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0,
				 mnl_socket_get_portid(nft_ctx->nf_sock),
				 NULL, NULL);
		if (ret <= 0)
			break;

		ret = mnl_socket_recvfrom(nft_ctx->nf_sock, buf, sizeof(buf));
	}

	/* We're sending an incomplete message to see if the kernel supports
	 * set messages in batches. EINVAL means that we sent an incomplete
	 * message with missing attributes. The kernel just ignores messages
	 * that we cannot include in the batch.
	 */
	return (ret == -1 && errno == EINVAL) ? true : false;
err:
	mnl_nlmsg_batch_stop(b);
	return ret;
}
