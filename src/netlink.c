/*
 * Copyright (c) 2008-2012 Patrick McHardy <kaber@trash.net>
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <libnftnl/table.h>
#include <libnftnl/trace.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <libnftnl/udata.h>
#include <libnftnl/common.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <netlink.h>
#include <mnl.h>
#include <expression.h>
#include <statement.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>
#include <iface.h>

static struct mnl_socket *nf_sock;
static struct mnl_socket *nf_mon_sock;

const struct input_descriptor indesc_netlink = {
	.name	= "netlink",
	.type	= INDESC_NETLINK,
};

const struct location netlink_location = {
	.indesc	= &indesc_netlink,
};

static struct mnl_socket *nfsock_open(void)
{
	struct mnl_socket *s;

	s = mnl_socket_open(NETLINK_NETFILTER);
	if (s == NULL)
		netlink_init_error();
	return s;
}

static void __init netlink_open_sock(void)
{
	nf_sock = nfsock_open();
	fcntl(mnl_socket_get_fd(nf_sock), F_SETFL, O_NONBLOCK);
}

static void __exit netlink_close_sock(void)
{
	if (nf_sock)
		mnl_socket_close(nf_sock);
	if (nf_mon_sock)
		mnl_socket_close(nf_mon_sock);
}

void netlink_restart(void)
{
	netlink_close_sock();
	netlink_open_sock();
}

void netlink_genid_get(void)
{
	mnl_genid_get(nf_sock);
}

static void netlink_open_mon_sock(void)
{
	nf_mon_sock = nfsock_open();
}

void __noreturn __netlink_abi_error(const char *file, int line,
				    const char *reason)
{
	fprintf(stderr, "E: Contact urgently your Linux kernel vendor. "
		"Netlink ABI is broken: %s:%d %s\n", file, line, reason);
	exit(NFT_EXIT_FAILURE);
}

int netlink_io_error(struct netlink_ctx *ctx, const struct location *loc,
		     const char *fmt, ...)
{
	struct error_record *erec;
	va_list ap;

	if (loc == NULL)
		loc = &netlink_location;

	va_start(ap, fmt);
	erec = erec_vcreate(EREC_ERROR, loc, fmt, ap);
	va_end(ap);
	erec_queue(erec, ctx->msgs);
	return -1;
}

void __noreturn __netlink_init_error(const char *filename, int line,
				     const char *reason)
{
	fprintf(stderr, "%s:%d: Unable to initialize Netlink socket: %s\n",
		filename, line, reason);
	exit(NFT_EXIT_NONL);
}

struct nftnl_table *alloc_nftnl_table(const struct handle *h)
{
	struct nftnl_table *nlt;

	nlt = nftnl_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();

	nftnl_table_set_u32(nlt, NFTNL_TABLE_FAMILY, h->family);
	if (h->table != NULL)
		nftnl_table_set(nlt, NFTNL_TABLE_NAME, h->table);

	return nlt;
}

struct nftnl_chain *alloc_nftnl_chain(const struct handle *h)
{
	struct nftnl_chain *nlc;

	nlc = nftnl_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();

	nftnl_chain_set_u32(nlc, NFTNL_CHAIN_FAMILY, h->family);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_TABLE, h->table);
	if (h->handle.id != 0)
		nftnl_chain_set_u64(nlc, NFTNL_CHAIN_HANDLE, h->handle.id);
	if (h->chain != NULL)
		nftnl_chain_set_str(nlc, NFTNL_CHAIN_NAME, h->chain);

	return nlc;
}

struct nftnl_rule *alloc_nftnl_rule(const struct handle *h)
{
	struct nftnl_rule *nlr;

	nlr = nftnl_rule_alloc();
	if (nlr == NULL)
		memory_allocation_error();

	nftnl_rule_set_u32(nlr, NFTNL_RULE_FAMILY, h->family);
	nftnl_rule_set_str(nlr, NFTNL_RULE_TABLE, h->table);
	if (h->chain != NULL)
		nftnl_rule_set_str(nlr, NFTNL_RULE_CHAIN, h->chain);
	if (h->handle.id)
		nftnl_rule_set_u64(nlr, NFTNL_RULE_HANDLE, h->handle.id);
	if (h->position.id)
		nftnl_rule_set_u64(nlr, NFTNL_RULE_POSITION, h->position.id);

	return nlr;
}

struct nftnl_expr *alloc_nft_expr(const char *name)
{
	struct nftnl_expr *nle;

	nle = nftnl_expr_alloc(name);
	if (nle == NULL)
		memory_allocation_error();

	return nle;
}

struct nftnl_set *alloc_nftnl_set(const struct handle *h)
{
	struct nftnl_set *nls;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table);
	if (h->set != NULL)
		nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set);
	if (h->set_id)
		nftnl_set_set_u32(nls, NFTNL_SET_ID, h->set_id);

	return nls;
}

static struct nftnl_set_elem *alloc_nftnl_setelem(const struct expr *expr)
{
	const struct expr *elem, *key, *data;
	struct nftnl_set_elem *nlse;
	struct nft_data_linearize nld;
	struct nftnl_udata_buf *udbuf;

	nlse = nftnl_set_elem_alloc();
	if (nlse == NULL)
		memory_allocation_error();

	data = NULL;
	if (expr->ops->type == EXPR_MAPPING) {
		elem = expr->left;
		if (!(expr->flags & EXPR_F_INTERVAL_END))
			data = expr->right;
	} else {
		elem = expr;
	}
	key = elem->key;

	netlink_gen_data(key, &nld);
	nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_KEY, &nld.value, nld.len);
	if (elem->timeout)
		nftnl_set_elem_set_u64(nlse, NFTNL_SET_ELEM_TIMEOUT,
				       elem->timeout);
	if (elem->comment) {
		udbuf = nftnl_udata_buf_alloc(NFT_USERDATA_MAXLEN);
		if (!udbuf)
			memory_allocation_error();
		if (!nftnl_udata_put_strz(udbuf, UDATA_TYPE_COMMENT,
					  elem->comment))
			memory_allocation_error();
		nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_USERDATA,
				   nftnl_udata_buf_data(udbuf),
				   nftnl_udata_buf_len(udbuf));
		nftnl_udata_buf_free(udbuf);
	}

	if (data != NULL) {
		netlink_gen_data(data, &nld);
		switch (data->ops->type) {
		case EXPR_VERDICT:
			nftnl_set_elem_set_u32(nlse, NFTNL_SET_ELEM_VERDICT,
					       data->verdict);
			if (data->chain != NULL)
				nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_CHAIN,
						   nld.chain, strlen(nld.chain));
			break;
		case EXPR_VALUE:
			nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_DATA,
					   nld.value, nld.len);
			break;
		default:
			BUG("unexpected set element expression\n");
			break;
		}
	}

	if (expr->flags & EXPR_F_INTERVAL_END)
		nftnl_set_elem_set_u32(nlse, NFTNL_SET_ELEM_FLAGS,
				       NFT_SET_ELEM_INTERVAL_END);

	return nlse;
}

void netlink_gen_raw_data(const mpz_t value, enum byteorder byteorder,
			  unsigned int len, struct nft_data_linearize *data)
{
	assert(len > 0);
	mpz_export_data(data->value, value, byteorder, len);
	data->len = len;
}

static void netlink_gen_concat_data(const struct expr *expr,
				    struct nft_data_linearize *nld)
{
	const struct expr *i;
	unsigned int len, offset;

	len = expr->len / BITS_PER_BYTE;
	if (1) {
		unsigned char data[len];

		memset(data, 0, sizeof(data));
		offset = 0;
		list_for_each_entry(i, &expr->expressions, list) {
			assert(i->ops->type == EXPR_VALUE);
			mpz_export_data(data + offset, i->value, i->byteorder,
					i->len / BITS_PER_BYTE);
			offset += netlink_padded_len(i->len) / BITS_PER_BYTE;
		}

		memcpy(nld->value, data, len);
		nld->len = len;
	}
}

static void netlink_gen_constant_data(const struct expr *expr,
				      struct nft_data_linearize *data)
{
	assert(expr->ops->type == EXPR_VALUE);
	netlink_gen_raw_data(expr->value, expr->byteorder,
			     div_round_up(expr->len, BITS_PER_BYTE), data);
}

static void netlink_gen_verdict(const struct expr *expr,
				struct nft_data_linearize *data)
{
	data->verdict = expr->verdict;

	switch (expr->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		strncpy(data->chain, expr->chain, NFT_CHAIN_MAXNAMELEN);
		data->chain[NFT_CHAIN_MAXNAMELEN-1] = '\0';
		break;
	}
}

void netlink_gen_data(const struct expr *expr, struct nft_data_linearize *data)
{
	switch (expr->ops->type) {
	case EXPR_VALUE:
		return netlink_gen_constant_data(expr, data);
	case EXPR_CONCAT:
		return netlink_gen_concat_data(expr, data);
	case EXPR_VERDICT:
		return netlink_gen_verdict(expr, data);
	default:
		BUG("invalid data expression type %s\n", expr->ops->name);
	}
}

struct expr *netlink_alloc_value(const struct location *loc,
				 const struct nft_data_delinearize *nld)
{
	return constant_expr_alloc(loc, &invalid_type, BYTEORDER_INVALID,
				   nld->len * BITS_PER_BYTE, nld->value);
}

static struct expr *netlink_alloc_verdict(const struct location *loc,
					  const struct nft_data_delinearize *nld)
{
	char *chain;

	switch (nld->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		chain = xstrdup(nld->chain);
		break;
	default:
		chain = NULL;
		break;
	}

	return verdict_expr_alloc(loc, nld->verdict, chain);
}

struct expr *netlink_alloc_data(const struct location *loc,
				const struct nft_data_delinearize *nld,
				enum nft_registers dreg)
{
	switch (dreg) {
	case NFT_REG_VERDICT:
		return netlink_alloc_verdict(loc, nld);
	default:
		return netlink_alloc_value(loc, nld);
	}
}

int netlink_add_rule_batch(struct netlink_ctx *ctx,
			   const struct handle *h,
		           const struct rule *rule, uint32_t flags)
{
	struct nftnl_rule *nlr;
	int err;

	nlr = alloc_nftnl_rule(&rule->handle);
	netlink_linearize_rule(ctx, nlr, rule);
	err = mnl_nft_rule_batch_add(nlr, flags | NLM_F_EXCL, ctx->seqnum);
	nftnl_rule_free(nlr);
	if (err < 0)
		netlink_io_error(ctx, &rule->location,
				 "Could not add rule to batch: %s",
				 strerror(errno));
	return err;
}

int netlink_replace_rule_batch(struct netlink_ctx *ctx, const struct handle *h,
			       const struct rule *rule,
			       const struct location *loc)
{
	struct nftnl_rule *nlr;
	int err;

	nlr = alloc_nftnl_rule(&rule->handle);
	netlink_linearize_rule(ctx, nlr, rule);
	err = mnl_nft_rule_batch_replace(nlr, 0, ctx->seqnum);
	nftnl_rule_free(nlr);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not replace rule to batch: %s",
				 strerror(errno));
	return err;
}

int netlink_add_rule_list(struct netlink_ctx *ctx, const struct handle *h,
			  const struct list_head *rule_list)
{
	struct rule *rule;

	list_for_each_entry(rule, rule_list, list) {
		if (netlink_add_rule_batch(ctx, &rule->handle, rule,
					   NLM_F_APPEND) < 0)
			return -1;
	}
	return 0;
}

int netlink_del_rule_batch(struct netlink_ctx *ctx, const struct handle *h,
			   const struct location *loc)
{
	struct nftnl_rule *nlr;
	int err;

	nlr = alloc_nftnl_rule(h);
	err = mnl_nft_rule_batch_del(nlr, 0, ctx->seqnum);
	nftnl_rule_free(nlr);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete rule to batch: %s",
				 strerror(errno));
	return err;
}

void netlink_dump_rule(const struct nftnl_rule *nlr)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nftnl_rule_snprintf(buf, sizeof(buf), nlr, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

void netlink_dump_expr(const struct nftnl_expr *nle)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nftnl_expr_snprintf(buf, sizeof(buf), nle, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

static int list_rule_cb(struct nftnl_rule *nlr, void *arg)
{
	struct netlink_ctx *ctx = arg;
	const struct handle *h = ctx->data;
	struct rule *rule;
	const char *table, *chain;
	uint32_t family;

	family = nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY);
	table  = nftnl_rule_get_str(nlr, NFTNL_RULE_TABLE);
	chain  = nftnl_rule_get_str(nlr, NFTNL_RULE_CHAIN);

	if (h->family != family ||
	    strcmp(table, h->table) != 0 ||
	    (h->chain && strcmp(chain, h->chain) != 0))
		return 0;

	netlink_dump_rule(nlr);
	rule = netlink_delinearize_rule(ctx, nlr);
	list_add_tail(&rule->list, &ctx->list);

	return 0;
}

static int netlink_list_rules(struct netlink_ctx *ctx, const struct handle *h,
			      const struct location *loc)
{
	struct nftnl_rule_list *rule_cache;

	rule_cache = mnl_nft_rule_dump(nf_sock, h->family);
	if (rule_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive rules from kernel: %s",
					strerror(errno));
	}

	ctx->data = h;
	nftnl_rule_list_foreach(rule_cache, list_rule_cb, ctx);
	nftnl_rule_list_free(rule_cache);
	return 0;
}

static int netlink_flush_rules(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc)
{
	return netlink_del_rule_batch(ctx, h, loc);
}

void netlink_dump_chain(const struct nftnl_chain *nlc)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nftnl_chain_snprintf(buf, sizeof(buf), nlc, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

static int netlink_add_chain_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
				    const struct location *loc,
				    const struct chain *chain, bool excl)
{
	struct nftnl_chain *nlc;
	int err;

	nlc = alloc_nftnl_chain(h);
	if (chain != NULL) {
		if (chain->flags & CHAIN_F_BASECHAIN) {
			nftnl_chain_set_u32(nlc, NFTNL_CHAIN_HOOKNUM,
					    chain->hooknum);
			nftnl_chain_set_s32(nlc, NFTNL_CHAIN_PRIO,
					    chain->priority);
			nftnl_chain_set_str(nlc, NFTNL_CHAIN_TYPE,
					    chain->type);
		}
		if (chain->policy != -1)
			nftnl_chain_set_u32(nlc, NFTNL_CHAIN_POLICY,
					    chain->policy);
	}

	netlink_dump_chain(nlc);
	err = mnl_nft_chain_add(nf_sock, nlc, excl ? NLM_F_EXCL : 0);
	nftnl_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add chain: %s",
				 strerror(errno));
	return err;
}

static int netlink_add_chain_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc,
				   const struct chain *chain, bool excl)
{
	struct nftnl_chain *nlc;
	int err;

	nlc = alloc_nftnl_chain(h);
	if (chain != NULL) {
		if (chain->flags & CHAIN_F_BASECHAIN) {
			nftnl_chain_set_u32(nlc, NFTNL_CHAIN_HOOKNUM,
					    chain->hooknum);
			nftnl_chain_set_s32(nlc, NFTNL_CHAIN_PRIO,
					    chain->priority);
			nftnl_chain_set_str(nlc, NFTNL_CHAIN_TYPE,
					    chain->type);
		}
		if (chain->policy != -1)
			nftnl_chain_set_u32(nlc, NFTNL_CHAIN_POLICY,
					    chain->policy);
		if (chain->dev != NULL)
			nftnl_chain_set_str(nlc, NFTNL_CHAIN_DEV,
					    chain->dev);
	}

	netlink_dump_chain(nlc);
	err = mnl_nft_chain_batch_add(nlc, excl ? NLM_F_EXCL : 0,
				      ctx->seqnum);
	nftnl_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add chain: %s",
				 strerror(errno));
	return err;
}

int netlink_add_chain(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc, const struct chain *chain,
		      bool excl)
{
	if (ctx->batch_supported)
		return netlink_add_chain_batch(ctx, h, loc, chain, excl);
	else
		return netlink_add_chain_compat(ctx, h, loc, chain, excl);
}

static int netlink_rename_chain_compat(struct netlink_ctx *ctx,
				       const struct handle *h,
				       const struct location *loc,
				       const char *name)
{
	struct nftnl_chain *nlc;
	int err;

	nlc = alloc_nftnl_chain(h);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_NAME, name);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_add(nf_sock, nlc, 0);
	nftnl_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not rename chain: %s",
				 strerror(errno));
	return err;
}

static int netlink_rename_chain_batch(struct netlink_ctx *ctx,
				      const struct handle *h,
				      const struct location *loc,
				      const char *name)
{
	struct nftnl_chain *nlc;
	int err;

	nlc = alloc_nftnl_chain(h);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_NAME, name);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_batch_add(nlc, 0, ctx->seqnum);
	nftnl_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not rename chain: %s",
				 strerror(errno));
	return err;
}

int netlink_rename_chain(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc, const char *name)
{
	if (ctx->batch_supported)
		return netlink_rename_chain_batch(ctx, h, loc, name);
	else
		return netlink_rename_chain_compat(ctx, h, loc, name);
}

static int netlink_del_chain_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
				    const struct location *loc)
{
	struct nftnl_chain *nlc;
	int err;

	nlc = alloc_nftnl_chain(h);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_delete(nf_sock, nlc, 0);
	nftnl_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete chain: %s",
				 strerror(errno));
	return err;
}

static int netlink_del_chain_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc)
{
	struct nftnl_chain *nlc;
	int err;

	nlc = alloc_nftnl_chain(h);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_batch_del(nlc, 0, ctx->seqnum);
	nftnl_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete chain: %s",
				 strerror(errno));
	return err;
}

int netlink_delete_chain(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc)
{
	if (ctx->batch_supported)
		return netlink_del_chain_batch(ctx, h, loc);
	else
		return netlink_del_chain_compat(ctx, h, loc);
}

static struct chain *netlink_delinearize_chain(struct netlink_ctx *ctx,
					       const struct nftnl_chain *nlc)
{
	struct chain *chain;

	chain = chain_alloc(nftnl_chain_get_str(nlc, NFTNL_CHAIN_NAME));
	chain->handle.family =
		nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY);
	chain->handle.table  =
		xstrdup(nftnl_chain_get_str(nlc, NFTNL_CHAIN_TABLE));
	chain->handle.handle.id =
		nftnl_chain_get_u64(nlc, NFTNL_CHAIN_HANDLE);

	if (nftnl_chain_is_set(nlc, NFTNL_CHAIN_HOOKNUM) &&
	    nftnl_chain_is_set(nlc, NFTNL_CHAIN_PRIO) &&
	    nftnl_chain_is_set(nlc, NFTNL_CHAIN_TYPE) &&
	    nftnl_chain_is_set(nlc, NFTNL_CHAIN_POLICY)) {
		chain->hooknum       =
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_HOOKNUM);
		chain->hookstr       =
			hooknum2str(chain->handle.family, chain->hooknum);
		chain->priority      =
			nftnl_chain_get_s32(nlc, NFTNL_CHAIN_PRIO);
		chain->type          =
			xstrdup(nftnl_chain_get_str(nlc, NFTNL_CHAIN_TYPE));
		chain->policy          =
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_POLICY);
		if (nftnl_chain_is_set(nlc, NFTNL_CHAIN_DEV)) {
			chain->dev	=
				xstrdup(nftnl_chain_get_str(nlc, NFTNL_CHAIN_DEV));
		}
		chain->flags        |= CHAIN_F_BASECHAIN;
	}

	return chain;
}

static int list_chain_cb(struct nftnl_chain *nlc, void *arg)
{
	struct netlink_ctx *ctx = arg;
	const struct handle *h = ctx->data;
	const char *table;
	const char *name;
	struct chain *chain;
	uint32_t family;

	table  = nftnl_chain_get_str(nlc, NFTNL_CHAIN_TABLE);
	name   = nftnl_chain_get_str(nlc, NFTNL_CHAIN_NAME);
	family = nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY);

	if (h->family != family || strcmp(table, h->table) != 0)
		return 0;
	if (h->chain && strcmp(name, h->chain) != 0)
		return 0;

	chain = netlink_delinearize_chain(ctx, nlc);
	list_add_tail(&chain->list, &ctx->list);

	return 0;
}

int netlink_list_chains(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	struct nftnl_chain_list *chain_cache;
	struct chain *chain;

	chain_cache = mnl_nft_chain_dump(nf_sock, h->family);
	if (chain_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive chains from kernel: %s",
					strerror(errno));
	}

	ctx->data = h;
	nftnl_chain_list_foreach(chain_cache, list_chain_cb, ctx);
	nftnl_chain_list_free(chain_cache);

	/* Caller wants all existing chains */
	if (h->chain == NULL)
		return 0;

	/* Check if this chain exists, otherwise return an error */
	list_for_each_entry(chain, &ctx->list, list) {
		if (strcmp(chain->handle.chain, h->chain) == 0)
			return 0;
	}

	return netlink_io_error(ctx, NULL,
				"Could not find chain `%s' in table `%s': %s",
				h->chain, h->table,
				strerror(ENOENT));
}

int netlink_get_chain(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc)
{
	struct nftnl_chain *nlc;
	struct chain *chain;
	int err;

	nlc = alloc_nftnl_chain(h);
	err = mnl_nft_chain_get(nf_sock, nlc, 0);
	if (err < 0) {
		netlink_io_error(ctx, loc,
				 "Could not receive chain from kernel: %s",
				 strerror(errno));
		goto out;
	}

	chain = netlink_delinearize_chain(ctx, nlc);
	list_add_tail(&chain->list, &ctx->list);
out:
	nftnl_chain_free(nlc);
	return err;
}

int netlink_list_chain(struct netlink_ctx *ctx, const struct handle *h,
		       const struct location *loc)
{
	return netlink_list_rules(ctx, h, loc);
}

int netlink_flush_chain(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	return netlink_del_rule_batch(ctx, h, loc);
}

static int netlink_add_table_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
				    const struct location *loc,
				    const struct table *table, bool excl)
{
	struct nftnl_table *nlt;
	int err;

	nlt = alloc_nftnl_table(h);
	err = mnl_nft_table_add(nf_sock, nlt, excl ? NLM_F_EXCL : 0);
	nftnl_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add table: %s",
				 strerror(errno));
	return err;
}

static int netlink_add_table_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc,
				   const struct table *table, bool excl)
{
	struct nftnl_table *nlt;
	int err;

	nlt = alloc_nftnl_table(h);
	if (table != NULL)
		nftnl_table_set_u32(nlt, NFTNL_TABLE_FLAGS, table->flags);
	else
		nftnl_table_set_u32(nlt, NFTNL_TABLE_FLAGS, 0);

	err = mnl_nft_table_batch_add(nlt, excl ? NLM_F_EXCL : 0,
				      ctx->seqnum);
	nftnl_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add table: %s",
				 strerror(errno));
	return err;
}

int netlink_add_table(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc,
		      const struct table *table, bool excl)
{
	if (ctx->batch_supported)
		return netlink_add_table_batch(ctx, h, loc, table, excl);
	else
		return netlink_add_table_compat(ctx, h, loc, table, excl);
}

static int netlink_del_table_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
				    const struct location *loc)
{
	struct nftnl_table *nlt;
	int err;

	nlt = alloc_nftnl_table(h);
	err = mnl_nft_table_delete(nf_sock, nlt, 0);
	nftnl_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete table: %s",
				 strerror(errno));
	return err;
}

static int netlink_del_table_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc)
{
	struct nftnl_table *nlt;
	int err;

	nlt = alloc_nftnl_table(h);
	err = mnl_nft_table_batch_del(nlt, 0, ctx->seqnum);
	nftnl_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete table: %s",
				 strerror(errno));
	return err;
}

int netlink_delete_table(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc)
{
	if (ctx->batch_supported)
		return netlink_del_table_batch(ctx, h, loc);
	else
		return netlink_del_table_compat(ctx, h, loc);
}

void netlink_dump_table(const struct nftnl_table *nlt)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nftnl_table_snprintf(buf, sizeof(buf), nlt, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

static struct table *netlink_delinearize_table(struct netlink_ctx *ctx,
					       const struct nftnl_table *nlt)
{
	struct table *table;

	table = table_alloc();
	table->handle.family = nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY);
	table->handle.table  = xstrdup(nftnl_table_get_str(nlt, NFTNL_TABLE_NAME));
	table->flags	     = nftnl_table_get_u32(nlt, NFTNL_TABLE_FLAGS);

	return table;
}

static int list_table_cb(struct nftnl_table *nlt, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct table *table;

	table = netlink_delinearize_table(ctx, nlt);
	list_add_tail(&table->list, &ctx->list);

	return 0;
}

int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	struct nftnl_table_list *table_cache;

	table_cache = mnl_nft_table_dump(nf_sock, h->family);
	if (table_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive tables from kernel: %s",
					strerror(errno));
	}

	nftnl_table_list_foreach(table_cache, list_table_cb, ctx);
	nftnl_table_list_free(table_cache);
	return 0;
}

int netlink_get_table(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc, struct table *table)
{
	struct nftnl_table *nlt;
	struct table *ntable;
	int err;

	nlt = alloc_nftnl_table(h);
	err = mnl_nft_table_get(nf_sock, nlt, 0);
	if (err < 0) {
		netlink_io_error(ctx, loc,
				 "Could not receive table from kernel: %s",
				 strerror(errno));
		goto out;
	}

	ntable = netlink_delinearize_table(ctx, nlt);
	table->flags = ntable->flags;
	table_free(ntable);
out:
	nftnl_table_free(nlt);
	return err;
}

int netlink_list_table(struct netlink_ctx *ctx, const struct handle *h,
		       const struct location *loc)
{
	return netlink_list_rules(ctx, h, loc);
}

int netlink_flush_table(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	return netlink_flush_rules(ctx, h, loc);
}

static enum nft_data_types dtype_map_to_kernel(const struct datatype *dtype)
{
	switch (dtype->type) {
	case TYPE_VERDICT:
		return NFT_DATA_VERDICT;
	default:
		return dtype->type;
	}
}

static const struct datatype *dtype_map_from_kernel(enum nft_data_types type)
{
	switch (type) {
	case NFT_DATA_VERDICT:
		return &verdict_type;
	default:
		if (type & ~TYPE_MASK)
			return concat_type_alloc(type);
		return datatype_lookup(type);
	}
}

void netlink_dump_set(const struct nftnl_set *nls)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nftnl_set_snprintf(buf, sizeof(buf), nls, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

static struct set *netlink_delinearize_set(struct netlink_ctx *ctx,
					   const struct nftnl_set *nls)
{
	struct set *set;
	const struct datatype *keytype, *datatype;
	uint32_t flags, key, data, data_len;

	key = nftnl_set_get_u32(nls, NFTNL_SET_KEY_TYPE);
	keytype = dtype_map_from_kernel(key);
	if (keytype == NULL) {
		netlink_io_error(ctx, NULL, "Unknown data type in set key %u",
				 key);
		return NULL;
	}

	flags = nftnl_set_get_u32(nls, NFTNL_SET_FLAGS);
	if (flags & NFT_SET_MAP) {
		data = nftnl_set_get_u32(nls, NFTNL_SET_DATA_TYPE);
		datatype = dtype_map_from_kernel(data);
		if (datatype == NULL) {
			netlink_io_error(ctx, NULL,
					 "Unknown data type in set key %u",
					 data);
			return NULL;
		}
	} else
		datatype = NULL;

	set = set_alloc(&netlink_location);
	set->handle.family = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);
	set->handle.table  = xstrdup(nftnl_set_get_str(nls, NFTNL_SET_TABLE));
	set->handle.set    = xstrdup(nftnl_set_get_str(nls, NFTNL_SET_NAME));

	set->keytype = keytype;
	set->keylen  = nftnl_set_get_u32(nls, NFTNL_SET_KEY_LEN) * BITS_PER_BYTE;
	set->flags   = nftnl_set_get_u32(nls, NFTNL_SET_FLAGS);

	set->datatype = datatype;
	if (nftnl_set_is_set(nls, NFTNL_SET_DATA_LEN)) {
		data_len = nftnl_set_get_u32(nls, NFTNL_SET_DATA_LEN);
		set->datalen = data_len * BITS_PER_BYTE;
	}

	if (nftnl_set_is_set(nls, NFTNL_SET_TIMEOUT))
		set->timeout = nftnl_set_get_u64(nls, NFTNL_SET_TIMEOUT);
	if (nftnl_set_is_set(nls, NFTNL_SET_GC_INTERVAL))
		set->gc_int  = nftnl_set_get_u32(nls, NFTNL_SET_GC_INTERVAL);

	if (nftnl_set_is_set(nls, NFTNL_SET_POLICY))
		set->policy = nftnl_set_get_u32(nls, NFTNL_SET_POLICY);

	if (nftnl_set_is_set(nls, NFTNL_SET_DESC_SIZE))
		set->desc.size = nftnl_set_get_u32(nls, NFTNL_SET_DESC_SIZE);

	return set;
}

static int netlink_add_set_compat(struct netlink_ctx *ctx,
				  const struct handle *h, struct set *set,
				  bool excl)
{
	unsigned int flags = excl ? NLM_F_EXCL : 0;
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	nftnl_set_set_u32(nls, NFTNL_SET_FLAGS, set->flags);
	nftnl_set_set_u32(nls, NFTNL_SET_KEY_TYPE,
			  dtype_map_to_kernel(set->keytype));
	nftnl_set_set_u32(nls, NFTNL_SET_KEY_LEN,
			  div_round_up(set->keylen, BITS_PER_BYTE));
	if (set->flags & NFT_SET_MAP) {
		nftnl_set_set_u32(nls, NFTNL_SET_DATA_TYPE,
				  dtype_map_to_kernel(set->datatype));
		nftnl_set_set_u32(nls, NFTNL_SET_DATA_LEN,
				  set->datalen / BITS_PER_BYTE);
	}
	netlink_dump_set(nls);

	err = mnl_nft_set_add(nf_sock, nls, NLM_F_ECHO | flags);
	if (err < 0)
		netlink_io_error(ctx, &set->location, "Could not add set: %s",
				 strerror(errno));

	set->handle.set = xstrdup(nftnl_set_get_str(nls, NFTNL_SET_NAME));
	nftnl_set_free(nls);

	return err;
}

static int netlink_add_set_batch(struct netlink_ctx *ctx,
				 const struct handle *h, struct set *set,
				 bool excl)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	nftnl_set_set_u32(nls, NFTNL_SET_FLAGS, set->flags);
	nftnl_set_set_u32(nls, NFTNL_SET_KEY_TYPE,
			  dtype_map_to_kernel(set->keytype));
	nftnl_set_set_u32(nls, NFTNL_SET_KEY_LEN,
			  div_round_up(set->keylen, BITS_PER_BYTE));
	if (set->flags & NFT_SET_MAP) {
		nftnl_set_set_u32(nls, NFTNL_SET_DATA_TYPE,
				  dtype_map_to_kernel(set->datatype));
		nftnl_set_set_u32(nls, NFTNL_SET_DATA_LEN,
				  set->datalen / BITS_PER_BYTE);
	}
	if (set->timeout)
		nftnl_set_set_u64(nls, NFTNL_SET_TIMEOUT, set->timeout);
	if (set->gc_int)
		nftnl_set_set_u32(nls, NFTNL_SET_GC_INTERVAL, set->gc_int);

	nftnl_set_set_u32(nls, NFTNL_SET_ID, set->handle.set_id);

	if (!(set->flags & NFT_SET_CONSTANT)) {
		if (set->policy != NFT_SET_POL_PERFORMANCE)
			nftnl_set_set_u32(nls, NFTNL_SET_POLICY, set->policy);

		if (set->desc.size != 0)
			nftnl_set_set_u32(nls, NFTNL_SET_DESC_SIZE,
					  set->desc.size);
	}

	netlink_dump_set(nls);

	err = mnl_nft_set_batch_add(nls, excl ? NLM_F_EXCL : 0, ctx->seqnum);
	if (err < 0)
		netlink_io_error(ctx, &set->location, "Could not add set: %s",
				 strerror(errno));
	nftnl_set_free(nls);

	return err;
}

int netlink_add_set(struct netlink_ctx *ctx, const struct handle *h,
		    struct set *set, bool excl)
{
	if (ctx->batch_supported)
		return netlink_add_set_batch(ctx, h, set, excl);
	else
		return netlink_add_set_compat(ctx, h, set, excl);
}

static int netlink_del_set_compat(struct netlink_ctx *ctx,
				  const struct handle *h,
				  const struct location *loc)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	err = mnl_nft_set_delete(nf_sock, nls, 0);
	nftnl_set_free(nls);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete set: %s",
				 strerror(errno));
	return err;
}

static int netlink_del_set_batch(struct netlink_ctx *ctx,
				 const struct handle *h,
				 const struct location *loc)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	err = mnl_nft_set_batch_del(nls, 0, ctx->seqnum);
	nftnl_set_free(nls);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete set: %s",
				 strerror(errno));
	return err;
}

int netlink_delete_set(struct netlink_ctx *ctx, const struct handle *h,
		       const struct location *loc)
{
	if (ctx->batch_supported)
		return netlink_del_set_batch(ctx, h, loc);
	else
		return netlink_del_set_compat(ctx, h, loc);
}

static int list_set_cb(struct nftnl_set *nls, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct set *set;

	set = netlink_delinearize_set(ctx, nls);
	if (set == NULL)
		return -1;
	list_add_tail(&set->list, &ctx->list);
	return 0;
}

int netlink_list_sets(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc)
{
	struct nftnl_set_list *set_cache;
	int err;

	set_cache = mnl_nft_set_dump(nf_sock, h->family, h->table);
	if (set_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive sets from kernel: %s",
					strerror(errno));
	}

	err = nftnl_set_list_foreach(set_cache, list_set_cb, ctx);
	nftnl_set_list_free(set_cache);
	return err;
}

int netlink_get_set(struct netlink_ctx *ctx, const struct handle *h,
		    const struct location *loc)
{
	struct nftnl_set *nls;
	struct set *set;
	int err;

	nls = alloc_nftnl_set(h);
	err = mnl_nft_set_get(nf_sock, nls);
	if (err < 0) {
		nftnl_set_free(nls);
		return netlink_io_error(ctx, loc,
					"Could not receive set from kernel: %s",
					strerror(errno));
	}

	set = netlink_delinearize_set(ctx, nls);
	nftnl_set_free(nls);
	if (set == NULL)
		return -1;
	list_add_tail(&set->list, &ctx->list);

	return err;
}

static void alloc_setelem_cache(const struct expr *set, struct nftnl_set *nls)
{
	struct nftnl_set_elem *nlse;
	const struct expr *expr;

	list_for_each_entry(expr, &set->expressions, list) {
		nlse = alloc_nftnl_setelem(expr);
		nftnl_set_elem_add(nls, nlse);
	}
}

static int netlink_add_setelems_batch(struct netlink_ctx *ctx,
				      const struct handle *h,
				      const struct expr *expr, bool excl)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_batch_add(nls, excl ? NLM_F_EXCL : 0,
					ctx->seqnum);
	nftnl_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not add set elements: %s",
				 strerror(errno));
	return err;
}

static int netlink_add_setelems_compat(struct netlink_ctx *ctx,
				       const struct handle *h,
				       const struct expr *expr, bool excl)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_add(nf_sock, nls, excl ? NLM_F_EXCL : 0);
	nftnl_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not add set elements: %s",
				 strerror(errno));
	return err;
}

int netlink_add_setelems(struct netlink_ctx *ctx, const struct handle *h,
			 const struct expr *expr, bool excl)
{
	if (ctx->batch_supported)
		return netlink_add_setelems_batch(ctx, h, expr, excl);
	else
		return netlink_add_setelems_compat(ctx, h, expr, excl);
}

static int netlink_del_setelems_batch(struct netlink_ctx *ctx,
				      const struct handle *h,
				      const struct expr *expr)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	if (expr)
		alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_batch_del(nls, 0, ctx->seqnum);
	nftnl_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not delete set elements: %s",
				 strerror(errno));
	return err;
}

static int netlink_del_setelems_compat(struct netlink_ctx *ctx,
				       const struct handle *h,
				       const struct expr *expr)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_delete(nf_sock, nls, 0);
	nftnl_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not delete set elements: %s",
				 strerror(errno));
	return err;
}

int netlink_flush_setelems(struct netlink_ctx *ctx, const struct handle *h,
			   const struct location *loc)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_batch_flush(nls, 0, ctx->seqnum);
	nftnl_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, loc,
				 "Could not flush set elements: %s",
				 strerror(errno));
	return err;
}

static struct expr *netlink_parse_concat_elem(const struct datatype *dtype,
					      struct expr *data)
{
	const struct datatype *subtype;
	struct expr *concat, *expr;
	int off = dtype->subtypes;

	concat = concat_expr_alloc(&data->location);
	while (off > 0) {
		subtype = concat_subtype_lookup(dtype->type, --off);

		expr		= constant_expr_splice(data, subtype->size);
		expr->dtype     = subtype;
		expr->byteorder = subtype->byteorder;

		if (expr->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(expr->value, expr->len / BITS_PER_BYTE);

		if (expr->dtype->basetype != NULL &&
		    expr->dtype->basetype->type == TYPE_BITMASK)
			expr = bitmask_expr_to_binops(expr);

		compound_expr_add(concat, expr);
		data->len -= netlink_padding_len(expr->len);
	}
	expr_free(data);

	return concat;
}

static int parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	unsigned char *value = nftnl_udata_get(attr);
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);
	const struct nftnl_udata **tb = data;

	switch (type) {
	case UDATA_TYPE_COMMENT:
		if (value[len - 1] != '\0')
			return -1;
		break;
	default:
		return 0;
	}
	tb[type] = attr;
	return 0;
}

static char *udata_get_comment(const void *data, uint32_t data_len)
{
	const struct nftnl_udata *tb[UDATA_TYPE_MAX + 1] = {};

	if (nftnl_udata_parse(data, data_len, parse_udata_cb, tb) < 0)
		return NULL;

	if (!tb[UDATA_TYPE_COMMENT])
		return NULL;

	return xstrdup(nftnl_udata_get(tb[UDATA_TYPE_COMMENT]));
}

static int netlink_delinearize_setelem(struct nftnl_set_elem *nlse,
				       const struct set *set)
{
	struct nft_data_delinearize nld;
	struct expr *expr, *key, *data;
	uint32_t flags = 0;

	nld.value =
		nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_KEY, &nld.len);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_FLAGS))
		flags = nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_FLAGS);

	key = netlink_alloc_value(&netlink_location, &nld);
	key->dtype	= set->keytype;
	key->byteorder	= set->keytype->byteorder;
	if (set->keytype->subtypes)
		key = netlink_parse_concat_elem(set->keytype, key);

	if (!(set->flags & NFT_SET_INTERVAL) &&
	    key->byteorder == BYTEORDER_HOST_ENDIAN)
		mpz_switch_byteorder(key->value, key->len / BITS_PER_BYTE);

	if (key->dtype->basetype != NULL &&
	    key->dtype->basetype->type == TYPE_BITMASK)
		key = bitmask_expr_to_binops(key);

	expr = set_elem_expr_alloc(&netlink_location, key);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_TIMEOUT))
		expr->timeout	 = nftnl_set_elem_get_u64(nlse, NFTNL_SET_ELEM_TIMEOUT);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_EXPIRATION))
		expr->expiration = nftnl_set_elem_get_u64(nlse, NFTNL_SET_ELEM_EXPIRATION);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_USERDATA)) {
		const void *data;
		uint32_t len;

		data = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_USERDATA, &len);
		expr->comment = udata_get_comment(data, len);
	}
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_EXPR)) {
		const struct nftnl_expr *nle;

		nle = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_EXPR, NULL);
		expr->stmt = netlink_parse_set_expr(set, nle);
	}

	if (flags & NFT_SET_ELEM_INTERVAL_END) {
		expr->flags |= EXPR_F_INTERVAL_END;
	} else {
		if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_DATA)) {
			nld.value = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_DATA,
						       &nld.len);
		} else if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_CHAIN)) {
			nld.chain = nftnl_set_elem_get_str(nlse, NFTNL_SET_ELEM_CHAIN);
			nld.verdict = nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_VERDICT);
		} else if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_VERDICT)) {
			nld.verdict = nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_VERDICT);
		} else
			goto out;

		data = netlink_alloc_data(&netlink_location, &nld,
					  set->datatype->type == TYPE_VERDICT ?
					  NFT_REG_VERDICT : NFT_REG_1);
		data->dtype = set->datatype;
		data->byteorder = set->datatype->byteorder;
		if (data->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(data->value, data->len / BITS_PER_BYTE);

		expr = mapping_expr_alloc(&netlink_location, expr, data);
	}
out:
	compound_expr_add(set->init, expr);
	return 0;
}

int netlink_delete_setelems(struct netlink_ctx *ctx, const struct handle *h,
			    const struct expr *expr)
{
	if (ctx->batch_supported)
		return netlink_del_setelems_batch(ctx, h, expr);
	else
		return netlink_del_setelems_compat(ctx, h, expr);
}

static int list_setelem_cb(struct nftnl_set_elem *nlse, void *arg)
{
	struct netlink_ctx *ctx = arg;
	return netlink_delinearize_setelem(nlse, ctx->set);
}

int netlink_get_setelems(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc, struct set *set)
{
	struct nftnl_set *nls;
	int err;

	nls = alloc_nftnl_set(h);

	err = mnl_nft_setelem_get(nf_sock, nls);
	if (err < 0) {
		nftnl_set_free(nls);
		if (errno == EINTR)
			return -1;

		goto out;
	}

	ctx->set = set;
	set->init = set_expr_alloc(loc);
	nftnl_set_elem_foreach(nls, list_setelem_cb, ctx);
	nftnl_set_free(nls);
	ctx->set = NULL;

	if (set->flags & NFT_SET_INTERVAL)
		interval_map_decompose(set->init);
out:
	if (err < 0)
		netlink_io_error(ctx, loc, "Could not receive set elements: %s",
				 strerror(errno));
	return err;
}

int netlink_batch_send(struct list_head *err_list)
{
	return mnl_batch_talk(nf_sock, err_list);
}

int netlink_flush_ruleset(struct netlink_ctx *ctx, const struct handle *h,
			  const struct location *loc)
{
	struct nftnl_table *nlt;
	int err;

	if (!ctx->batch_supported)
		return netlink_io_error(ctx, loc, "Operation not supported");

	nlt = alloc_nftnl_table(h);
	err = mnl_nft_table_batch_del(nlt, 0, ctx->seqnum);
	nftnl_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not flush the ruleset: %s",
				 strerror(errno));
	return err;
}

struct nftnl_ruleset *netlink_dump_ruleset(struct netlink_ctx *ctx,
					 const struct handle *h,
					 const struct location *loc)
{
	struct nftnl_ruleset *rs;

	rs = mnl_nft_ruleset_dump(nf_sock, h->family);
	if (rs == NULL) {
		if (errno == EINTR)
			return NULL;

		netlink_io_error(ctx, loc, "Could not receive ruleset: %s",
				 strerror(errno));
	}

	return rs;
}

static struct nftnl_table *netlink_table_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_table *nlt;

	nlt = nftnl_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();
	if (nftnl_table_nlmsg_parse(nlh, nlt) < 0)
		netlink_abi_error();

	return nlt;
}

static struct nftnl_chain *netlink_chain_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_chain *nlc;

	nlc = nftnl_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();
	if (nftnl_chain_nlmsg_parse(nlh, nlc) < 0)
		netlink_abi_error();

	return nlc;
}

static struct nftnl_set *netlink_set_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_set *nls;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();
	if (nftnl_set_nlmsg_parse(nlh, nls) < 0)
		netlink_abi_error();

	return nls;
}

static struct nftnl_set *netlink_setelem_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_set *nls;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();
	if (nftnl_set_elems_nlmsg_parse(nlh, nls) < 0)
		netlink_abi_error();

	return nls;
}

static struct nftnl_rule *netlink_rule_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_rule *nlr;

	nlr = nftnl_rule_alloc();
	if (nlr == NULL)
		memory_allocation_error();
	if (nftnl_rule_nlmsg_parse(nlh, nlr) < 0)
		netlink_abi_error();

	return nlr;
}

static uint32_t netlink_msg2nftnl_of(uint32_t msg)
{
	switch (msg) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_NEWSET:
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_NEWRULE:
		return NFTNL_OF_EVENT_NEW;
	case NFT_MSG_DELTABLE:
	case NFT_MSG_DELCHAIN:
	case NFT_MSG_DELSET:
	case NFT_MSG_DELSETELEM:
	case NFT_MSG_DELRULE:
		return NFTNL_OF_EVENT_DEL;
	}

	return 0;
}

static void nlr_for_each_set(struct nftnl_rule *nlr,
			     void (*cb)(struct set *s, void *data),
			     void *data)
{
	struct nftnl_expr_iter *nlrei;
	struct nftnl_expr *nlre;
	const char *set_name, *table;
	const char *name;
	struct set *s;
	uint32_t family;

	nlrei = nftnl_expr_iter_create(nlr);
	if (nlrei == NULL)
		memory_allocation_error();

	family = nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY);
	table = nftnl_rule_get_str(nlr, NFTNL_RULE_TABLE);

	nlre = nftnl_expr_iter_next(nlrei);
	while (nlre != NULL) {
		name = nftnl_expr_get_str(nlre, NFTNL_EXPR_NAME);
		if (strcmp(name, "lookup") != 0)
			goto next;

		set_name = nftnl_expr_get_str(nlre, NFTNL_EXPR_LOOKUP_SET);
		s = set_lookup_global(family, table, set_name);
		if (s == NULL)
			goto next;

		cb(s, data);
next:
		nlre = nftnl_expr_iter_next(nlrei);
	}
	nftnl_expr_iter_destroy(nlrei);
}

static int netlink_events_table_cb(const struct nlmsghdr *nlh, int type,
				   struct netlink_mon_handler *monh)
{
	struct nftnl_table *nlt;
	uint32_t family;

	nlt = netlink_table_alloc(nlh);

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		if (type == NFT_MSG_NEWTABLE) {
			if (nlh->nlmsg_flags & NLM_F_EXCL)
				printf("update table ");
			else
				printf("add table ");
		} else {
			printf("delete table ");
		}

		family = nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY);

		printf("%s %s\n", family2str(family),
		       nftnl_table_get_str(nlt, NFTNL_TABLE_NAME));
		break;
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		nftnl_table_fprintf(stdout, nlt, monh->format,
				    netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}

	nftnl_table_free(nlt);
	return MNL_CB_OK;
}

static int netlink_events_chain_cb(const struct nlmsghdr *nlh, int type,
				   struct netlink_mon_handler *monh)
{
	struct nftnl_chain *nlc;
	struct chain *c;
	uint32_t family;

	nlc = netlink_chain_alloc(nlh);

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		switch (type) {
		case NFT_MSG_NEWCHAIN:
			if (nlh->nlmsg_flags & NLM_F_EXCL)
				printf("update ");
			else
				printf("add ");

			c = netlink_delinearize_chain(monh->ctx, nlc);
			chain_print_plain(c);
			chain_free(c);
			break;
		case NFT_MSG_DELCHAIN:
			family = nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY);
			printf("delete chain %s %s %s\n", family2str(family),
			       nftnl_chain_get_str(nlc, NFTNL_CHAIN_TABLE),
			       nftnl_chain_get_str(nlc, NFTNL_CHAIN_NAME));
			break;
		}
		break;
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		nftnl_chain_fprintf(stdout, nlc, monh->format,
				    netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}

	nftnl_chain_free(nlc);
	return MNL_CB_OK;
}

static int netlink_events_set_cb(const struct nlmsghdr *nlh, int type,
				 struct netlink_mon_handler *monh)
{
	struct nftnl_set *nls;
	struct set *set;
	uint32_t family, flags;

	nls = netlink_set_alloc(nlh);
	flags = nftnl_set_get_u32(nls, NFTNL_SET_FLAGS);
	if (flags & NFT_SET_ANONYMOUS)
		goto out;

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		switch (type) {
		case NFT_MSG_NEWSET:
			printf("add ");
			set = netlink_delinearize_set(monh->ctx, nls);
			if (set == NULL) {
				nftnl_set_free(nls);
				return MNL_CB_ERROR;
			}
			set_print_plain(set);
			set_free(set);
			printf("\n");
			break;
		case NFT_MSG_DELSET:
			family = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);
			printf("delete set %s %s %s\n",
			       family2str(family),
			       nftnl_set_get_str(nls, NFTNL_SET_TABLE),
			       nftnl_set_get_str(nls, NFTNL_SET_NAME));
			break;
		}
		break;
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		nftnl_set_fprintf(stdout, nls, monh->format,
				netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}
out:
	nftnl_set_free(nls);
	return MNL_CB_OK;
}

static int netlink_events_setelem_cb(const struct nlmsghdr *nlh, int type,
				     struct netlink_mon_handler *monh)
{
	struct nftnl_set_elems_iter *nlsei;
	struct nftnl_set_elem *nlse;
	struct nftnl_set *nls;
	struct set *dummyset;
	struct set *set;
	const char *setname, *table;
	uint32_t family;

	nls = netlink_setelem_alloc(nlh);
	table = nftnl_set_get_str(nls, NFTNL_SET_TABLE);
	setname = nftnl_set_get_str(nls, NFTNL_SET_NAME);
	family = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);

	set = set_lookup_global(family, table, setname);
	if (set == NULL) {
		fprintf(stderr, "W: Received event for an unknown set.");
		goto out;
	}

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		if (set->flags & NFT_SET_ANONYMOUS)
			goto out;

		/* we want to 'delinearize' the set_elem, but don't
		 * modify the original cached set. This path is only
		 * used by named sets, so use a dummy set.
		 */
		dummyset = set_alloc(monh->loc);
		dummyset->keytype = set->keytype;
		dummyset->datatype = set->datatype;
		dummyset->init = set_expr_alloc(monh->loc);

		nlsei = nftnl_set_elems_iter_create(nls);
		if (nlsei == NULL)
			memory_allocation_error();

		nlse = nftnl_set_elems_iter_next(nlsei);
		while (nlse != NULL) {
			if (netlink_delinearize_setelem(nlse, dummyset) < 0) {
				set_free(dummyset);
				nftnl_set_elems_iter_destroy(nlsei);
				goto out;
			}
			nlse = nftnl_set_elems_iter_next(nlsei);
		}
		nftnl_set_elems_iter_destroy(nlsei);

		switch (type) {
		case NFT_MSG_NEWSETELEM:
			printf("add ");
			break;
		case NFT_MSG_DELSETELEM:
			printf("delete ");
			break;
		default:
			set_free(dummyset);
			goto out;
		}
		printf("element %s %s %s ", family2str(family), table, setname);
		expr_print(dummyset->init);
		printf("\n");

		set_free(dummyset);
		break;
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		nftnl_set_fprintf(stdout, nls, monh->format,
				  netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}
out:
	nftnl_set_free(nls);
	return MNL_CB_OK;
}

static void rule_map_decompose_cb(struct set *s, void *data)
{
	if (s->flags & NFT_SET_INTERVAL)
		interval_map_decompose(s->init);
}

static int netlink_events_rule_cb(const struct nlmsghdr *nlh, int type,
				  struct netlink_mon_handler *monh)
{
	struct nftnl_rule *nlr;
	const char *family;
	const char *table;
	const char *chain;
	struct rule *r;
	uint64_t handle;
	uint32_t fam;

	nlr = netlink_rule_alloc(nlh);
	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		fam = nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY);
		family = family2str(fam);
		table = nftnl_rule_get_str(nlr, NFTNL_RULE_TABLE);
		chain = nftnl_rule_get_str(nlr, NFTNL_RULE_CHAIN);
		handle = nftnl_rule_get_u64(nlr, NFTNL_RULE_HANDLE);

		switch (type) {
		case NFT_MSG_NEWRULE:
			r = netlink_delinearize_rule(monh->ctx, nlr);
			nlr_for_each_set(nlr, rule_map_decompose_cb, NULL);

			printf("add rule %s %s %s ", family, table, chain);
			rule_print(r);
			printf("\n");

			rule_free(r);
			break;
		case NFT_MSG_DELRULE:
			printf("delete rule %s %s %s handle %u\n",
			       family, table, chain, (unsigned int)handle);
			break;
		}
		break;
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		nftnl_rule_fprintf(stdout, nlr, monh->format,
				 netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}

	nftnl_rule_free(nlr);
	return MNL_CB_OK;
}

static void netlink_events_cache_addtable(struct netlink_mon_handler *monh,
					  const struct nlmsghdr *nlh)
{
	struct nftnl_table *nlt;
	struct table *t;

	nlt = netlink_table_alloc(nlh);
	t = netlink_delinearize_table(monh->ctx, nlt);
	nftnl_table_free(nlt);

	table_add_hash(t);
}

static void netlink_events_cache_deltable(struct netlink_mon_handler *monh,
					  const struct nlmsghdr *nlh)
{
	struct nftnl_table *nlt;
	struct table *t;
	struct handle h;

	nlt      = netlink_table_alloc(nlh);
	h.family = nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY);
	h.table  = nftnl_table_get_str(nlt, NFTNL_TABLE_NAME);

	t = table_lookup(&h);
	if (t == NULL)
		goto out;

	list_del(&t->list);
	table_free(t);
out:
	nftnl_table_free(nlt);
}

static void netlink_events_cache_addset(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh)
{
	struct netlink_ctx set_tmpctx;
	struct nftnl_set *nls;
	struct table *t;
	struct set *s;
	LIST_HEAD(msgs);

	memset(&set_tmpctx, 0, sizeof(set_tmpctx));
	init_list_head(&set_tmpctx.list);
	init_list_head(&msgs);
	set_tmpctx.msgs = &msgs;

	nls = netlink_set_alloc(nlh);
	s = netlink_delinearize_set(&set_tmpctx, nls);
	if (s == NULL)
		goto out;
	s->init = set_expr_alloc(monh->loc);

	t = table_lookup(&s->handle);
	if (t == NULL) {
		fprintf(stderr, "W: Unable to cache set: table not found.\n");
		set_free(s);
		goto out;
	}

	set_add_hash(s, t);
out:
	nftnl_set_free(nls);
}

static void netlink_events_cache_addsetelem(struct netlink_mon_handler *monh,
					    const struct nlmsghdr *nlh)
{
	struct nftnl_set_elems_iter *nlsei;
	struct nftnl_set_elem *nlse;
	struct nftnl_set *nls;
	struct set *set;
	const char *table, *setname;
	uint32_t family;

	nls     = netlink_setelem_alloc(nlh);
	family  = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);
	table   = nftnl_set_get_str(nls, NFTNL_SET_TABLE);
	setname = nftnl_set_get_str(nls, NFTNL_SET_NAME);

	set = set_lookup_global(family, table, setname);
	if (set == NULL) {
		fprintf(stderr,
			"W: Unable to cache set_elem. Set not found.\n");
		goto out;
	}

	nlsei = nftnl_set_elems_iter_create(nls);
	if (nlsei == NULL)
		memory_allocation_error();

	nlse = nftnl_set_elems_iter_next(nlsei);
	while (nlse != NULL) {
		if (netlink_delinearize_setelem(nlse, set) < 0) {
			fprintf(stderr,
				"W: Unable to cache set_elem. "
				"Delinearize failed.\n");
			nftnl_set_elems_iter_destroy(nlsei);
			goto out;
		}
		nlse = nftnl_set_elems_iter_next(nlsei);
	}
	nftnl_set_elems_iter_destroy(nlsei);
out:
	nftnl_set_free(nls);
}

static void netlink_events_cache_delset_cb(struct set *s,
					   void *data)
{
	list_del(&s->list);
	set_free(s);
}

static void netlink_events_cache_delsets(struct netlink_mon_handler *monh,
					 const struct nlmsghdr *nlh)
{
	struct nftnl_rule *nlr = netlink_rule_alloc(nlh);

	nlr_for_each_set(nlr, netlink_events_cache_delset_cb, NULL);
	nftnl_rule_free(nlr);
}

static void netlink_events_cache_update(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh, int type)
{
	if (!monh->cache_needed)
		return;

	switch (type) {
	case NFT_MSG_NEWTABLE:
		netlink_events_cache_addtable(monh, nlh);
		break;
	case NFT_MSG_DELTABLE:
		netlink_events_cache_deltable(monh, nlh);
		break;
	case NFT_MSG_NEWSET:
		netlink_events_cache_addset(monh, nlh);
		break;
	case NFT_MSG_NEWSETELEM:
		netlink_events_cache_addsetelem(monh, nlh);
		break;
	case NFT_MSG_DELRULE:
		/* there are no notification for anon-set deletion */
		netlink_events_cache_delsets(monh, nlh);
		break;
	}
}

static void trace_print_hdr(const struct nftnl_trace *nlt)
{
	printf("trace id %08x ", nftnl_trace_get_u32(nlt, NFTNL_TRACE_ID));
	printf("%s ", family2str(nftnl_trace_get_u32(nlt, NFTNL_TRACE_FAMILY)));
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_TABLE))
		printf("%s ", nftnl_trace_get_str(nlt, NFTNL_TRACE_TABLE));
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_CHAIN))
		printf("%s ", nftnl_trace_get_str(nlt, NFTNL_TRACE_CHAIN));
}

static void trace_print_expr(const struct nftnl_trace *nlt, unsigned int attr,
			     struct expr *lhs)
{
	struct expr *rhs, *rel;
	const void *data;
	uint32_t len;

	data = nftnl_trace_get_data(nlt, attr, &len);
	rhs  = constant_expr_alloc(&netlink_location,
				   lhs->dtype, lhs->byteorder,
				   len * BITS_PER_BYTE, data);
	rel  = relational_expr_alloc(&netlink_location, OP_EQ, lhs, rhs);

	expr_print(rel);
	printf(" ");
	expr_free(rel);
}

static void trace_print_verdict(const struct nftnl_trace *nlt)
{
	const char *chain = NULL;
	unsigned int verdict;
	struct expr *expr;

	verdict = nftnl_trace_get_u32(nlt, NFTNL_TRACE_VERDICT);
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_JUMP_TARGET))
		chain = xstrdup(nftnl_trace_get_str(nlt, NFTNL_TRACE_JUMP_TARGET));
	expr = verdict_expr_alloc(&netlink_location, verdict, chain);

	printf("verdict ");
	expr_print(expr);
	expr_free(expr);
}

static void trace_print_rule(const struct nftnl_trace *nlt)
{
	const struct table *table;
	uint64_t rule_handle;
	struct chain *chain;
	struct rule *rule;
	struct handle h;

	h.family = nftnl_trace_get_u32(nlt, NFTNL_TRACE_FAMILY);
	h.table  = nftnl_trace_get_str(nlt, NFTNL_TRACE_TABLE);
	h.chain  = nftnl_trace_get_str(nlt, NFTNL_TRACE_CHAIN);

	if (!h.table)
		return;

	table = table_lookup(&h);
	if (!table)
		return;

	chain = chain_lookup(table, &h);
	if (!chain)
		return;

	rule_handle = nftnl_trace_get_u64(nlt, NFTNL_TRACE_RULE_HANDLE);
	rule = rule_lookup(chain, rule_handle);
	if (!rule)
		return;

	trace_print_hdr(nlt);
	printf("rule ");
	rule_print(rule);
	printf(" (");
	trace_print_verdict(nlt);
	printf(")\n");
}

static void trace_gen_stmts(struct list_head *stmts,
			    struct proto_ctx *ctx, struct payload_dep_ctx *pctx,
			    const struct nftnl_trace *nlt, unsigned int attr,
			    enum proto_bases base)
{
	struct list_head unordered = LIST_HEAD_INIT(unordered);
	struct list_head list;
	struct expr *rel, *lhs, *rhs, *tmp, *nexpr;
	struct stmt *stmt;
	const struct proto_desc *desc;
	const void *hdr;
	uint32_t hlen;
	unsigned int n;
	bool stacked;

	if (!nftnl_trace_is_set(nlt, attr))
		return;
	hdr = nftnl_trace_get_data(nlt, attr, &hlen);

	lhs = payload_expr_alloc(&netlink_location, NULL, 0);
	payload_init_raw(lhs, base, 0, hlen * BITS_PER_BYTE);
	rhs = constant_expr_alloc(&netlink_location,
				  &invalid_type, BYTEORDER_INVALID,
				  hlen * BITS_PER_BYTE, hdr);

restart:
	init_list_head(&list);
	payload_expr_expand(&list, lhs, ctx);
	expr_free(lhs);

	desc = NULL;
	list_for_each_entry_safe(lhs, nexpr, &list, list) {
		if (desc && desc != ctx->protocol[base].desc) {
			/* Chained protocols */
			lhs->payload.offset = 0;
			if (ctx->protocol[base].desc == NULL)
				break;
			goto restart;
		}

		tmp = constant_expr_splice(rhs, lhs->len);
		expr_set_type(tmp, lhs->dtype, lhs->byteorder);
		if (tmp->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(tmp->value, tmp->len / BITS_PER_BYTE);

		/* Skip unknown and filtered expressions */
		desc = lhs->payload.desc;
		if (lhs->dtype == &invalid_type ||
		    desc->checksum_key == payload_hdr_field(lhs) ||
		    desc->format.filter & (1 << payload_hdr_field(lhs))) {
			expr_free(lhs);
			expr_free(tmp);
			continue;
		}

		rel  = relational_expr_alloc(&lhs->location, OP_EQ, lhs, tmp);
		stmt = expr_stmt_alloc(&rel->location, rel);
		list_add_tail(&stmt->list, &unordered);

		desc = ctx->protocol[base].desc;
		lhs->ops->pctx_update(ctx, rel);
	}

	expr_free(rhs);

	n = 0;
next:
	list_for_each_entry(stmt, &unordered, list) {
		rel = stmt->expr;
		lhs = rel->left;

		/* Move statements to result list in defined order */
		desc = lhs->payload.desc;
		if (desc->format.order[n] &&
		    desc->format.order[n] != payload_hdr_field(lhs))
			continue;

		list_move_tail(&stmt->list, stmts);
		n++;

		stacked = payload_is_stacked(desc, rel);

		if (lhs->flags & EXPR_F_PROTOCOL &&
		    pctx->pbase == PROTO_BASE_INVALID) {
			payload_dependency_store(pctx, stmt, base - stacked);
		} else {
			payload_dependency_kill(pctx, lhs);
			if (lhs->flags & EXPR_F_PROTOCOL)
				payload_dependency_store(pctx, stmt, base - stacked);
		}

		goto next;
	}
}

static void trace_print_packet(const struct nftnl_trace *nlt)
{
	struct list_head stmts = LIST_HEAD_INIT(stmts);
	const struct proto_desc *ll_desc;
	struct payload_dep_ctx pctx = {};
	struct proto_ctx ctx;
	uint16_t dev_type;
	uint32_t nfproto;
	struct stmt *stmt, *next;

	trace_print_hdr(nlt);

	printf("packet: ");
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_IIF))
		trace_print_expr(nlt, NFTNL_TRACE_IIF,
				 meta_expr_alloc(&netlink_location,
						 NFT_META_IIF));
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_OIF))
		trace_print_expr(nlt, NFTNL_TRACE_OIF,
				 meta_expr_alloc(&netlink_location,
						 NFT_META_OIF));

	proto_ctx_init(&ctx, nftnl_trace_get_u32(nlt, NFTNL_TRACE_FAMILY));
	ll_desc = ctx.protocol[PROTO_BASE_LL_HDR].desc;
	if ((ll_desc == &proto_inet || ll_desc  == &proto_netdev) &&
	    nftnl_trace_is_set(nlt, NFTNL_TRACE_NFPROTO)) {
		nfproto = nftnl_trace_get_u32(nlt, NFTNL_TRACE_NFPROTO);

		proto_ctx_update(&ctx, PROTO_BASE_LL_HDR, &netlink_location, NULL);
		proto_ctx_update(&ctx, PROTO_BASE_NETWORK_HDR, &netlink_location,
				 proto_find_upper(ll_desc, nfproto));
	}
	if (ctx.protocol[PROTO_BASE_LL_HDR].desc == NULL &&
	    nftnl_trace_is_set(nlt, NFTNL_TRACE_IIFTYPE)) {
		dev_type = nftnl_trace_get_u16(nlt, NFTNL_TRACE_IIFTYPE);
		proto_ctx_update(&ctx, PROTO_BASE_LL_HDR, &netlink_location,
				 proto_dev_desc(dev_type));
	}

	trace_gen_stmts(&stmts, &ctx, &pctx, nlt, NFTNL_TRACE_LL_HEADER,
			PROTO_BASE_LL_HDR);
	trace_gen_stmts(&stmts, &ctx, &pctx, nlt, NFTNL_TRACE_NETWORK_HEADER,
			PROTO_BASE_NETWORK_HDR);
	trace_gen_stmts(&stmts, &ctx, &pctx, nlt, NFTNL_TRACE_TRANSPORT_HEADER,
			PROTO_BASE_TRANSPORT_HDR);

	list_for_each_entry_safe(stmt, next, &stmts, list) {
		stmt_print(stmt);
		printf(" ");
		stmt_free(stmt);
	}
	printf("\n");
}

static int netlink_events_trace_cb(const struct nlmsghdr *nlh, int type,
				   struct netlink_mon_handler *monh)
{
	struct nftnl_trace *nlt;

	assert(type == NFT_MSG_TRACE);

	nlt = nftnl_trace_alloc();
	if (!nlt)
		memory_allocation_error();

	if (nftnl_trace_nlmsg_parse(nlh, nlt) < 0)
		netlink_abi_error();

	switch (nftnl_trace_get_u32(nlt, NFTNL_TRACE_TYPE)) {
	case NFT_TRACETYPE_RULE:
		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_LL_HEADER) ||
		    nftnl_trace_is_set(nlt, NFTNL_TRACE_NETWORK_HEADER))
			trace_print_packet(nlt);

		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_RULE_HANDLE))
			trace_print_rule(nlt);
		break;
	case NFT_TRACETYPE_POLICY:
	case NFT_TRACETYPE_RETURN:
		trace_print_hdr(nlt);

		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_VERDICT)) {
			trace_print_verdict(nlt);
			printf(" ");
		}

		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_MARK))
			trace_print_expr(nlt, NFTNL_TRACE_MARK,
					 meta_expr_alloc(&netlink_location,
							 NFT_META_MARK));
		printf("\n");
		break;
	}

	nftnl_trace_free(nlt);
	return MNL_CB_OK;
}

static int netlink_events_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret = MNL_CB_OK;
	uint16_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	struct netlink_mon_handler *monh = (struct netlink_mon_handler *)data;

	netlink_events_cache_update(monh, nlh, type);

	if (!(monh->monitor_flags & (1 << type)))
		return ret;

	switch (type) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		ret = netlink_events_table_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		ret = netlink_events_chain_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWSET:
	case NFT_MSG_DELSET:		/* nft {add|delete} set */
		ret = netlink_events_set_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_DELSETELEM:	/* nft {add|delete} element */
		ret = netlink_events_setelem_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWRULE:
	case NFT_MSG_DELRULE:
		ret = netlink_events_rule_cb(nlh, type, monh);
		break;
	case NFT_MSG_TRACE:
		ret = netlink_events_trace_cb(nlh, type, monh);
		break;
	}
	fflush(stdout);

	return ret;
}

int netlink_monitor(struct netlink_mon_handler *monhandler)
{
	netlink_open_mon_sock();

	if (mnl_socket_bind(nf_mon_sock, (1 << (NFNLGRP_NFTABLES-1)) |
					 (1 << (NFNLGRP_NFTRACE-1)),
			    MNL_SOCKET_AUTOPID) < 0)
		return netlink_io_error(monhandler->ctx, monhandler->loc,
					"Could not bind to netlink socket %s",
					strerror(errno));

	return mnl_nft_event_listener(nf_mon_sock, netlink_events_cb,
				      monhandler);
}

bool netlink_batch_supported(void)
{
	return mnl_batch_supported(nf_sock);
}
