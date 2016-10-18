/*
 * Copyright (c) 2013-2015 Pablo Neira Ayuso <pablo@netfilter.org>
 * Copyright (c) 2015 Arturo Borrero Gonzalez <arturo@debian.org>
 *
 * This program is free software; you can redistribute it and/or modifyi
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <xtables.h>
#include <getopt.h>
#include <ctype.h>	/* for isspace */
#include <statement.h>
#include <netlink.h>
#include <xt.h>
#include <erec.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_arp/arp_tables.h>
#include <linux/netfilter_bridge/ebtables.h>

void xt_stmt_xlate(const struct stmt *stmt)
{
	struct xt_xlate *xl = xt_xlate_alloc(10240);

	switch (stmt->xt.type) {
	case NFT_XT_MATCH:
		if (stmt->xt.match == NULL && stmt->xt.opts) {
			printf("%s", stmt->xt.opts);
		} else if (stmt->xt.match->xlate) {
			struct xt_xlate_mt_params params = {
				.ip		= stmt->xt.entry,
				.match		= stmt->xt.match->m,
				.numeric        = 0,
			};

			stmt->xt.match->xlate(xl, &params);
			printf("%s", xt_xlate_get(xl));
		} else if (stmt->xt.match->print) {
			printf("#");
			stmt->xt.match->print(&stmt->xt.entry,
					      stmt->xt.match->m, 0);
		}
		break;
	case NFT_XT_WATCHER:
	case NFT_XT_TARGET:
		if (stmt->xt.target == NULL && stmt->xt.opts) {
			printf("%s", stmt->xt.opts);
		} else if (stmt->xt.target->xlate) {
			struct xt_xlate_tg_params params = {
				.ip		= stmt->xt.entry,
				.target		= stmt->xt.target->t,
				.numeric        = 0,
			};

			stmt->xt.target->xlate(xl, &params);
			printf("%s", xt_xlate_get(xl));
		} else if (stmt->xt.target->print) {
			printf("#");
			stmt->xt.target->print(NULL, stmt->xt.target->t, 0);
		}
		break;
	default:
		break;
	}

	xt_xlate_free(xl);
}

void xt_stmt_release(const struct stmt *stmt)
{
	switch (stmt->xt.type) {
	case NFT_XT_MATCH:
		if (!stmt->xt.match)
			break;
		if (stmt->xt.match->m)
			xfree(stmt->xt.match->m);
		xfree(stmt->xt.match);
		break;
	case NFT_XT_WATCHER:
	case NFT_XT_TARGET:
		if (!stmt->xt.target)
			break;
		if (stmt->xt.target->t)
			xfree(stmt->xt.target->t);
		xfree(stmt->xt.target);
		break;
	default:
		break;
	}
	xfree(stmt->xt.entry);
}

static void *xt_entry_alloc(struct xt_stmt *xt, uint32_t af)
{
	union nft_entry {
		struct ipt_entry ipt;
		struct ip6t_entry ip6t;
		struct arpt_entry arpt;
		struct ebt_entry ebt;
	} *entry;

	entry = xmalloc(sizeof(union nft_entry));

	switch (af) {
	case NFPROTO_IPV4:
		entry->ipt.ip.proto = xt->proto;
		break;
	case NFPROTO_IPV6:
		entry->ip6t.ipv6.proto = xt->proto;
		break;
	case NFPROTO_BRIDGE:
		entry->ebt.ethproto = xt->proto;
		break;
	case NFPROTO_ARP:
		entry->arpt.arp.arhln_mask = 0xff;
		entry->arpt.arp.arhln = 6;
		break;
	default:
		break;
	}

	return entry;
}

static uint32_t xt_proto(const struct proto_ctx *pctx)
{
	const struct proto_desc *desc = NULL;

	if (pctx->family == NFPROTO_BRIDGE) {
		desc = pctx->protocol[PROTO_BASE_NETWORK_HDR].desc;
		if (desc == NULL)
			return 0;
		if (strcmp(desc->name, "ip") == 0)
			return __constant_htons(ETH_P_IP);
		if (strcmp(desc->name, "ip6") == 0)
			return __constant_htons(ETH_P_IPV6);
		return 0;
	}

	desc = pctx->protocol[PROTO_BASE_TRANSPORT_HDR].desc;
	if (desc == NULL)
		return 0;
	if (strcmp(desc->name, "tcp") == 0)
		return IPPROTO_TCP;
	else if (strcmp(desc->name, "udp") == 0)
		return IPPROTO_UDP;
	else if (strcmp(desc->name, "udplite") == 0)
		return IPPROTO_UDPLITE;
	else if (strcmp(desc->name, "sctp") == 0)
		return IPPROTO_SCTP;
	else if (strcmp(desc->name, "dccp") == 0)
		return IPPROTO_DCCP;
	else if (strcmp(desc->name, "esp") == 0)
		return IPPROTO_ESP;
	else if (strcmp(desc->name, "ah") == 0)
		return IPPROTO_AH;

	return 0;
}

static struct xtables_target *xt_target_clone(struct xtables_target *t)
{
	struct xtables_target *clone;

	clone = xzalloc(sizeof(struct xtables_target));
	memcpy(clone, t, sizeof(struct xtables_target));
	return clone;
}

static struct xtables_match *xt_match_clone(struct xtables_match *m)
{
	struct xtables_match *clone;

	clone = xzalloc(sizeof(struct xtables_match));
	memcpy(clone, m, sizeof(struct xtables_match));
	return clone;
}

/*
 * Delinearization
 */

void netlink_parse_match(struct netlink_parse_ctx *ctx,
			 const struct location *loc,
			 const struct nftnl_expr *nle)
{
	struct stmt *stmt;
	const char *name;
	struct xtables_match *mt;
	const char *mtinfo;
	struct xt_entry_match *m;
	uint32_t mt_len;

	xtables_set_nfproto(ctx->table->handle.family);

	name = nftnl_expr_get_str(nle, NFT_EXPR_MT_NAME);

	mt = xtables_find_match(name, XTF_TRY_LOAD, NULL);
	if (!mt)
		BUG("XT match %s not found\n", name);

	mtinfo = nftnl_expr_get(nle, NFT_EXPR_MT_INFO, &mt_len);

	m = xzalloc(sizeof(struct xt_entry_match) + mt_len);
	memcpy(&m->data, mtinfo, mt_len);

	m->u.match_size = mt_len + XT_ALIGN(sizeof(struct xt_entry_match));
	m->u.user.revision = nftnl_expr_get_u32(nle, NFT_EXPR_MT_REV);

	stmt = xt_stmt_alloc(loc);
	stmt->xt.name = strdup(name);
	stmt->xt.type = NFT_XT_MATCH;
	stmt->xt.match = xt_match_clone(mt);
	stmt->xt.match->m = m;

	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

void netlink_parse_target(struct netlink_parse_ctx *ctx,
			  const struct location *loc,
			  const struct nftnl_expr *nle)
{
	struct stmt *stmt;
	const char *name;
	struct xtables_target *tg;
	const void *tginfo;
	struct xt_entry_target *t;
	size_t size;
	uint32_t tg_len;

	xtables_set_nfproto(ctx->table->handle.family);

	name = nftnl_expr_get_str(nle, NFT_EXPR_TG_NAME);
	tg = xtables_find_target(name, XTF_TRY_LOAD);
	if (!tg)
		BUG("XT target %s not found\n", name);

	tginfo = nftnl_expr_get(nle, NFT_EXPR_TG_INFO, &tg_len);

	size = XT_ALIGN(sizeof(struct xt_entry_target)) + tg_len;
	t = xzalloc(size);
	memcpy(&t->data, tginfo, tg_len);
	t->u.target_size = size;
	t->u.user.revision = nftnl_expr_get_u32(nle, NFT_EXPR_TG_REV);
	strcpy(t->u.user.name, tg->name);

	stmt = xt_stmt_alloc(loc);
	stmt->xt.name = strdup(name);
	stmt->xt.type = NFT_XT_TARGET;
	stmt->xt.target = xt_target_clone(tg);
	stmt->xt.target->t = t;

	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static bool is_watcher(uint32_t family, struct stmt *stmt)
{
	if (family != NFPROTO_BRIDGE ||
	    stmt->xt.type != NFT_XT_TARGET)
		return false;

	/* this has to be hardcoded :-( */
	if (strcmp(stmt->xt.name, "log") == 0)
		return true;
	else if (strcmp(stmt->xt.name, "nflog") == 0)
		return true;

	return false;
}

void stmt_xt_postprocess(struct rule_pp_ctx *rctx, struct stmt *stmt,
			 struct rule *rule)
{
	if (is_watcher(rctx->pctx.family, stmt))
		stmt->xt.type = NFT_XT_WATCHER;

	stmt->xt.proto = xt_proto(&rctx->pctx);
	stmt->xt.entry = xt_entry_alloc(&stmt->xt, rctx->pctx.family);
}

static int nft_xt_compatible_revision(const char *name, uint8_t rev, int opt)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, type;
	struct nfgenmsg *nfg;
	int ret = 0;

	if (opt == IPT_SO_GET_REVISION_MATCH)
		type = 0;
	else
		type = 1;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFT_COMPAT << 8) | NFNL_MSG_COMPAT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	mnl_attr_put_strz(nlh, NFTA_COMPAT_NAME, name);
	mnl_attr_put_u32(nlh, NFTA_COMPAT_REV, htonl(rev));
	mnl_attr_put_u32(nlh, NFTA_COMPAT_TYPE, htonl(type));

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL)
		return 0;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		goto err;

	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		goto err;

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1)
		goto err;

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1)
		goto err;

err:
	mnl_socket_close(nl);

	return ret < 0 ? 0 : 1;
}

static struct option original_opts[] = {
	{ NULL },
};

static struct xtables_globals xt_nft_globals = {
	.program_name		= "nft",
	.program_version	= PACKAGE_VERSION,
	.orig_opts		= original_opts,
	.compat_rev		= nft_xt_compatible_revision,
};

static void __init xt_init(void)
{
	/* Default to IPv4, but this changes in runtime */
	xtables_init_all(&xt_nft_globals, NFPROTO_IPV4);
}
