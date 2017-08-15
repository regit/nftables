/*
 * Conntrack expression related definitions and types.
 *
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

#include <errno.h>
#include <erec.h>
#include <expression.h>
#include <datatype.h>
#include <gmputil.h>
#include <ct.h>
#include <gmputil.h>
#include <utils.h>
#include <statement.h>

#define CONNLABEL_CONF	DEFAULT_INCLUDE_PATH "/connlabel.conf"

static const struct symbol_table ct_state_tbl = {
	.base		= BASE_HEXADECIMAL,
	.symbols	= {
		SYMBOL("invalid",	NF_CT_STATE_INVALID_BIT),
		SYMBOL("new",		NF_CT_STATE_BIT(IP_CT_NEW)),
		SYMBOL("established",	NF_CT_STATE_BIT(IP_CT_ESTABLISHED)),
		SYMBOL("related",	NF_CT_STATE_BIT(IP_CT_RELATED)),
		SYMBOL("untracked",	NF_CT_STATE_UNTRACKED_BIT),
		SYMBOL_LIST_END
	}
};

const struct datatype ct_state_type = {
	.type		= TYPE_CT_STATE,
	.name		= "ct_state",
	.desc		= "conntrack state",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &bitmask_type,
	.sym_tbl	= &ct_state_tbl,
};

static const struct symbol_table ct_dir_tbl = {
	.base		= BASE_DECIMAL,
	.symbols	= {
		SYMBOL("original",	IP_CT_DIR_ORIGINAL),
		SYMBOL("reply",		IP_CT_DIR_REPLY),
		SYMBOL_LIST_END
	}
};

const struct datatype ct_dir_type = {
	.type		= TYPE_CT_DIR,
	.name		= "ct_dir",
	.desc		= "conntrack direction",
	.byteorder	= BYTEORDER_INVALID,
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &ct_dir_tbl,
};

static const struct symbol_table ct_status_tbl = {
	/*
	 * There are more, but most of them don't make sense for filtering.
	 */
	.base		= BASE_HEXADECIMAL,
	.symbols	= {
		SYMBOL("expected",	IPS_EXPECTED),
		SYMBOL("seen-reply",	IPS_SEEN_REPLY),
		SYMBOL("assured",	IPS_ASSURED),
		SYMBOL("confirmed",	IPS_CONFIRMED),
		SYMBOL("snat",		IPS_SRC_NAT),
		SYMBOL("dnat",		IPS_DST_NAT),
		SYMBOL("dying",		IPS_DYING),
		SYMBOL_LIST_END
	},
};

const struct datatype ct_status_type = {
	.type		= TYPE_CT_STATUS,
	.name		= "ct_status",
	.desc		= "conntrack status",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &bitmask_type,
	.sym_tbl	= &ct_status_tbl,
};

static const struct symbol_table ct_events_tbl = {
	.base		= BASE_HEXADECIMAL,
	.symbols	= {
		SYMBOL("new",		1 << IPCT_NEW),
		SYMBOL("related",	1 << IPCT_RELATED),
		SYMBOL("destroy",	1 << IPCT_DESTROY),
		SYMBOL("reply",		1 << IPCT_REPLY),
		SYMBOL("assured",	1 << IPCT_ASSURED),
		SYMBOL("protoinfo",	1 << IPCT_PROTOINFO),
		SYMBOL("helper",	1 << IPCT_HELPER),
		SYMBOL("mark",		1 << IPCT_MARK),
		SYMBOL("seqadj",	1 << IPCT_SEQADJ),
		SYMBOL("secmark",	1 << IPCT_SECMARK),
		SYMBOL("label",		1 << IPCT_LABEL),
		SYMBOL_LIST_END
	},
};

static const struct datatype ct_event_type = {
	.type		= TYPE_CT_EVENTBIT,
	.name		= "ct_event",
	.desc		= "conntrack event bits",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &bitmask_type,
	.sym_tbl	= &ct_events_tbl,
};

static struct symbol_table *ct_label_tbl;

#define CT_LABEL_BIT_SIZE 128

static void ct_label_type_print(const struct expr *expr,
				 struct output_ctx *octx)
{
	unsigned long bit = mpz_scan1(expr->value, 0);
	const struct symbolic_constant *s;

	for (s = ct_label_tbl->symbols; s->identifier != NULL; s++) {
		if (bit != s->value)
			continue;
		octx->print(octx->ctx, "\"%s\"", s->identifier);
		return;
	}
	/* can happen when connlabel.conf is altered after rules were added */
	octx->print(octx->ctx, "%ld\n", (long)mpz_scan1(expr->value, 0));
}

static struct error_record *ct_label_type_parse(const struct expr *sym,
						struct expr **res)
{
	const struct symbolic_constant *s;
	const struct datatype *dtype;
	uint8_t data[CT_LABEL_BIT_SIZE];
	uint64_t bit;
	mpz_t value;

	for (s = ct_label_tbl->symbols; s->identifier != NULL; s++) {
		if (!strcmp(sym->identifier, s->identifier))
			break;
	}

	dtype = sym->dtype;
	if (s->identifier == NULL) {
		char *ptr;

		errno = 0;
		bit = strtoull(sym->identifier, &ptr, 0);
		if (*ptr)
			return error(&sym->location, "%s: could not parse %s \"%s\"",
				     CONNLABEL_CONF, dtype->desc, sym->identifier);
		if (errno)
			return error(&sym->location, "%s: could not parse %s \"%s\": %s",
				     CONNLABEL_CONF, dtype->desc, sym->identifier, strerror(errno));

	} else {
		bit = s->value;
	}

	if (bit >= CT_LABEL_BIT_SIZE)
		return error(&sym->location, "%s: bit %" PRIu64 " out of range (%u max)",
			     sym->identifier, bit, CT_LABEL_BIT_SIZE);

	mpz_init2(value, dtype->size);
	mpz_setbit(value, bit);
	mpz_export_data(data, value, BYTEORDER_HOST_ENDIAN, sizeof(data));

	*res = constant_expr_alloc(&sym->location, dtype,
				   dtype->byteorder, sizeof(data),
				   data);
	mpz_clear(value);
	return NULL;
}

static const struct datatype ct_label_type = {
	.type		= TYPE_CT_LABEL,
	.name		= "ct_label",
	.desc		= "conntrack label",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= CT_LABEL_BIT_SIZE,
	.basetype	= &bitmask_type,
	.print		= ct_label_type_print,
	.parse		= ct_label_type_parse,
};

void ct_label_table_init(void)
{
	ct_label_tbl = rt_symbol_table_init(CONNLABEL_CONF);
}

void ct_label_table_exit(void)
{
	rt_symbol_table_free(ct_label_tbl);
}

#ifndef NF_CT_HELPER_NAME_LEN
#define NF_CT_HELPER_NAME_LEN	16
#endif

static const struct ct_template ct_templates[] = {
	[NFT_CT_STATE]		= CT_TEMPLATE("state",	    &ct_state_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_DIRECTION]	= CT_TEMPLATE("direction",  &ct_dir_type,
					      BYTEORDER_HOST_ENDIAN,
					      BITS_PER_BYTE),
	[NFT_CT_STATUS]		= CT_TEMPLATE("status",	    &ct_status_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_MARK]		= CT_TEMPLATE("mark",	    &mark_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_EXPIRATION]	= CT_TEMPLATE("expiration", &time_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_HELPER]		= CT_TEMPLATE("helper",	    &string_type,
					      BYTEORDER_HOST_ENDIAN,
					      NF_CT_HELPER_NAME_LEN * BITS_PER_BYTE),
	[NFT_CT_L3PROTOCOL]	= CT_TEMPLATE("l3proto",    &nfproto_type,
					      BYTEORDER_HOST_ENDIAN,
					      BITS_PER_BYTE),
	[NFT_CT_SRC]		= CT_TEMPLATE("saddr",	    &invalid_type,
					      BYTEORDER_BIG_ENDIAN, 0),
	[NFT_CT_DST]		= CT_TEMPLATE("daddr",	    &invalid_type,
					      BYTEORDER_BIG_ENDIAN, 0),
	[NFT_CT_PROTOCOL]	= CT_TEMPLATE("protocol",   &inet_protocol_type,
					      BYTEORDER_BIG_ENDIAN,
					      BITS_PER_BYTE),
	[NFT_CT_PROTO_SRC]	= CT_TEMPLATE("proto-src",  &invalid_type,
					      BYTEORDER_BIG_ENDIAN,
					      2 * BITS_PER_BYTE),
	[NFT_CT_PROTO_DST]	= CT_TEMPLATE("proto-dst",  &invalid_type,
					      BYTEORDER_BIG_ENDIAN,
					      2 * BITS_PER_BYTE),
	[NFT_CT_LABELS]		= CT_TEMPLATE("label", &ct_label_type,
					      BYTEORDER_HOST_ENDIAN,
					      CT_LABEL_BIT_SIZE),
	[NFT_CT_BYTES]		= CT_TEMPLATE("bytes", &integer_type,
					      BYTEORDER_HOST_ENDIAN, 64),
	[NFT_CT_PKTS]		= CT_TEMPLATE("packets", &integer_type,
					      BYTEORDER_HOST_ENDIAN, 64),
	[NFT_CT_AVGPKT]		= CT_TEMPLATE("avgpkt", &integer_type,
					      BYTEORDER_HOST_ENDIAN, 64),
	[NFT_CT_ZONE]		= CT_TEMPLATE("zone", &integer_type,
					      BYTEORDER_HOST_ENDIAN, 16),
	[NFT_CT_EVENTMASK]	= CT_TEMPLATE("event", &ct_event_type,
					      BYTEORDER_HOST_ENDIAN, 32),
};

static void ct_print(enum nft_ct_keys key, int8_t dir, struct output_ctx *octx)
{
	const struct symbolic_constant *s;

	octx->print(octx->ctx, "ct ");
	if (dir < 0)
		goto done;

	for (s = ct_dir_tbl.symbols; s->identifier != NULL; s++) {
		if (dir == (int)s->value) {
			octx->print(octx->ctx, "%s ", s->identifier);
			break;
		}
	}
 done:
	octx->print(octx->ctx, "%s", ct_templates[key].token);
}

static void ct_expr_print(const struct expr *expr, struct output_ctx *octx)
{
	ct_print(expr->ct.key, expr->ct.direction, octx);
}

static bool ct_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	if (e1->ct.key != e2->ct.key)
		return false;

	return e1->ct.direction == e2->ct.direction;
}

static void ct_expr_clone(struct expr *new, const struct expr *expr)
{
	new->ct = expr->ct;
}

static void ct_expr_pctx_update(struct proto_ctx *ctx, const struct expr *expr)
{
	const struct expr *left = expr->left, *right = expr->right;
	const struct proto_desc *base, *desc;

	assert(expr->op == OP_EQ);

	switch (left->ct.key) {
	case NFT_CT_PROTOCOL:
		base = ctx->protocol[PROTO_BASE_NETWORK_HDR].desc;
		desc = proto_find_upper(base, mpz_get_uint32(right->value));

		proto_ctx_update(ctx, PROTO_BASE_TRANSPORT_HDR,
				 &expr->location, desc);
		break;
	default:
		break;
	}
}

static const struct expr_ops ct_expr_ops = {
	.type		= EXPR_CT,
	.name		= "ct",
	.print		= ct_expr_print,
	.cmp		= ct_expr_cmp,
	.clone		= ct_expr_clone,
	.pctx_update	= ct_expr_pctx_update,
};

struct error_record *ct_dir_parse(const struct location *loc, const char *str,
				  int8_t *direction)
{
	const struct symbolic_constant *s;

	for (s = ct_dir_tbl.symbols; s->identifier != NULL; s++) {
		if (!strcmp(str, s->identifier)) {
			*direction = s->value;
			return NULL;
		}
	}

	return error(loc, "Could not parse direction %s", str);
}

struct error_record *ct_key_parse(const struct location *loc, const char *str,
				  unsigned int *key)
{
	int ret, len, offset = 0;
	const char *sep = "";
	unsigned int i;
	char buf[1024];
	size_t size;

	for (i = 0; i < array_size(ct_templates); i++) {
		if (!ct_templates[i].token || strcmp(ct_templates[i].token, str))
			continue;

		*key = i;
		return NULL;
	}

	len = (int)sizeof(buf);
	size = sizeof(buf);

	for (i = 0; i < array_size(ct_templates); i++) {
		if (!ct_templates[i].token)
			continue;

		if (offset)
			sep = ", ";

		ret = snprintf(buf+offset, len, "%s%s", sep, ct_templates[i].token);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		assert(offset < (int)sizeof(buf));
	}

	return error(loc, "syntax error, unexpected %s, known keys are %s", str, buf);
}

struct error_record *ct_objtype_parse(const struct location *loc, const char *str, int *type)
{
	if (strcmp(str, "helper") == 0) {
		*type = NFT_OBJECT_CT_HELPER;
		return NULL;
	}

	return error(loc, "unknown ct class '%s', want 'helper'", str);
}

struct expr *ct_expr_alloc(const struct location *loc, enum nft_ct_keys key,
			   int8_t direction)
{
	const struct ct_template *tmpl = &ct_templates[key];
	struct expr *expr;

	expr = expr_alloc(loc, &ct_expr_ops, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->ct.key = key;
	expr->ct.direction = direction;

	switch (key) {
	case NFT_CT_PROTOCOL:
		expr->flags = EXPR_F_PROTOCOL;
		break;
	default:
		break;
	}

	return expr;
}

void ct_expr_update_type(struct proto_ctx *ctx, struct expr *expr)
{
	const struct proto_desc *desc;

	switch (expr->ct.key) {
	case NFT_CT_SRC:
	case NFT_CT_DST:
		desc = ctx->protocol[PROTO_BASE_NETWORK_HDR].desc;
		if (desc == &proto_ip)
			expr->dtype = &ipaddr_type;
		else if (desc == &proto_ip6)
			expr->dtype = &ip6addr_type;

		expr->len = expr->dtype->size;
		break;
	case NFT_CT_PROTO_SRC:
	case NFT_CT_PROTO_DST:
		desc = ctx->protocol[PROTO_BASE_TRANSPORT_HDR].desc;
		if (desc == NULL)
			break;
		expr->dtype = &inet_service_type;
		break;
	default:
		break;
	}
}

static void ct_stmt_print(const struct stmt *stmt, struct output_ctx *octx)
{
	ct_print(stmt->ct.key, stmt->ct.direction, octx);
	octx->print(octx->ctx, " set ");
	expr_print(stmt->ct.expr, octx);
}

static const struct stmt_ops ct_stmt_ops = {
	.type		= STMT_CT,
	.name		= "ct",
	.print		= ct_stmt_print,
};

struct stmt *ct_stmt_alloc(const struct location *loc, enum nft_ct_keys key,
			   int8_t direction, struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &ct_stmt_ops);
	stmt->ct.key	= key;
	stmt->ct.tmpl	= &ct_templates[key];
	stmt->ct.expr	= expr;
	stmt->ct.direction = direction;

	return stmt;
}

static void notrack_stmt_print(const struct stmt *stmt, struct output_ctx *octx)
{
	octx->print(octx->ctx, "notrack");
}

static const struct stmt_ops notrack_stmt_ops = {
	.type		= STMT_NOTRACK,
	.name		= "notrack",
	.print		= notrack_stmt_print,
};

struct stmt *notrack_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &notrack_stmt_ops);
}
