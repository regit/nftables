/*
 * Routing expression related definition and types.
 *
 * Copyright (c) 2016 Anders K. Pedersen <akp@cohaesio.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <expression.h>
#include <datatype.h>
#include <rt.h>
#include <rule.h>

static struct symbol_table *realm_tbl;
static void __init realm_table_init(void)
{
	realm_tbl = rt_symbol_table_init("/etc/iproute2/rt_realms");
}

static void __exit realm_table_exit(void)
{
	rt_symbol_table_free(realm_tbl);
}

static void realm_type_print(const struct expr *expr, struct output_ctx *octx)
{
	return symbolic_constant_print(realm_tbl, expr, true, octx);
}

static struct error_record *realm_type_parse(const struct expr *sym,
					     struct expr **res)
{
	return symbolic_constant_parse(sym, realm_tbl, res);
}

const struct datatype realm_type = {
	.type		= TYPE_REALM,
	.name		= "realm",
	.desc		= "routing realm",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= realm_type_print,
	.parse		= realm_type_parse,
	.flags		= DTYPE_F_PREFIX,
};

static const struct rt_template rt_templates[] = {
	[NFT_RT_CLASSID]	= RT_TEMPLATE("classid",
					      &realm_type,
					      4 * BITS_PER_BYTE,
					      BYTEORDER_HOST_ENDIAN,
					      false),
	[NFT_RT_NEXTHOP4]	= RT_TEMPLATE("nexthop",
					      &ipaddr_type,
					      4 * BITS_PER_BYTE,
					      BYTEORDER_BIG_ENDIAN,
					      true),
	[NFT_RT_NEXTHOP6]	= RT_TEMPLATE("nexthop",
					      &ip6addr_type,
					      16 * BITS_PER_BYTE,
					      BYTEORDER_BIG_ENDIAN,
					      true),
};

static void rt_expr_print(const struct expr *expr, struct output_ctx *octx)
{
	printf("rt %s", rt_templates[expr->rt.key].token);
}

static bool rt_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->rt.key == e2->rt.key;
}

static void rt_expr_clone(struct expr *new, const struct expr *expr)
{
	new->rt.key = expr->rt.key;
}

static const struct expr_ops rt_expr_ops = {
	.type		= EXPR_RT,
	.name		= "rt",
	.print		= rt_expr_print,
	.cmp		= rt_expr_cmp,
	.clone		= rt_expr_clone,
};

struct expr *rt_expr_alloc(const struct location *loc, enum nft_rt_keys key,
			   bool invalid)
{
	const struct rt_template *tmpl = &rt_templates[key];
	struct expr *expr;

	if (invalid && tmpl->invalid)
		expr = expr_alloc(loc, &rt_expr_ops, &invalid_type,
				  tmpl->byteorder, 0);
	else
		expr = expr_alloc(loc, &rt_expr_ops, tmpl->dtype,
				  tmpl->byteorder, tmpl->len);
	expr->rt.key = key;

	return expr;
}

void rt_expr_update_type(struct proto_ctx *ctx, struct expr *expr)
{
	const struct proto_desc *desc;

	switch (expr->rt.key) {
	case NFT_RT_NEXTHOP4:
		desc = ctx->protocol[PROTO_BASE_NETWORK_HDR].desc;
		if (desc == &proto_ip)
			expr->dtype = &ipaddr_type;
		else if (desc == &proto_ip6) {
			expr->rt.key++;
			expr->dtype = &ip6addr_type;
		}
		expr->len = expr->dtype->size;
		break;
	default:
		break;
	}
}
