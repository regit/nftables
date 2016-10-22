/*
 * Number generator expression definitions.
 *
 * Copyright (c) 2016 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <nftables.h>
#include <expression.h>
#include <datatype.h>
#include <gmputil.h>
#include <numgen.h>
#include <utils.h>

static const char *numgen_type[NFT_NG_RANDOM + 1] = {
	[NFT_NG_INCREMENTAL]	= "inc",
	[NFT_NG_RANDOM]		= "random",
};

static const char *numgen_type_str(enum nft_ng_types type)
{
	if (type > NFT_NG_RANDOM)
		return "[unknown numgen]";

	return numgen_type[type];
}

static void numgen_expr_print(const struct expr *expr)
{
	printf("numgen %s mod %u", numgen_type_str(expr->numgen.type),
	       expr->numgen.mod);
	if (expr->numgen.offset)
		printf(" offset %u", expr->numgen.offset);
}

static bool numgen_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->numgen.type == e2->numgen.type &&
	       e1->numgen.mod == e2->numgen.mod &&
	       e1->numgen.offset == e2->numgen.offset;
}

static void numgen_expr_clone(struct expr *new, const struct expr *expr)
{
	new->numgen.type = expr->numgen.type;
	new->numgen.mod = expr->numgen.mod;
	new->numgen.offset = expr->numgen.offset;
}

static const struct expr_ops numgen_expr_ops = {
	.type		= EXPR_NUMGEN,
	.name		= "numgen",
	.print		= numgen_expr_print,
	.cmp		= numgen_expr_cmp,
	.clone		= numgen_expr_clone,
};

struct expr *numgen_expr_alloc(const struct location *loc,
			       enum nft_ng_types type, uint32_t mod,
			       uint32_t offset)
{
	struct expr *expr;

	expr = expr_alloc(loc, &numgen_expr_ops, &integer_type,
			  BYTEORDER_HOST_ENDIAN, 4 * BITS_PER_BYTE);
	expr->numgen.type  = type;
	expr->numgen.mod   = mod;
	expr->numgen.offset = offset;

	return expr;
}
