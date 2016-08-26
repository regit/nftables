/*
 * Hash expression definitions.
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
#include <hash.h>
#include <utils.h>

static void hash_expr_print(const struct expr *expr)
{
	printf("jhash ");
	expr_print(expr->hash.expr);
	printf(" mod %u", expr->hash.mod);
	if (expr->hash.seed)
		printf(" seed 0x%x", expr->hash.seed);
}

static bool hash_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return expr_cmp(e1->hash.expr, e2->hash.expr) &&
	       e1->hash.mod == e2->hash.mod &&
	       e1->hash.seed == e2->hash.seed;
}

static void hash_expr_clone(struct expr *new, const struct expr *expr)
{
	new->hash.expr = expr_clone(expr->hash.expr);
	new->hash.mod = expr->hash.mod;
	new->hash.seed = expr->hash.seed;
}

static const struct expr_ops hash_expr_ops = {
	.type		= EXPR_HASH,
	.name		= "hash",
	.print		= hash_expr_print,
	.cmp		= hash_expr_cmp,
	.clone		= hash_expr_clone,
};

struct expr *hash_expr_alloc(const struct location *loc, uint32_t mod,
			     uint32_t seed)
{
	struct expr *expr;

	expr = expr_alloc(loc, &hash_expr_ops, &integer_type,
			  BYTEORDER_HOST_ENDIAN, 4 * BITS_PER_BYTE);
	expr->hash.mod  = mod;
	expr->hash.seed = seed;

	return expr;
}
