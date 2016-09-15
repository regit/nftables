/*
 * FIB expression.
 *
 * Copyright (c) Red Hat GmbH.  Author: Florian Westphal <fw@strlen.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <nftables.h>
#include <erec.h>
#include <expression.h>
#include <datatype.h>
#include <gmputil.h>
#include <utils.h>
#include <string.h>
#include <fib.h>

#include <linux/rtnetlink.h>
#include <net/if.h>

static const char *fib_result[NFT_FIB_RESULT_MAX + 1] = {
	[NFT_FIB_RESULT_OIF] = "oif",
	[NFT_FIB_RESULT_OIFNAME] = "oifname",
	[NFT_FIB_RESULT_ADDRTYPE] = "type",
};

static const struct symbol_table addrtype_tbl = {
	.symbols	= {
		SYMBOL("unspec",	RTN_UNSPEC),
		SYMBOL("unicast",	RTN_UNICAST),
		SYMBOL("local",		RTN_LOCAL),
		SYMBOL("broadcast",	RTN_BROADCAST),
		SYMBOL("anycast",	RTN_ANYCAST),
		SYMBOL("multicast",	RTN_MULTICAST),
		SYMBOL("blackhole",	RTN_BLACKHOLE),
		SYMBOL("unreachable",	RTN_UNREACHABLE),
		SYMBOL("prohibit",	RTN_PROHIBIT),
		SYMBOL_LIST_END
	}
};

static const struct datatype fib_addr_type = {
	.type		= TYPE_FIB_ADDR,
	.name		= "fib_addrtype",
	.desc		= "fib address type",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &addrtype_tbl,
};

static const char *fib_result_str(enum nft_fib_result result)
{
	if (result <= NFT_FIB_RESULT_MAX)
		return fib_result[result];

	return "unknown";
}

static void __fib_expr_print_f(unsigned int *flags, unsigned int f, const char *s)
{
	if ((*flags & f) == 0)
		return;

	printf("%s", s);
	*flags &= ~f;
	if (*flags)
		printf(" . ");
}

static void fib_expr_print(const struct expr *expr)
{
	unsigned int flags = expr->fib.flags;

	printf("fib ");
	__fib_expr_print_f(&flags, NFTA_FIB_F_SADDR, "saddr");
	__fib_expr_print_f(&flags, NFTA_FIB_F_DADDR, "daddr");
	__fib_expr_print_f(&flags, NFTA_FIB_F_MARK, "mark");
	__fib_expr_print_f(&flags, NFTA_FIB_F_IIF, "iif");
	__fib_expr_print_f(&flags, NFTA_FIB_F_OIF, "oif");

	if (flags)
		printf("0x%x", flags);

	printf(" %s", fib_result_str(expr->fib.result));
}

static bool fib_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return  e1->fib.result == e2->fib.result &&
		e1->fib.flags == e2->fib.flags;
}

static void fib_expr_clone(struct expr *new, const struct expr *expr)
{
	new->fib.result = expr->fib.result;
	new->fib.flags= expr->fib.flags;
}

static const struct expr_ops fib_expr_ops = {
	.type		= EXPR_FIB,
	.name		= "fib",
	.print		= fib_expr_print,
	.cmp		= fib_expr_cmp,
	.clone		= fib_expr_clone,
};

struct expr *fib_expr_alloc(const struct location *loc,
			    unsigned int flags, unsigned int result)
{
	const struct datatype *type;
	unsigned int len = 4 * BITS_PER_BYTE;
	struct expr *expr;

	switch (result) {
	case NFT_FIB_RESULT_OIF:
		type = &ifindex_type;
		break;
	case NFT_FIB_RESULT_OIFNAME:
		type = &string_type;
		len = IFNAMSIZ * BITS_PER_BYTE;
		break;
	case NFT_FIB_RESULT_ADDRTYPE:
		type = &fib_addr_type;
		break;
	default:
		BUG("Unknown result %d\n", result);
	}

	expr = expr_alloc(loc, &fib_expr_ops, type,
			  BYTEORDER_HOST_ENDIAN, len);

	expr->fib.result = result;
	expr->fib.flags	= flags;

	return expr;
}

static void __init fib_init(void)
{
	datatype_register(&fib_addr_type);
}
