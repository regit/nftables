/*
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
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter/nf_tables.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <expression.h>
#include <statement.h>
#include <rule.h>
#include <erec.h>
#include <gmputil.h>
#include <utils.h>
#include <xt.h>

static int expr_evaluate(struct eval_ctx *ctx, struct expr **expr);

static const char *byteorder_names[] = {
	[BYTEORDER_INVALID]		= "invalid",
	[BYTEORDER_HOST_ENDIAN]		= "host endian",
	[BYTEORDER_BIG_ENDIAN]		= "big endian",
};

#define chain_error(ctx, s1, fmt, args...) \
	__stmt_binary_error(ctx, &(s1)->location, NULL, fmt, ## args)
#define monitor_error(ctx, s1, fmt, args...) \
	__stmt_binary_error(ctx, &(s1)->location, NULL, fmt, ## args)
#define cmd_error(ctx, fmt, args...) \
	__stmt_binary_error(ctx, &(ctx->cmd)->location, NULL, fmt, ## args)

static int __fmtstring(3, 4) set_error(struct eval_ctx *ctx,
				       const struct set *set,
				       const char *fmt, ...)
{
	struct error_record *erec;
	va_list ap;

	va_start(ap, fmt);
	erec = erec_vcreate(EREC_ERROR, &set->location, fmt, ap);
	va_end(ap);
	erec_queue(erec, ctx->msgs);
	return -1;
}

static struct expr *implicit_set_declaration(struct eval_ctx *ctx,
					     const char *name,
					     const struct datatype *keytype,
					     unsigned int keylen,
					     struct expr *expr)
{
	struct cmd *cmd;
	struct set *set;
	struct handle h;

	set = set_alloc(&expr->location);
	set->flags	= NFT_SET_ANONYMOUS | expr->set_flags;
	set->handle.set = xstrdup(name),
	set->keytype 	= keytype;
	set->keylen	= keylen;
	set->init	= expr;

	if (ctx->table != NULL)
		list_add_tail(&set->list, &ctx->table->sets);
	else {
		handle_merge(&set->handle, &ctx->cmd->handle);
		memset(&h, 0, sizeof(h));
		handle_merge(&h, &set->handle);
		cmd = cmd_alloc(CMD_ADD, CMD_OBJ_SET, &h, &expr->location, set);
		cmd->location = set->location;
		list_add_tail(&cmd->list, &ctx->cmd->list);
	}

	return set_ref_expr_alloc(&expr->location, set);
}

static enum ops byteorder_conversion_op(struct expr *expr,
					enum byteorder byteorder)
{
	switch (expr->byteorder) {
	case BYTEORDER_HOST_ENDIAN:
		if (byteorder == BYTEORDER_BIG_ENDIAN)
			return OP_HTON;
		break;
	case BYTEORDER_BIG_ENDIAN:
		if (byteorder == BYTEORDER_HOST_ENDIAN)
			return OP_NTOH;
		break;
	default:
		break;
	}
	BUG("invalid byte order conversion %u => %u\n",
	    expr->byteorder, byteorder);
}

static int byteorder_conversion(struct eval_ctx *ctx, struct expr **expr,
				enum byteorder byteorder)
{
	enum ops op;

	assert(!expr_is_constant(*expr) || expr_is_singleton(*expr));

	if ((*expr)->byteorder == byteorder)
		return 0;
	if (expr_basetype(*expr)->type != TYPE_INTEGER)
		return expr_error(ctx->msgs, *expr,
			 	  "Byteorder mismatch: expected %s, got %s",
				  byteorder_names[byteorder],
				  byteorder_names[(*expr)->byteorder]);

	if (expr_is_constant(*expr))
		(*expr)->byteorder = byteorder;
	else {
		op = byteorder_conversion_op(*expr, byteorder);
		*expr = unary_expr_alloc(&(*expr)->location, op, *expr);
		if (expr_evaluate(ctx, expr) < 0)
			return -1;
	}
	return 0;
}

static struct table *table_lookup_global(struct eval_ctx *ctx)
{
	struct table *table;

	if (ctx->table != NULL)
		return ctx->table;

	table = table_lookup(&ctx->cmd->handle);
	if (table == NULL)
		return NULL;

	return table;
}

/*
 * Symbol expression: parse symbol and evaluate resulting expression.
 */
static int expr_evaluate_symbol(struct eval_ctx *ctx, struct expr **expr)
{
	struct error_record *erec;
	struct symbol *sym;
	struct table *table;
	struct set *set;
	struct expr *new;
	int ret;

	switch ((*expr)->symtype) {
	case SYMBOL_VALUE:
		(*expr)->dtype = ctx->ectx.dtype;
		erec = symbol_parse(*expr, &new);
		if (erec != NULL) {
			erec_queue(erec, ctx->msgs);
			return -1;
		}
		break;
	case SYMBOL_DEFINE:
		sym = symbol_lookup((*expr)->scope, (*expr)->identifier);
		if (sym == NULL)
			return expr_error(ctx->msgs, *expr,
					  "undefined identifier '%s'",
					  (*expr)->identifier);
		new = expr_clone(sym->expr);
		break;
	case SYMBOL_SET:
		ret = cache_update(ctx->cmd->op, ctx->msgs);
		if (ret < 0)
			return ret;

		table = table_lookup_global(ctx);
		if (table == NULL)
			return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
					 ctx->cmd->handle.table);

		set = set_lookup(table, (*expr)->identifier);
		if (set == NULL)
			return cmd_error(ctx, "Could not process rule: Set '%s' does not exist",
					 (*expr)->identifier);
		new = set_ref_expr_alloc(&(*expr)->location, set);
		break;
	}

	expr_free(*expr);
	*expr = new;

	return expr_evaluate(ctx, expr);
}

static int expr_evaluate_string(struct eval_ctx *ctx, struct expr **exprp)
{
	struct expr *expr = *exprp;
	unsigned int len = div_round_up(expr->len, BITS_PER_BYTE), datalen;
	struct expr *value, *prefix;
	int data_len = ctx->ectx.len > 0 ? ctx->ectx.len : len + 1;
	char data[data_len];

	if (ctx->ectx.len > 0) {
		if (expr->len > ctx->ectx.len)
			return expr_error(ctx->msgs, expr,
					  "String exceeds maximum length of %u",
					  ctx->ectx.len / BITS_PER_BYTE);
		expr->len = ctx->ectx.len;
	}

	memset(data + len, 0, data_len - len);
	mpz_export_data(data, expr->value, BYTEORDER_HOST_ENDIAN, len);

	assert(strlen(data) > 0);
	datalen = strlen(data) - 1;
	if (data[datalen] != '*') {
		/* We need to reallocate the constant expression with the right
		 * expression length to avoid problems on big endian.
		 */
		value = constant_expr_alloc(&expr->location, &string_type,
					    BYTEORDER_HOST_ENDIAN,
					    expr->len, data);
		expr_free(expr);
		*exprp = value;
		return 0;
	}

	if (datalen >= 1 &&
	    data[datalen - 1] == '\\') {
		char unescaped_str[data_len];

		memset(unescaped_str, 0, sizeof(unescaped_str));
		xstrunescape(data, unescaped_str);

		value = constant_expr_alloc(&expr->location, &string_type,
					    BYTEORDER_HOST_ENDIAN,
					    expr->len, unescaped_str);
		expr_free(expr);
		*exprp = value;
		return 0;
	}
	value = constant_expr_alloc(&expr->location, &string_type,
				    BYTEORDER_HOST_ENDIAN,
				    datalen * BITS_PER_BYTE, data);

	prefix = prefix_expr_alloc(&expr->location, value,
				   datalen * BITS_PER_BYTE);
	prefix->dtype = &string_type;
	prefix->flags |= EXPR_F_CONSTANT;
	prefix->byteorder = BYTEORDER_HOST_ENDIAN;

	expr_free(expr);
	*exprp = prefix;
	return 0;
}

static int expr_evaluate_integer(struct eval_ctx *ctx, struct expr **exprp)
{
	struct expr *expr = *exprp;
	char *valstr, *rangestr;
	mpz_t mask;

	if (ctx->ectx.maxval > 0 &&
	    mpz_cmp_ui(expr->value, ctx->ectx.maxval) > 0) {
		valstr = mpz_get_str(NULL, 10, expr->value);
		expr_error(ctx->msgs, expr,
			   "Value %s exceeds valid range 0-%u",
			   valstr, ctx->ectx.maxval);
		free(valstr);
		return -1;
	}

	mpz_init_bitmask(mask, ctx->ectx.len);
	if (mpz_cmp(expr->value, mask) > 0) {
		valstr = mpz_get_str(NULL, 10, expr->value);
		rangestr = mpz_get_str(NULL, 10, mask);
		expr_error(ctx->msgs, expr,
			   "Value %s exceeds valid range 0-%s",
			   valstr, rangestr);
		free(valstr);
		free(rangestr);
		mpz_clear(mask);
		return -1;
	}
	expr->byteorder = ctx->ectx.byteorder;
	expr->len = ctx->ectx.len;
	mpz_clear(mask);
	return 0;
}

static int expr_evaluate_value(struct eval_ctx *ctx, struct expr **expr)
{
	switch (expr_basetype(*expr)->type) {
	case TYPE_INTEGER:
		if (expr_evaluate_integer(ctx, expr) < 0)
			return -1;
		break;
	case TYPE_STRING:
		if (expr_evaluate_string(ctx, expr) < 0)
			return -1;
		break;
	default:
		BUG("invalid basetype %s\n", expr_basetype(*expr)->name);
	}
	return 0;
}

/*
 * Primary expressions determine the datatype context.
 */
static int expr_evaluate_primary(struct eval_ctx *ctx, struct expr **expr)
{
	__expr_set_context(&ctx->ectx, (*expr)->dtype, (*expr)->byteorder,
			   (*expr)->len, 0);
	return 0;
}

static int
conflict_resolution_gen_dependency(struct eval_ctx *ctx, int protocol,
				   const struct expr *expr,
				   struct stmt **res)
{
	enum proto_bases base = expr->payload.base;
	const struct proto_hdr_template *tmpl;
	const struct proto_desc *desc = NULL;
	struct expr *dep, *left, *right;
	struct stmt *stmt;

	assert(expr->payload.base == PROTO_BASE_LL_HDR);

	desc = ctx->pctx.protocol[base].desc;
	tmpl = &desc->templates[desc->protocol_key];
	left = payload_expr_alloc(&expr->location, desc, desc->protocol_key);

	right = constant_expr_alloc(&expr->location, tmpl->dtype,
				    tmpl->dtype->byteorder, tmpl->len,
				    constant_data_ptr(protocol, tmpl->len));

	dep = relational_expr_alloc(&expr->location, OP_EQ, left, right);
	stmt = expr_stmt_alloc(&dep->location, dep);
	if (stmt_evaluate(ctx, stmt) < 0)
		return expr_error(ctx->msgs, expr,
					  "dependency statement is invalid");

	*res = stmt;
	return 0;
}

static uint8_t expr_offset_shift(const struct expr *expr, unsigned int offset,
				 unsigned int *extra_len)
{
	unsigned int new_offset, len;
	int shift;

	new_offset = offset % BITS_PER_BYTE;
	len = round_up(expr->len, BITS_PER_BYTE);
	shift = len - (new_offset + expr->len);
	while (shift < 0) {
		shift += BITS_PER_BYTE;
		*extra_len += BITS_PER_BYTE;
	}
	return shift;
}

static void expr_evaluate_bits(struct eval_ctx *ctx, struct expr **exprp)
{
	struct expr *expr = *exprp, *and, *mask, *lshift, *off;
	unsigned masklen, len = expr->len, extra_len = 0;
	uint8_t shift;
	mpz_t bitmask;

	switch (expr->ops->type) {
	case EXPR_PAYLOAD:
		shift = expr_offset_shift(expr, expr->payload.offset,
					  &extra_len);
		break;
	case EXPR_EXTHDR:
		shift = expr_offset_shift(expr, expr->exthdr.tmpl->offset,
					  &extra_len);
		break;
	default:
		BUG("Unknown expression %s\n", expr->ops->name);
	}

	masklen = len + shift;
	assert(masklen <= NFT_REG_SIZE * BITS_PER_BYTE);

	mpz_init2(bitmask, masklen);
	mpz_bitmask(bitmask, len);
	mpz_lshift_ui(bitmask, shift);

	mask = constant_expr_alloc(&expr->location, expr_basetype(expr),
				   BYTEORDER_HOST_ENDIAN, masklen, NULL);
	mpz_set(mask->value, bitmask);

	and = binop_expr_alloc(&expr->location, OP_AND, expr, mask);
	and->dtype	= expr->dtype;
	and->byteorder	= expr->byteorder;
	and->len	= masklen;

	if (shift) {
		off = constant_expr_alloc(&expr->location,
					  expr_basetype(expr),
					  BYTEORDER_BIG_ENDIAN,
					  sizeof(shift), &shift);

		lshift = binop_expr_alloc(&expr->location, OP_RSHIFT, and, off);
		lshift->dtype		= expr->dtype;
		lshift->byteorder	= expr->byteorder;
		lshift->len		= masklen;

		*exprp = lshift;
	} else
		*exprp = and;

	if (extra_len)
		expr->len += extra_len;
}

static int __expr_evaluate_exthdr(struct eval_ctx *ctx, struct expr **exprp)
{
	struct expr *expr = *exprp;

	if (expr_evaluate_primary(ctx, exprp) < 0)
		return -1;

	if (expr->exthdr.tmpl->offset % BITS_PER_BYTE != 0 ||
	    expr->len % BITS_PER_BYTE != 0)
		expr_evaluate_bits(ctx, exprp);

	return 0;
}

/*
 * Exthdr expression: check whether dependencies are fulfilled, otherwise
 * generate the necessary relational expression and prepend it to the current
 * statement.
 */
static int expr_evaluate_exthdr(struct eval_ctx *ctx, struct expr **exprp)
{
	const struct proto_desc *base;
	struct expr *expr = *exprp;
	struct stmt *nstmt;

	base = ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR].desc;
	if (base == &proto_ip6)
		return __expr_evaluate_exthdr(ctx, exprp);

	if (base)
		return expr_error(ctx->msgs, expr,
				  "cannot use exthdr with %s", base->name);

	if (exthdr_gen_dependency(ctx, expr, &nstmt) < 0)
		return -1;

	list_add(&nstmt->list, &ctx->rule->stmts);

	return __expr_evaluate_exthdr(ctx, exprp);
}

/* dependency supersede.
 *
 * 'inet' is a 'phony' l2 dependeny used by NFPROTO_INET to fulfill network
 * header dependency, i.e. ensure that 'ip saddr 1.2.3.4' only sees ip headers.
 *
 * If a match expression that depends on a particular L2 header, e.g. ethernet,
 * is used, we thus get a conflict since we already have a l2 header dependency.
 *
 * But in the inet case we can just ignore the conflict since only another
 * restriction is added, and these are not mutually exclusive.
 *
 * Example: inet filter in ip saddr 1.2.3.4 ether saddr a:b:c:d:e:f
 *
 * ip saddr adds meta dependency on ipv4 packets
 * ether saddr adds another dependeny on ethernet frames.
 */
static int meta_iiftype_gen_dependency(struct eval_ctx *ctx,
				       struct expr *payload, struct stmt **res)
{
	struct stmt *nstmt;
	uint16_t type;

	if (proto_dev_type(payload->payload.desc, &type) < 0)
		return expr_error(ctx->msgs, payload,
				  "protocol specification is invalid "
				  "for this family");

	nstmt = meta_stmt_meta_iiftype(&payload->location, type);
	if (stmt_evaluate(ctx, nstmt) < 0)
		return expr_error(ctx->msgs, payload,
				  "dependency statement is invalid");

	*res = nstmt;
	return 0;
}

static bool proto_is_dummy(const struct proto_desc *desc)
{
	return desc == &proto_inet || desc == &proto_netdev;
}

static int resolve_protocol_conflict(struct eval_ctx *ctx,
				     const struct proto_desc *desc,
				     struct expr *payload)
{
	enum proto_bases base = payload->payload.base;
	struct stmt *nstmt = NULL;
	int link, err;

	if (payload->payload.base == PROTO_BASE_LL_HDR &&
	    proto_is_dummy(desc)) {
		err = meta_iiftype_gen_dependency(ctx, payload, &nstmt);
		if (err < 0)
			return err;

		list_add_tail(&nstmt->list, &ctx->stmt->list);
	}

	assert(base <= PROTO_BASE_MAX);
	/* This payload and the existing context don't match, conflict. */
	if (ctx->pctx.protocol[base + 1].desc != NULL)
		return 1;

	link = proto_find_num(desc, payload->payload.desc);
	if (link < 0 ||
	    conflict_resolution_gen_dependency(ctx, link, payload, &nstmt) < 0)
		return 1;

	payload->payload.offset += ctx->pctx.protocol[base].offset;
	list_add_tail(&nstmt->list, &ctx->stmt->list);

	return 0;
}

/*
 * Payload expression: check whether dependencies are fulfilled, otherwise
 * generate the necessary relational expression and prepend it to the current
 * statement.
 */
static int __expr_evaluate_payload(struct eval_ctx *ctx, struct expr *expr)
{
	struct expr *payload = expr;
	enum proto_bases base = payload->payload.base;
	const struct proto_desc *desc;
	struct stmt *nstmt;
	int err;

	desc = ctx->pctx.protocol[base].desc;
	if (desc == NULL) {
		if (payload_gen_dependency(ctx, payload, &nstmt) < 0)
			return -1;
		list_add_tail(&nstmt->list, &ctx->stmt->list);
	} else {
		/* No conflict: Same payload protocol as context, adjust offset
		 * if needed.
		 */
		if (desc == payload->payload.desc) {
			payload->payload.offset +=
				ctx->pctx.protocol[base].offset;
			return 0;
		}
		/* If we already have context and this payload is on the same
		 * base, try to resolve the protocol conflict.
		 */
		if (payload->payload.base == desc->base) {
			err = resolve_protocol_conflict(ctx, desc, payload);
			if (err <= 0)
				return err;

			desc = ctx->pctx.protocol[base].desc;
			if (desc == payload->payload.desc)
				return 0;
		}
		return expr_error(ctx->msgs, payload,
				  "conflicting protocols specified: %s vs. %s",
				  ctx->pctx.protocol[base].desc->name,
				  payload->payload.desc->name);
	}
	return 0;
}

static bool payload_needs_adjustment(const struct expr *expr)
{
	return expr->payload.offset % BITS_PER_BYTE != 0 ||
	       expr->len % BITS_PER_BYTE != 0;
}

static int expr_evaluate_payload(struct eval_ctx *ctx, struct expr **exprp)
{
	struct expr *expr = *exprp;

	if (__expr_evaluate_payload(ctx, expr) < 0)
		return -1;

	if (expr_evaluate_primary(ctx, exprp) < 0)
		return -1;

	if (payload_needs_adjustment(expr))
		expr_evaluate_bits(ctx, exprp);

	return 0;
}

/*
 * RT expression: validate protocol dependencies.
 */
static int expr_evaluate_rt(struct eval_ctx *ctx, struct expr **expr)
{
	const struct proto_desc *base;
	struct expr *rt = *expr;

	rt_expr_update_type(&ctx->pctx, rt);

	base = ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR].desc;
	switch (rt->rt.key) {
	case NFT_RT_NEXTHOP4:
		if (base != &proto_ip)
			goto err;
		break;
	case NFT_RT_NEXTHOP6:
		if (base != &proto_ip6)
			goto err;
		break;
	default:
		break;
	}

	return expr_evaluate_primary(ctx, expr);

err:
	return expr_error(ctx->msgs, rt,
			  "meta nfproto ipv4 or ipv6 must be specified "
			  "before routing expression");
}

/*
 * CT expression: update the protocol dependant types bases on the protocol
 * context.
 */
static int expr_evaluate_ct(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *ct = *expr;

	ct_expr_update_type(&ctx->pctx, ct);

	return expr_evaluate_primary(ctx, expr);
}

/*
 * Prefix expression: the argument must be a constant value of integer or
 * string base type; the prefix length must be less than or equal to the type
 * width.
 */
static int expr_evaluate_prefix(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *prefix = *expr, *base, *and, *mask;

	if (expr_evaluate(ctx, &prefix->prefix) < 0)
		return -1;
	base = prefix->prefix;

	if (!expr_is_constant(base))
		return expr_error(ctx->msgs, prefix,
				  "Prefix expression is undefined for "
				  "non-constant expressions");

	switch (expr_basetype(base)->type) {
	case TYPE_INTEGER:
	case TYPE_STRING:
		break;
	default:
		return expr_error(ctx->msgs, prefix,
				  "Prefix expression is undefined for "
				  "%s types", base->dtype->desc);
	}

	if (prefix->prefix_len > base->len)
		return expr_error(ctx->msgs, prefix,
				  "Prefix length %u is invalid for type "
				  "of %u bits width",
				  prefix->prefix_len, base->len);

	/* Clear the uncovered bits of the base value */
	mask = constant_expr_alloc(&prefix->location, expr_basetype(base),
				   BYTEORDER_HOST_ENDIAN, base->len, NULL);
	switch (expr_basetype(base)->type) {
	case TYPE_INTEGER:
		mpz_prefixmask(mask->value, base->len, prefix->prefix_len);
		break;
	case TYPE_STRING:
		mpz_init2(mask->value, base->len);
		mpz_bitmask(mask->value, prefix->prefix_len);
		break;
	}
	and  = binop_expr_alloc(&prefix->location, OP_AND, base, mask);
	prefix->prefix = and;
	if (expr_evaluate(ctx, &prefix->prefix) < 0)
		return -1;
	base = prefix->prefix;
	assert(expr_is_constant(base));

	prefix->dtype	  = base->dtype;
	prefix->byteorder = base->byteorder;
	prefix->len	  = base->len;
	prefix->flags	 |= EXPR_F_CONSTANT;
	return 0;
}

/*
 * Range expression: both sides must be constants of integer base type.
 */
static int expr_evaluate_range_expr(struct eval_ctx *ctx,
				    const struct expr *range,
				    struct expr **expr)
{
	if (expr_evaluate(ctx, expr) < 0)
		return -1;

	if (expr_basetype(*expr)->type != TYPE_INTEGER)
		return expr_binary_error(ctx->msgs, *expr, range,
					 "Range expression is undefined for "
					 "%s types", (*expr)->dtype->desc);
	if (!expr_is_constant(*expr))
		return expr_binary_error(ctx->msgs, *expr, range,
					 "Range is not constant");
	return 0;
}

static int expr_evaluate_range(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *range = *expr, *left, *right;

	if (expr_evaluate_range_expr(ctx, range, &range->left) < 0)
		return -1;
	left = range->left;

	if (expr_evaluate_range_expr(ctx, range, &range->right) < 0)
		return -1;
	right = range->right;

	if (mpz_cmp(left->value, right->value) >= 0)
		return expr_error(ctx->msgs, range,
				  "Range has zero or negative size");

	range->dtype = left->dtype;
	range->flags |= EXPR_F_CONSTANT;
	return 0;
}

/*
 * Unary expressions: unary expressions are only generated internally for
 * byteorder conversion of non-constant numerical expressions.
 */
static int expr_evaluate_unary(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *unary = *expr, *arg;
	enum byteorder byteorder;

	if (expr_evaluate(ctx, &unary->arg) < 0)
		return -1;
	arg = unary->arg;

	assert(!expr_is_constant(arg));
	assert(expr_basetype(arg)->type == TYPE_INTEGER);
	assert(arg->ops->type != EXPR_UNARY);

	switch (unary->op) {
	case OP_HTON:
		assert(arg->byteorder == BYTEORDER_HOST_ENDIAN);
		byteorder = BYTEORDER_BIG_ENDIAN;
		break;
	case OP_NTOH:
		assert(arg->byteorder == BYTEORDER_BIG_ENDIAN);
		byteorder = BYTEORDER_HOST_ENDIAN;
		break;
	default:
		BUG("invalid unary operation %u\n", unary->op);
	}

	unary->dtype	 = arg->dtype;
	unary->byteorder = byteorder;
	unary->len	 = arg->len;
	return 0;
}

/*
 * Binops
 */
static int constant_binop_simplify(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *op = *expr, *left = (*expr)->left, *right = (*expr)->right;
	struct expr *new;
	mpz_t val, mask;

	assert(left->ops->type == EXPR_VALUE);
	assert(right->ops->type == EXPR_VALUE);
	assert(left->byteorder == right->byteorder);

	mpz_init2(val, op->len);
	mpz_init_bitmask(mask, op->len);

	switch (op->op) {
	case OP_AND:
		mpz_and(val, left->value, right->value);
		mpz_and(val, val, mask);
		break;
	case OP_XOR:
		mpz_xor(val, left->value, right->value);
		mpz_and(val, val, mask);
		break;
	case OP_OR:
		mpz_ior(val, left->value, right->value);
		mpz_and(val, val, mask);
		break;
	case OP_LSHIFT:
		assert(left->byteorder == BYTEORDER_HOST_ENDIAN);
		mpz_set(val, left->value);
		mpz_lshift_ui(val, mpz_get_uint32(right->value));
		mpz_and(val, val, mask);
		break;
	case OP_RSHIFT:
		assert(left->byteorder == BYTEORDER_HOST_ENDIAN);
		mpz_set(val, left->value);
		mpz_and(val, val, mask);
		mpz_rshift_ui(val, mpz_get_uint32(right->value));
		break;
	default:
		BUG("invalid binary operation %u\n", op->op);
	}

	new = constant_expr_alloc(&op->location, op->dtype, op->byteorder,
				  op->len, NULL);
	mpz_set(new->value, val);

	expr_free(*expr);
	*expr = new;

	mpz_clear(mask);
	mpz_clear(val);

	return expr_evaluate(ctx, expr);
}

static int expr_evaluate_shift(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *op = *expr, *left = op->left, *right = op->right;

	if (mpz_get_uint32(right->value) >= left->len)
		return expr_binary_error(ctx->msgs, right, left,
					 "%s shift of %u bits is undefined "
					 "for type of %u bits width",
					 op->op == OP_LSHIFT ? "Left" : "Right",
					 mpz_get_uint32(right->value),
					 left->len);

	/* Both sides need to be in host byte order */
	if (byteorder_conversion(ctx, &op->left, BYTEORDER_HOST_ENDIAN) < 0)
		return -1;
	left = op->left;
	if (byteorder_conversion(ctx, &op->right, BYTEORDER_HOST_ENDIAN) < 0)
		return -1;

	op->dtype     = &integer_type;
	op->byteorder = BYTEORDER_HOST_ENDIAN;
	op->len       = left->len;

	if (expr_is_constant(left))
		return constant_binop_simplify(ctx, expr);
	return 0;
}

static int expr_evaluate_bitwise(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *op = *expr, *left = op->left;

	if (byteorder_conversion(ctx, &op->right, left->byteorder) < 0)
		return -1;

	op->dtype     = left->dtype;
	op->byteorder = left->byteorder;
	op->len	      = left->len;

	if (expr_is_constant(left))
		return constant_binop_simplify(ctx, expr);
	return 0;
}

/*
 * Binop expression: both sides must be of integer base type. The left
 * hand side may be either constant or non-constant; in case its constant
 * it must be a singleton. The ride hand side must always be a constant
 * singleton.
 */
static int expr_evaluate_binop(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *op = *expr, *left, *right;
	const char *sym = expr_op_symbols[op->op];

	if (expr_evaluate(ctx, &op->left) < 0)
		return -1;
	left = op->left;

	if (op->op == OP_LSHIFT || op->op == OP_RSHIFT)
		expr_set_context(&ctx->ectx, &integer_type, ctx->ectx.len);
	if (expr_evaluate(ctx, &op->right) < 0)
		return -1;
	right = op->right;

	switch (expr_basetype(left)->type) {
	case TYPE_INTEGER:
	case TYPE_STRING:
		break;
	default:
		return expr_binary_error(ctx->msgs, left, op,
					 "Binary operation (%s) is undefined "
					 "for %s types",
					 sym, left->dtype->desc);
	}

	if (expr_is_constant(left) && !expr_is_singleton(left))
		return expr_binary_error(ctx->msgs, left, op,
					 "Binary operation (%s) is undefined "
					 "for %s expressions",
					 sym, left->ops->name);

	if (!expr_is_constant(right))
		return expr_binary_error(ctx->msgs, right, op,
					 "Right hand side of binary operation "
					 "(%s) must be constant", sym);

	if (!expr_is_singleton(right))
		return expr_binary_error(ctx->msgs, left, op,
					 "Binary operation (%s) is undefined "
					 "for %s expressions",
					 sym, right->ops->name);

	/* The grammar guarantees this */
	assert(expr_basetype(left) == expr_basetype(right));

	switch (op->op) {
	case OP_LSHIFT:
	case OP_RSHIFT:
		return expr_evaluate_shift(ctx, expr);
	case OP_AND:
	case OP_XOR:
	case OP_OR:
		return expr_evaluate_bitwise(ctx, expr);
	default:
		BUG("invalid binary operation %u\n", op->op);
	}
}

static int list_member_evaluate(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *next = list_entry((*expr)->list.next, struct expr, list);
	int err;

	assert(*expr != next);
	list_del(&(*expr)->list);
	err = expr_evaluate(ctx, expr);
	list_add_tail(&(*expr)->list, &next->list);
	return err;
}

static int expr_evaluate_concat(struct eval_ctx *ctx, struct expr **expr)
{
	const struct datatype *dtype = ctx->ectx.dtype, *tmp;
	uint32_t type = dtype ? dtype->type : 0, ntype = 0;
	int off = dtype ? dtype->subtypes : 0;
	unsigned int flags = EXPR_F_CONSTANT | EXPR_F_SINGLETON;
	struct expr *i, *next;

	list_for_each_entry_safe(i, next, &(*expr)->expressions, list) {
		if (expr_is_constant(*expr) && dtype && off == 0)
			return expr_binary_error(ctx->msgs, i, *expr,
						 "unexpected concat component, "
						 "expecting %s",
						 dtype->desc);

		if (dtype == NULL)
			tmp = datatype_lookup(TYPE_INVALID);
		else
			tmp = concat_subtype_lookup(type, --off);
		expr_set_context(&ctx->ectx, tmp, tmp->size);

		if (list_member_evaluate(ctx, &i) < 0)
			return -1;
		flags &= i->flags;

		if (dtype == NULL && i->dtype->size == 0)
			return expr_binary_error(ctx->msgs, i, *expr,
						 "can not use variable sized "
						 "data types (%s) in concat "
						 "expressions",
						 i->dtype->name);

		ntype = concat_subtype_add(ntype, i->dtype->type);
	}

	(*expr)->flags |= flags;
	(*expr)->dtype = concat_type_alloc(ntype);
	(*expr)->len   = (*expr)->dtype->size;

	if (off > 0)
		return expr_error(ctx->msgs, *expr,
				  "datatype mismatch, expected %s, "
				  "expression has type %s",
				  dtype->desc, (*expr)->dtype->desc);

	expr_set_context(&ctx->ectx, (*expr)->dtype, (*expr)->len);

	return 0;
}

static int expr_evaluate_list(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *list = *expr, *new, *i, *next;
	mpz_t val;

	mpz_init_set_ui(val, 0);
	list_for_each_entry_safe(i, next, &list->expressions, list) {
		if (list_member_evaluate(ctx, &i) < 0)
			return -1;
		if (i->ops->type != EXPR_VALUE)
			return expr_error(ctx->msgs, i,
					  "List member must be a constant "
					  "value");
		if (i->dtype->basetype->type != TYPE_BITMASK)
			return expr_error(ctx->msgs, i,
					  "Basetype of type %s is not bitmask",
					  i->dtype->desc);
		mpz_ior(val, val, i->value);
	}

	new = constant_expr_alloc(&list->location, ctx->ectx.dtype,
				  BYTEORDER_HOST_ENDIAN, ctx->ectx.len, NULL);
	mpz_set(new->value, val);
	mpz_clear(val);

	expr_free(*expr);
	*expr = new;
	return 0;
}

static int expr_evaluate_set_elem(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *elem = *expr;

	if (expr_evaluate(ctx, &elem->key) < 0)
		return -1;

	if (ctx->set &&
	    !(ctx->set->flags & (NFT_SET_ANONYMOUS | NFT_SET_INTERVAL))) {
		switch (elem->key->ops->type) {
		case EXPR_PREFIX:
			return expr_error(ctx->msgs, elem,
					  "Set member cannot be prefix, "
					  "missing interval flag on declaration");
		case EXPR_RANGE:
			return expr_error(ctx->msgs, elem,
					  "Set member cannot be range, "
					  "missing interval flag on declaration");
		default:
			break;
		}
	}

	elem->dtype = elem->key->dtype;
	elem->len   = elem->key->len;
	elem->flags = elem->key->flags;
	return 0;
}

static int expr_evaluate_set(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *set = *expr, *i, *next;

	list_for_each_entry_safe(i, next, &set->expressions, list) {
		if (list_member_evaluate(ctx, &i) < 0)
			return -1;

		if (i->ops->type == EXPR_SET_ELEM &&
		    i->key->ops->type == EXPR_SET_REF)
			return expr_error(ctx->msgs, i,
					  "Set reference cannot be part of another set");

		if (!expr_is_constant(i))
			return expr_error(ctx->msgs, i,
					  "Set member is not constant");

		if (i->ops->type == EXPR_SET) {
			/* Merge recursive set definitions */
			list_splice_tail_init(&i->expressions, &i->list);
			list_del(&i->list);
			set->size      += i->size;
			set->set_flags |= i->set_flags;
			expr_free(i);
		} else if (!expr_is_singleton(i))
			set->set_flags |= NFT_SET_INTERVAL;
	}

	set->set_flags |= NFT_SET_CONSTANT;

	set->dtype = ctx->ectx.dtype;
	set->len   = ctx->ectx.len;
	set->flags |= EXPR_F_CONSTANT;
	return 0;
}

static int expr_evaluate_map(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr_ctx ectx = ctx->ectx;
	struct expr *map = *expr, *mappings;

	expr_set_context(&ctx->ectx, NULL, 0);
	if (expr_evaluate(ctx, &map->map) < 0)
		return -1;
	if (expr_is_constant(map->map))
		return expr_error(ctx->msgs, map->map,
				  "Map expression can not be constant");

	mappings = map->mappings;
	mappings->set_flags |= NFT_SET_MAP;

	switch (map->mappings->ops->type) {
	case EXPR_SET:
		mappings = implicit_set_declaration(ctx, "__map%d",
						    ctx->ectx.dtype,
						    ctx->ectx.len, mappings);
		mappings->set->datatype = ectx.dtype;
		mappings->set->datalen  = ectx.len;

		map->mappings = mappings;

		ctx->set = mappings->set;
		if (expr_evaluate(ctx, &map->mappings->set->init) < 0)
			return -1;
		ctx->set = NULL;

		map->mappings->set->flags |= map->mappings->set->init->set_flags;
		break;
	case EXPR_SYMBOL:
		if (expr_evaluate(ctx, &map->mappings) < 0)
			return -1;
		if (map->mappings->ops->type != EXPR_SET_REF ||
		    !(map->mappings->set->flags & NFT_SET_MAP))
			return expr_error(ctx->msgs, map->mappings,
					  "Expression is not a map");
		break;
	default:
		BUG("invalid mapping expression %s\n",
		    map->mappings->ops->name);
	}

	if (!datatype_equal(map->map->dtype, map->mappings->set->keytype))
		return expr_binary_error(ctx->msgs, map->mappings, map->map,
					 "datatype mismatch, map expects %s, "
					 "mapping expression has type %s",
					 map->mappings->set->keytype->desc,
					 map->map->dtype->desc);

	map->dtype = map->mappings->set->datatype;
	map->flags |= EXPR_F_CONSTANT;

	/* Data for range lookups needs to be in big endian order */
	if (map->mappings->set->flags & NFT_SET_INTERVAL &&
	    byteorder_conversion(ctx, &map->map, BYTEORDER_BIG_ENDIAN) < 0)
		return -1;

	return 0;
}

static int expr_evaluate_mapping(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *mapping = *expr;
	struct set *set = ctx->set;

	if (set == NULL)
		return expr_error(ctx->msgs, mapping,
				  "mapping outside of map context");
	if (!(set->flags & (NFT_SET_MAP | NFT_SET_OBJECT)))
		return set_error(ctx, set, "set is not a map");

	expr_set_context(&ctx->ectx, set->keytype, set->keylen);
	if (expr_evaluate(ctx, &mapping->left) < 0)
		return -1;
	if (!expr_is_constant(mapping->left))
		return expr_error(ctx->msgs, mapping->left,
				  "Key must be a constant");
	mapping->flags |= mapping->left->flags & EXPR_F_SINGLETON;

	expr_set_context(&ctx->ectx, set->datatype, set->datalen);
	if (expr_evaluate(ctx, &mapping->right) < 0)
		return -1;
	if (!expr_is_constant(mapping->right))
		return expr_error(ctx->msgs, mapping->right,
				  "Value must be a constant");
	if (!expr_is_singleton(mapping->right))
		return expr_error(ctx->msgs, mapping->right,
				  "Value must be a singleton");

	mapping->flags |= EXPR_F_CONSTANT;
	return 0;
}

/* We got datatype context via statement. If the basetype is compatible, set
 * this expression datatype to the one of the statement to make it datatype
 * compatible. This is a more conservative approach than enabling datatype
 * compatibility between two different datatypes whose basetype is the same,
 * let's revisit this later once users come with valid usecases to generalize
 * this.
 */
static void expr_dtype_integer_compatible(struct eval_ctx *ctx,
					  struct expr *expr)
{
	if (ctx->ectx.dtype &&
	    ctx->ectx.dtype->basetype == &integer_type &&
	    ctx->ectx.len == 4 * BITS_PER_BYTE) {
		expr->dtype = ctx->ectx.dtype;
		expr->len   = ctx->ectx.len;
	}
}

static int expr_evaluate_numgen(struct eval_ctx *ctx, struct expr **exprp)
{
	struct expr *expr = *exprp;

	expr_dtype_integer_compatible(ctx, expr);

	__expr_set_context(&ctx->ectx, expr->dtype, expr->byteorder, expr->len,
			   expr->numgen.mod - 1);
	return 0;
}

static int expr_evaluate_hash(struct eval_ctx *ctx, struct expr **exprp)
{
	struct expr *expr = *exprp;

	expr_dtype_integer_compatible(ctx, expr);

	expr_set_context(&ctx->ectx, NULL, 0);
	if (expr_evaluate(ctx, &expr->hash.expr) < 0)
		return -1;

	/* expr_evaluate_primary() sets the context to what to the input
         * expression to be hashed. Since this input is transformed to a 4 bytes
	 * integer, restore context to the datatype that results from hashing.
	 */
	__expr_set_context(&ctx->ectx, expr->dtype, expr->byteorder, expr->len,
			   expr->hash.mod - 1);

	return 0;
}

/*
 * Transfer the invertible binops to the constant side of an equality
 * expression. A left shift is only invertible if the low n bits are
 * zero.
 */
static int binop_can_transfer(struct eval_ctx *ctx,
			      struct expr *left, struct expr *right)
{
	switch (left->op) {
	case OP_LSHIFT:
		if (mpz_scan1(right->value, 0) < mpz_get_uint32(left->right->value))
			return expr_binary_error(ctx->msgs, right, left,
						 "Comparison is always false");
		return 1;
	case OP_RSHIFT:
		if (ctx->ectx.len < right->len + mpz_get_uint32(left->right->value))
			ctx->ectx.len += mpz_get_uint32(left->right->value);
		return 1;
	case OP_XOR:
		return 1;
	default:
		return 0;
	}
}

static int binop_transfer_one(struct eval_ctx *ctx,
			      const struct expr *left, struct expr **right)
{
	expr_get(*right);

	switch (left->op) {
	case OP_LSHIFT:
		(*right) = binop_expr_alloc(&(*right)->location, OP_RSHIFT,
					    *right, expr_get(left->right));
		break;
	case OP_RSHIFT:
		(*right) = binop_expr_alloc(&(*right)->location, OP_LSHIFT,
					    *right, expr_get(left->right));
		break;
	case OP_XOR:
		(*right) = binop_expr_alloc(&(*right)->location, OP_XOR,
					    *right, expr_get(left->right));
		break;
	default:
		BUG("invalid binary operation %u\n", left->op);
	}

	return expr_evaluate(ctx, right);
}

static int binop_transfer(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *left = (*expr)->left, *i, *next;
	unsigned int shift;
	int err;

	if (left->ops->type != EXPR_BINOP)
		return 0;

	switch ((*expr)->right->ops->type) {
	case EXPR_VALUE:
		err = binop_can_transfer(ctx, left, (*expr)->right);
		if (err <= 0)
			return err;
		if (binop_transfer_one(ctx, left, &(*expr)->right) < 0)
			return -1;
		break;
	case EXPR_RANGE:
		err = binop_can_transfer(ctx, left, (*expr)->right->left);
		if (err <= 0)
			return err;
		err = binop_can_transfer(ctx, left, (*expr)->right->right);
		if (err <= 0)
			return err;
		if (binop_transfer_one(ctx, left, &(*expr)->right->left) < 0)
			return -1;
		if (binop_transfer_one(ctx, left, &(*expr)->right->right) < 0)
			return -1;
		break;
	case EXPR_SET:
		list_for_each_entry(i, &(*expr)->right->expressions, list) {
			err = binop_can_transfer(ctx, left, i);
			if (err <= 0)
				return err;
		}
		list_for_each_entry_safe(i, next, &(*expr)->right->expressions,
					 list) {
			list_del(&i->list);
			if (binop_transfer_one(ctx, left, &i) < 0)
				return -1;
			list_add_tail(&i->list, &next->list);
		}
		break;
	case EXPR_SET_REF:
		list_for_each_entry(i, &(*expr)->right->set->init->expressions, list) {
			switch (i->key->ops->type) {
			case EXPR_VALUE:
				err = binop_can_transfer(ctx, left, i->key);
				if (err <= 0)
					return err;
				break;
			case EXPR_RANGE:
				err = binop_can_transfer(ctx, left, i->key->left);
				if (err <= 0)
					return err;
				err = binop_can_transfer(ctx, left, i->key->right);
				if (err <= 0)
					return err;
				break;
			default:
				break;
			}
		}
		list_for_each_entry_safe(i, next, &(*expr)->right->set->init->expressions,
					 list) {
			list_del(&i->list);
			switch (i->key->ops->type) {
			case EXPR_VALUE:
				if (binop_transfer_one(ctx, left, &i->key) < 0)
					return -1;
				break;
			case EXPR_RANGE:
				if (binop_transfer_one(ctx, left, &i->key->left) < 0)
					return -1;
				if (binop_transfer_one(ctx, left, &i->key->right) < 0)
					return -1;
				break;
			default:
				break;
			}
			list_add_tail(&i->list, &next->list);
		}
		break;
	default:
		return 0;
	}

	switch (left->op) {
	case OP_RSHIFT:
		/* Mask out the bits the shift would have masked out */
		shift = mpz_get_uint8(left->right->value);
		mpz_bitmask(left->right->value, left->left->len);
		mpz_lshift_ui(left->right->value, shift);
		left->op = OP_AND;
		break;
	case OP_LSHIFT:
	case OP_XOR:
		left = expr_get((*expr)->left->left);
		left->dtype = (*expr)->left->dtype;
		expr_free((*expr)->left);
		(*expr)->left = left;
		break;
	default:
		BUG("invalid binop operation %u", left->op);
	}
	return 0;
}

static int expr_evaluate_relational(struct eval_ctx *ctx, struct expr **expr)
{
	struct expr *rel = *expr, *left, *right;

	if (expr_evaluate(ctx, &rel->left) < 0)
		return -1;
	left = rel->left;

	if (expr_evaluate(ctx, &rel->right) < 0)
		return -1;
	right = rel->right;

	if (rel->op == OP_IMPLICIT) {
		switch (right->ops->type) {
		case EXPR_RANGE:
			rel->op = OP_RANGE;
			break;
		case EXPR_SET:
		case EXPR_SET_REF:
			rel->op = OP_LOOKUP;
			break;
		case EXPR_LIST:
			rel->op = OP_FLAGCMP;
			break;
		default:
			if (right->dtype->basetype != NULL &&
			    right->dtype->basetype->type == TYPE_BITMASK)
				rel->op = OP_FLAGCMP;
			else
				rel->op = OP_EQ;
			break;
		}
	}

	if (!expr_is_constant(right))
		return expr_binary_error(ctx->msgs, right, rel,
					 "Right hand side of relational "
					 "expression (%s) must be constant",
					 expr_op_symbols[rel->op]);
	if (expr_is_constant(left))
		return expr_binary_error(ctx->msgs, left, right,
					 "Relational expression (%s) has "
					 "constant value",
					 expr_op_symbols[rel->op]);

	switch (rel->op) {
	case OP_LOOKUP:
		/* A literal set expression implicitly declares the set */
		if (right->ops->type == EXPR_SET)
			right = rel->right =
				implicit_set_declaration(ctx, "__set%d",
							 left->dtype,
							 left->len, right);
		else if (!datatype_equal(left->dtype, right->dtype))
			return expr_binary_error(ctx->msgs, right, left,
						 "datatype mismatch, expected %s, "
						 "set has type %s",
						 left->dtype->desc,
						 right->dtype->desc);

		/* Data for range lookups needs to be in big endian order */
		if (right->set->flags & NFT_SET_INTERVAL &&
		    byteorder_conversion(ctx, &rel->left,
					 BYTEORDER_BIG_ENDIAN) < 0)
			return -1;
		left = rel->left;
		break;
	case OP_EQ:
		if (!datatype_equal(left->dtype, right->dtype))
			return expr_binary_error(ctx->msgs, right, left,
						 "datatype mismatch, expected %s, "
						 "expression has type %s",
						 left->dtype->desc,
						 right->dtype->desc);
		/*
		 * Update protocol context for payload and meta iiftype
		 * equality expressions.
		 */
		if (left->flags & EXPR_F_PROTOCOL &&
		    left->ops->pctx_update)
			left->ops->pctx_update(&ctx->pctx, rel);

		if (left->ops->type == EXPR_CONCAT)
			return 0;

		/* fall through */
	case OP_NEQ:
	case OP_FLAGCMP:
		if (!datatype_equal(left->dtype, right->dtype))
			return expr_binary_error(ctx->msgs, right, left,
						 "datatype mismatch, expected %s, "
						 "expression has type %s",
						 left->dtype->desc,
						 right->dtype->desc);

		switch (right->ops->type) {
		case EXPR_RANGE:
			goto range;
		case EXPR_PREFIX:
			if (byteorder_conversion(ctx, &right->prefix, left->byteorder) < 0)
				return -1;
			break;
		case EXPR_VALUE:
			if (byteorder_conversion(ctx, &rel->right, left->byteorder) < 0)
				return -1;
			break;
		case EXPR_SET:
			assert(rel->op == OP_NEQ);
			right = rel->right =
				implicit_set_declaration(ctx, "__set%d",
							 left->dtype, left->len,
							 right);
			/* fall through */
		case EXPR_SET_REF:
			assert(rel->op == OP_NEQ);
			/* Data for range lookups needs to be in big endian order */
			if (right->set->flags & NFT_SET_INTERVAL &&
			    byteorder_conversion(ctx, &rel->left, BYTEORDER_BIG_ENDIAN) < 0)
				return -1;
			break;
		default:
			BUG("invalid expression type %s\n", right->ops->name);
		}
		break;
	case OP_LT:
	case OP_GT:
	case OP_LTE:
	case OP_GTE:
		if (!datatype_equal(left->dtype, right->dtype))
			return expr_binary_error(ctx->msgs, right, left,
						 "datatype mismatch, expected %s, "
						 "expression has type %s",
						 left->dtype->desc,
						 right->dtype->desc);

		switch (left->ops->type) {
		case EXPR_CONCAT:
			return expr_binary_error(ctx->msgs, left, rel,
					"Relational expression (%s) is undefined "
				        "for %s expressions",
					expr_op_symbols[rel->op],
					left->ops->name);
		default:
			break;
		}

		if (!expr_is_singleton(right))
			return expr_binary_error(ctx->msgs, right, rel,
					"Relational expression (%s) is undefined "
				        "for %s expressions",
					expr_op_symbols[rel->op],
					right->ops->name);

		if (byteorder_conversion(ctx, &rel->left, BYTEORDER_BIG_ENDIAN) < 0)
			return -1;
		if (byteorder_conversion(ctx, &rel->right, BYTEORDER_BIG_ENDIAN) < 0)
			return -1;
		break;
	case OP_RANGE:
		if (!datatype_equal(left->dtype, right->dtype))
			return expr_binary_error(ctx->msgs, right, left,
						 "datatype mismatch, expected %s, "
						 "expression has type %s",
						 left->dtype->desc,
						 right->dtype->desc);

range:
		switch (left->ops->type) {
		case EXPR_CONCAT:
			return expr_binary_error(ctx->msgs, left, rel,
					"Relational expression (%s) is undefined"
				        "for %s expressions",
					expr_op_symbols[rel->op],
					left->ops->name);
		default:
			break;
		}

		if (byteorder_conversion(ctx, &rel->left, BYTEORDER_BIG_ENDIAN) < 0)
			return -1;
		if (byteorder_conversion(ctx, &right->left, BYTEORDER_BIG_ENDIAN) < 0)
			return -1;
		if (byteorder_conversion(ctx, &right->right, BYTEORDER_BIG_ENDIAN) < 0)
			return -1;
		break;
	default:
		BUG("invalid relational operation %u\n", rel->op);
	}

	if (binop_transfer(ctx, expr) < 0)
		return -1;

	return 0;
}

static int expr_evaluate(struct eval_ctx *ctx, struct expr **expr)
{
#ifdef DEBUG
	if (debug_level & DEBUG_EVALUATION) {
		struct error_record *erec;
		erec = erec_create(EREC_INFORMATIONAL, &(*expr)->location,
				   "Evaluate %s", (*expr)->ops->name);
		erec_print(stdout, erec); expr_print(*expr); printf("\n\n");
	}
#endif

	switch ((*expr)->ops->type) {
	case EXPR_SYMBOL:
		return expr_evaluate_symbol(ctx, expr);
	case EXPR_SET_REF:
		return 0;
	case EXPR_VALUE:
		return expr_evaluate_value(ctx, expr);
	case EXPR_EXTHDR:
		return expr_evaluate_exthdr(ctx, expr);
	case EXPR_VERDICT:
	case EXPR_META:
	case EXPR_FIB:
		return expr_evaluate_primary(ctx, expr);
	case EXPR_PAYLOAD:
		return expr_evaluate_payload(ctx, expr);
	case EXPR_RT:
		return expr_evaluate_rt(ctx, expr);
	case EXPR_CT:
		return expr_evaluate_ct(ctx, expr);
	case EXPR_PREFIX:
		return expr_evaluate_prefix(ctx, expr);
	case EXPR_RANGE:
		return expr_evaluate_range(ctx, expr);
	case EXPR_UNARY:
		return expr_evaluate_unary(ctx, expr);
	case EXPR_BINOP:
		return expr_evaluate_binop(ctx, expr);
	case EXPR_CONCAT:
		return expr_evaluate_concat(ctx, expr);
	case EXPR_LIST:
		return expr_evaluate_list(ctx, expr);
	case EXPR_SET:
		return expr_evaluate_set(ctx, expr);
	case EXPR_SET_ELEM:
		return expr_evaluate_set_elem(ctx, expr);
	case EXPR_MAP:
		return expr_evaluate_map(ctx, expr);
	case EXPR_MAPPING:
		return expr_evaluate_mapping(ctx, expr);
	case EXPR_RELATIONAL:
		return expr_evaluate_relational(ctx, expr);
	case EXPR_NUMGEN:
		return expr_evaluate_numgen(ctx, expr);
	case EXPR_HASH:
		return expr_evaluate_hash(ctx, expr);
	default:
		BUG("unknown expression type %s\n", (*expr)->ops->name);
	}
}

static int stmt_evaluate_expr(struct eval_ctx *ctx, struct stmt *stmt)
{
	memset(&ctx->ectx, 0, sizeof(ctx->ectx));
	return expr_evaluate(ctx, &stmt->expr);
}

static int stmt_evaluate_arg(struct eval_ctx *ctx, struct stmt *stmt,
			     const struct datatype *dtype, unsigned int len,
			     struct expr **expr)
{
	expr_set_context(&ctx->ectx, dtype, len);
	if (expr_evaluate(ctx, expr) < 0)
		return -1;

	if (!datatype_equal((*expr)->dtype, dtype))
		return stmt_binary_error(ctx, *expr, stmt,
					 "datatype mismatch: expected %s, "
					 "expression has type %s",
					 dtype->desc, (*expr)->dtype->desc);
	return 0;
}

static int stmt_evaluate_verdict(struct eval_ctx *ctx, struct stmt *stmt)
{
	if (stmt_evaluate_arg(ctx, stmt, &verdict_type, 0, &stmt->expr) < 0)
		return -1;

	switch (stmt->expr->ops->type) {
	case EXPR_VERDICT:
		if (stmt->expr->verdict != NFT_CONTINUE)
			stmt->flags |= STMT_F_TERMINAL;
		break;
	case EXPR_MAP:
		break;
	default:
		BUG("invalid verdict expression %s\n", stmt->expr->ops->name);
	}
	return 0;
}

static bool stmt_evaluate_payload_need_csum(const struct expr *payload)
{
	const struct proto_desc *desc;

	desc = payload->payload.desc;

	return desc && desc->checksum_key;
}

static int stmt_evaluate_payload(struct eval_ctx *ctx, struct stmt *stmt)
{
	struct expr *binop, *mask, *and, *payload_bytes;
	unsigned int masklen, extra_len = 0;
	unsigned int payload_byte_size, payload_byte_offset;
	uint8_t shift_imm, data[NFT_REG_SIZE];
	struct expr *payload;
	mpz_t bitmask, ff;
	bool need_csum;

	if (__expr_evaluate_payload(ctx, stmt->payload.expr) < 0)
		return -1;

	payload = stmt->payload.expr;
	if (stmt_evaluate_arg(ctx, stmt, payload->dtype, payload->len,
			      &stmt->payload.val) < 0)
		return -1;

	need_csum = stmt_evaluate_payload_need_csum(payload);

	if (!payload_needs_adjustment(payload)) {

		/* We still need to munge the payload in case we have to
		 * update checksum and the length is not even because
		 * kernel checksum functions cannot deal with odd lengths.
		 */
		if (!need_csum || ((payload->len / BITS_PER_BYTE) & 1) == 0)
			return 0;
	}

	payload_byte_offset = payload->payload.offset / BITS_PER_BYTE;

	shift_imm = expr_offset_shift(payload, payload->payload.offset,
				      &extra_len);
	if (shift_imm) {
		struct expr *off;

		off = constant_expr_alloc(&payload->location,
					  expr_basetype(payload),
					  BYTEORDER_HOST_ENDIAN,
					  sizeof(shift_imm), &shift_imm);

		binop = binop_expr_alloc(&payload->location, OP_LSHIFT,
					 stmt->payload.val, off);
		binop->dtype		= payload->dtype;
		binop->byteorder	= payload->byteorder;

		stmt->payload.val = binop;
	}

	payload_byte_size = round_up(payload->len, BITS_PER_BYTE) / BITS_PER_BYTE;
	payload_byte_size += (extra_len / BITS_PER_BYTE);

	if (need_csum && payload_byte_size & 1) {
		payload_byte_size++;

		if (payload_byte_offset & 1) { /* prefer 16bit aligned fetch */
			payload_byte_offset--;
			assert(payload->payload.offset >= BITS_PER_BYTE);
		}
	}

	masklen = payload_byte_size * BITS_PER_BYTE;
	mpz_init_bitmask(ff, masklen);

	mpz_init2(bitmask, masklen);
	mpz_bitmask(bitmask, payload->len);
	mpz_lshift_ui(bitmask, shift_imm);

	mpz_xor(bitmask, ff, bitmask);
	mpz_clear(ff);

	assert(sizeof(data) * BITS_PER_BYTE >= masklen);
	mpz_export_data(data, bitmask, BYTEORDER_HOST_ENDIAN, masklen);
	mask = constant_expr_alloc(&payload->location, expr_basetype(payload),
				   BYTEORDER_HOST_ENDIAN, masklen, data);

	payload_bytes = payload_expr_alloc(&payload->location, NULL, 0);
	payload_init_raw(payload_bytes, payload->payload.base,
			 payload_byte_offset * BITS_PER_BYTE,
			 payload_byte_size * BITS_PER_BYTE);

	payload_bytes->payload.desc	 = payload->payload.desc;
	payload_bytes->dtype		 = &integer_type;
	payload_bytes->byteorder	 = payload->byteorder;

	payload->len = payload_bytes->len;
	payload->payload.offset = payload_bytes->payload.offset;

	and = binop_expr_alloc(&payload->location, OP_AND, payload_bytes, mask);

	and->dtype		 = payload_bytes->dtype;
	and->byteorder		 = payload_bytes->byteorder;
	and->len		 = payload_bytes->len;

	binop = binop_expr_alloc(&payload->location, OP_XOR, and,
				 stmt->payload.val);
	binop->dtype		= payload->dtype;
	binop->byteorder	= payload->byteorder;
	binop->len		= mask->len;
	stmt->payload.val = binop;

	return expr_evaluate(ctx, &stmt->payload.val);
}

static int stmt_evaluate_flow(struct eval_ctx *ctx, struct stmt *stmt)
{
	struct expr *key, *set, *setref;

	expr_set_context(&ctx->ectx, NULL, 0);
	if (expr_evaluate(ctx, &stmt->flow.key) < 0)
		return -1;
	if (expr_is_constant(stmt->flow.key))
		return expr_error(ctx->msgs, stmt->flow.key,
				  "Flow key expression can not be constant");
	if (stmt->flow.key->comment)
		return expr_error(ctx->msgs, stmt->flow.key,
				  "Flow key expression can not contain comments");

	/* Declare an empty set */
	key = stmt->flow.key;
	set = set_expr_alloc(&key->location);
	set->set_flags |= NFT_SET_EVAL;
	if (key->timeout)
		set->set_flags |= NFT_SET_TIMEOUT;

	setref = implicit_set_declaration(ctx, stmt->flow.table ?: "__ft%d",
					  key->dtype, key->len, set);

	stmt->flow.set = setref;

	if (stmt_evaluate(ctx, stmt->flow.stmt) < 0)
		return -1;
	if (!(stmt->flow.stmt->flags & STMT_F_STATEFUL))
		return stmt_binary_error(ctx, stmt->flow.stmt, stmt,
					 "Per-flow statement must be stateful");

	return 0;
}

static int stmt_evaluate_meta(struct eval_ctx *ctx, struct stmt *stmt)
{
	return stmt_evaluate_arg(ctx, stmt,
				 stmt->meta.tmpl->dtype,
				 stmt->meta.tmpl->len,
				 &stmt->meta.expr);
}

static int stmt_evaluate_ct(struct eval_ctx *ctx, struct stmt *stmt)
{
	return stmt_evaluate_arg(ctx, stmt,
				 stmt->ct.tmpl->dtype,
				 stmt->ct.tmpl->len,
				 &stmt->ct.expr);
}

static int reject_payload_gen_dependency_tcp(struct eval_ctx *ctx,
					     struct stmt *stmt,
					     struct expr **payload)
{
	const struct proto_desc *desc;

	desc = ctx->pctx.protocol[PROTO_BASE_TRANSPORT_HDR].desc;
	if (desc != NULL)
		return 0;
	*payload = payload_expr_alloc(&stmt->location, &proto_tcp,
				      TCPHDR_UNSPEC);
	return 1;
}

static int reject_payload_gen_dependency_family(struct eval_ctx *ctx,
						struct stmt *stmt,
						struct expr **payload)
{
	const struct proto_desc *base;

	base = ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR].desc;
	if (base != NULL)
		return 0;

	if (stmt->reject.icmp_code < 0)
		return stmt_error(ctx, stmt, "missing icmp error type");

	/* Generate a network dependency */
	switch (stmt->reject.family) {
	case NFPROTO_IPV4:
		*payload = payload_expr_alloc(&stmt->location, &proto_ip,
					     IPHDR_PROTOCOL);
		break;
	case NFPROTO_IPV6:
		*payload = payload_expr_alloc(&stmt->location, &proto_ip6,
					     IP6HDR_NEXTHDR);
		break;
	default:
		BUG("unknown reject family");
	}
	return 1;
}

static int stmt_reject_gen_dependency(struct eval_ctx *ctx, struct stmt *stmt,
				      struct expr *expr)
{
	struct expr *payload = NULL;
	struct stmt *nstmt;
	int ret;

	switch (stmt->reject.type) {
	case NFT_REJECT_TCP_RST:
		ret = reject_payload_gen_dependency_tcp(ctx, stmt, &payload);
		break;
	case NFT_REJECT_ICMP_UNREACH:
		ret = reject_payload_gen_dependency_family(ctx, stmt, &payload);
		break;
	default:
		BUG("cannot generate reject dependency for type %d",
		    stmt->reject.type);
	}
	if (ret <= 0)
		return ret;

	if (payload_gen_dependency(ctx, payload, &nstmt) < 0)
		return -1;

	list_add(&nstmt->list, &ctx->rule->stmts);
	return 0;
}

static int stmt_evaluate_reject_inet_family(struct eval_ctx *ctx,
					    struct stmt *stmt,
					    const struct proto_desc *desc)
{
	const struct proto_desc *base;
	int protocol;

	switch (stmt->reject.type) {
	case NFT_REJECT_TCP_RST:
		break;
	case NFT_REJECT_ICMPX_UNREACH:
		return stmt_binary_error(ctx, stmt->reject.expr,
				    &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				    "conflicting network protocol specified");
	case NFT_REJECT_ICMP_UNREACH:
		base = ctx->pctx.protocol[PROTO_BASE_LL_HDR].desc;
		protocol = proto_find_num(base, desc);
		switch (protocol) {
		case NFPROTO_IPV4:
			if (stmt->reject.family == NFPROTO_IPV4)
				break;
			return stmt_binary_error(ctx, stmt->reject.expr,
				  &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				  "conflicting protocols specified: ip vs ip6");
		case NFPROTO_IPV6:
			if (stmt->reject.family == NFPROTO_IPV6)
				break;
			return stmt_binary_error(ctx, stmt->reject.expr,
				  &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				  "conflicting protocols specified: ip vs ip6");
		default:
			BUG("unsupported family");
		}
		break;
	}

	return 0;
}

static int stmt_evaluate_reject_inet(struct eval_ctx *ctx, struct stmt *stmt,
				     struct expr *expr)
{
	const struct proto_desc *desc;

	desc = ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR].desc;
	if (desc != NULL &&
	    stmt_evaluate_reject_inet_family(ctx, stmt, desc) < 0)
		return -1;
	if (stmt->reject.type == NFT_REJECT_ICMPX_UNREACH)
		return 0;
	if (stmt_reject_gen_dependency(ctx, stmt, expr) < 0)
		return -1;
	return 0;
}

static int stmt_evaluate_reject_bridge_family(struct eval_ctx *ctx,
					      struct stmt *stmt,
					      const struct proto_desc *desc)
{
	const struct proto_desc *base;
	int protocol;

	switch (stmt->reject.type) {
	case NFT_REJECT_ICMPX_UNREACH:
		return stmt_binary_error(ctx, stmt->reject.expr,
				    &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				    "conflicting network protocol specified");
	case NFT_REJECT_TCP_RST:
		base = ctx->pctx.protocol[PROTO_BASE_LL_HDR].desc;
		protocol = proto_find_num(base, desc);
		switch (protocol) {
		case __constant_htons(ETH_P_IP):
		case __constant_htons(ETH_P_IPV6):
			break;
		default:
			return stmt_binary_error(ctx, stmt,
				    &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				    "cannot reject this network family");
		}
		break;
	case NFT_REJECT_ICMP_UNREACH:
		base = ctx->pctx.protocol[PROTO_BASE_LL_HDR].desc;
		protocol = proto_find_num(base, desc);
		switch (protocol) {
		case __constant_htons(ETH_P_IP):
			if (NFPROTO_IPV4 == stmt->reject.family)
				break;
			return stmt_binary_error(ctx, stmt->reject.expr,
				  &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				  "conflicting protocols specified: ip vs ip6");
		case __constant_htons(ETH_P_IPV6):
			if (NFPROTO_IPV6 == stmt->reject.family)
				break;
			return stmt_binary_error(ctx, stmt->reject.expr,
				  &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				  "conflicting protocols specified: ip vs ip6");
		default:
			return stmt_binary_error(ctx, stmt,
				    &ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR],
				    "cannot reject this network family");
		}
		break;
	}

	return 0;
}

static int stmt_evaluate_reject_bridge(struct eval_ctx *ctx, struct stmt *stmt,
				       struct expr *expr)
{
	const struct proto_desc *desc;

	desc = ctx->pctx.protocol[PROTO_BASE_LL_HDR].desc;
	if (desc != &proto_eth)
		return stmt_binary_error(ctx,
					 &ctx->pctx.protocol[PROTO_BASE_LL_HDR],
					 stmt, "unsupported link layer protocol");

	desc = ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR].desc;
	if (desc != NULL &&
	    stmt_evaluate_reject_bridge_family(ctx, stmt, desc) < 0)
		return -1;
	if (stmt->reject.type == NFT_REJECT_ICMPX_UNREACH)
		return 0;
	if (stmt_reject_gen_dependency(ctx, stmt, expr) < 0)
		return -1;
	return 0;
}

static int stmt_evaluate_reject_family(struct eval_ctx *ctx, struct stmt *stmt,
				       struct expr *expr)
{
	switch (ctx->pctx.family) {
	case NFPROTO_ARP:
		return stmt_error(ctx, stmt, "cannot use reject with arp");
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
		switch (stmt->reject.type) {
		case NFT_REJECT_TCP_RST:
			if (stmt_reject_gen_dependency(ctx, stmt, expr) < 0)
				return -1;
			break;
		case NFT_REJECT_ICMPX_UNREACH:
			return stmt_binary_error(ctx, stmt->reject.expr, stmt,
				   "abstracted ICMP unreachable not supported");
		case NFT_REJECT_ICMP_UNREACH:
			if (stmt->reject.family == ctx->pctx.family)
				break;
			return stmt_binary_error(ctx, stmt->reject.expr, stmt,
				  "conflicting protocols specified: ip vs ip6");
		}
		break;
	case NFPROTO_BRIDGE:
		if (stmt_evaluate_reject_bridge(ctx, stmt, expr) < 0)
			return -1;
		break;
	case NFPROTO_INET:
		if (stmt_evaluate_reject_inet(ctx, stmt, expr) < 0)
			return -1;
		break;
	}

	stmt->flags |= STMT_F_TERMINAL;
	return 0;
}

static int stmt_evaluate_reject_default(struct eval_ctx *ctx,
					  struct stmt *stmt)
{
	int protocol;
	const struct proto_desc *desc, *base;

	switch (ctx->pctx.family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
		stmt->reject.type = NFT_REJECT_ICMP_UNREACH;
		stmt->reject.family = ctx->pctx.family;
		if (ctx->pctx.family == NFPROTO_IPV4)
			stmt->reject.icmp_code = ICMP_PORT_UNREACH;
		else
			stmt->reject.icmp_code = ICMP6_DST_UNREACH_NOPORT;
		break;
	case NFPROTO_INET:
		desc = ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR].desc;
		if (desc == NULL) {
			stmt->reject.type = NFT_REJECT_ICMPX_UNREACH;
			stmt->reject.icmp_code = NFT_REJECT_ICMPX_PORT_UNREACH;
			break;
		}
		stmt->reject.type = NFT_REJECT_ICMP_UNREACH;
		base = ctx->pctx.protocol[PROTO_BASE_LL_HDR].desc;
		protocol = proto_find_num(base, desc);
		switch (protocol) {
		case NFPROTO_IPV4:
			stmt->reject.family = NFPROTO_IPV4;
			stmt->reject.icmp_code = ICMP_PORT_UNREACH;
			break;
		case NFPROTO_IPV6:
			stmt->reject.family = NFPROTO_IPV6;
			stmt->reject.icmp_code = ICMP6_DST_UNREACH_NOPORT;
			break;
		}
		break;
	case NFPROTO_BRIDGE:
		desc = ctx->pctx.protocol[PROTO_BASE_NETWORK_HDR].desc;
		if (desc == NULL) {
			stmt->reject.type = NFT_REJECT_ICMPX_UNREACH;
			stmt->reject.icmp_code = NFT_REJECT_ICMPX_PORT_UNREACH;
			break;
		}
		stmt->reject.type = NFT_REJECT_ICMP_UNREACH;
		base = ctx->pctx.protocol[PROTO_BASE_LL_HDR].desc;
		protocol = proto_find_num(base, desc);
		switch (protocol) {
		case __constant_htons(ETH_P_IP):
			stmt->reject.family = NFPROTO_IPV4;
			stmt->reject.icmp_code = ICMP_PORT_UNREACH;
			break;
		case __constant_htons(ETH_P_IPV6):
			stmt->reject.family = NFPROTO_IPV6;
			stmt->reject.icmp_code = ICMP6_DST_UNREACH_NOPORT;
			break;
		}
		break;
	}
	return 0;
}

static int stmt_evaluate_reject_icmp(struct eval_ctx *ctx, struct stmt *stmt)
{
	struct error_record *erec;
	struct expr *code;

	erec = symbol_parse(stmt->reject.expr, &code);
	if (erec != NULL) {
		erec_queue(erec, ctx->msgs);
		return -1;
	}
	stmt->reject.icmp_code = mpz_get_uint8(code->value);
	return 0;
}

static int stmt_evaluate_reset(struct eval_ctx *ctx, struct stmt *stmt)
{
	int protonum;
	const struct proto_desc *desc, *base;
	struct proto_ctx *pctx = &ctx->pctx;

	desc = pctx->protocol[PROTO_BASE_TRANSPORT_HDR].desc;
	if (desc == NULL)
		return 0;

	base = pctx->protocol[PROTO_BASE_NETWORK_HDR].desc;
	if (base == NULL)
		base = &proto_inet_service;

	protonum = proto_find_num(base, desc);
	switch (protonum) {
	case IPPROTO_TCP:
		break;
	default:
		if (stmt->reject.type == NFT_REJECT_TCP_RST) {
			return stmt_binary_error(ctx, stmt,
				 &ctx->pctx.protocol[PROTO_BASE_TRANSPORT_HDR],
				 "you cannot use tcp reset with this protocol");
		}
		break;
	}
	return 0;
}

static int stmt_evaluate_reject(struct eval_ctx *ctx, struct stmt *stmt)
{
	struct expr *expr = ctx->cmd->expr;

	if (stmt->reject.icmp_code < 0) {
		if (stmt_evaluate_reject_default(ctx, stmt) < 0)
			return -1;
	} else if (stmt->reject.expr != NULL) {
		if (stmt_evaluate_reject_icmp(ctx, stmt) < 0)
			return -1;
	} else {
		if (stmt_evaluate_reset(ctx, stmt) < 0)
			return -1;
	}

	return stmt_evaluate_reject_family(ctx, stmt, expr);
}

static int nat_evaluate_family(struct eval_ctx *ctx, struct stmt *stmt)
{
	switch (ctx->pctx.family) {
	case AF_INET:
	case AF_INET6:
		return 0;
	default:
		return stmt_error(ctx, stmt,
				  "NAT is only supported for IPv4/IPv6");
	}
}

static int evaluate_addr(struct eval_ctx *ctx, struct stmt *stmt,
			     struct expr **expr)
{
	struct proto_ctx *pctx = &ctx->pctx;
	const struct datatype *dtype;
	unsigned int len;

	if (pctx->family == AF_INET) {
		dtype = &ipaddr_type;
		len   = 4 * BITS_PER_BYTE;
	} else {
		dtype = &ip6addr_type;
		len   = 16 * BITS_PER_BYTE;
	}

	return stmt_evaluate_arg(ctx, stmt, dtype, len, expr);
}

static int nat_evaluate_transport(struct eval_ctx *ctx, struct stmt *stmt,
				  struct expr **expr)
{
	struct proto_ctx *pctx = &ctx->pctx;

	if (pctx->protocol[PROTO_BASE_TRANSPORT_HDR].desc == NULL)
		return stmt_binary_error(ctx, *expr, stmt,
					 "transport protocol mapping is only "
					 "valid after transport protocol match");

	return stmt_evaluate_arg(ctx, stmt,
				 &inet_service_type, 2 * BITS_PER_BYTE,
				 expr);
}

static int stmt_evaluate_nat(struct eval_ctx *ctx, struct stmt *stmt)
{
	int err;

	err = nat_evaluate_family(ctx, stmt);
	if (err < 0)
		return err;

	if (stmt->nat.addr != NULL) {
		err = evaluate_addr(ctx, stmt, &stmt->nat.addr);
		if (err < 0)
			return err;
	}
	if (stmt->nat.proto != NULL) {
		err = nat_evaluate_transport(ctx, stmt, &stmt->nat.proto);
		if (err < 0)
			return err;
	}

	stmt->flags |= STMT_F_TERMINAL;
	return 0;
}

static int stmt_evaluate_masq(struct eval_ctx *ctx, struct stmt *stmt)
{
	int err;

	err = nat_evaluate_family(ctx, stmt);
	if (err < 0)
		return err;

	if (stmt->masq.proto != NULL) {
		err = nat_evaluate_transport(ctx, stmt, &stmt->masq.proto);
		if (err < 0)
			return err;
	}

	stmt->flags |= STMT_F_TERMINAL;
	return 0;
}

static int stmt_evaluate_redir(struct eval_ctx *ctx, struct stmt *stmt)
{
	int err;

	err = nat_evaluate_family(ctx, stmt);
	if (err < 0)
		return err;

	if (stmt->redir.proto != NULL) {
		err = nat_evaluate_transport(ctx, stmt, &stmt->redir.proto);
		if (err < 0)
			return err;
	}

	stmt->flags |= STMT_F_TERMINAL;
	return 0;
}

static int stmt_evaluate_dup(struct eval_ctx *ctx, struct stmt *stmt)
{
	int err;

	switch (ctx->pctx.family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
		if (stmt->dup.to == NULL)
			return stmt_error(ctx, stmt,
					  "missing destination address");
		err = evaluate_addr(ctx, stmt, &stmt->dup.to);
		if (err < 0)
			return err;

		if (stmt->dup.dev != NULL) {
			err = stmt_evaluate_arg(ctx, stmt, &ifindex_type,
						sizeof(uint32_t) * BITS_PER_BYTE,
						&stmt->dup.dev);
			if (err < 0)
				return err;
		}
		break;
	case NFPROTO_NETDEV:
		if (stmt->dup.to == NULL)
			return stmt_error(ctx, stmt,
					  "missing destination interface");
		if (stmt->dup.dev != NULL)
			return stmt_error(ctx, stmt, "cannot specify device");

		err = stmt_evaluate_arg(ctx, stmt, &ifindex_type,
					sizeof(uint32_t) * BITS_PER_BYTE,
					&stmt->dup.to);
		if (err < 0)
			return err;
		break;
	default:
		return stmt_error(ctx, stmt, "unsupported family");
	}
	return 0;
}

static int stmt_evaluate_fwd(struct eval_ctx *ctx, struct stmt *stmt)
{
	int err;

	switch (ctx->pctx.family) {
	case NFPROTO_NETDEV:
		if (stmt->fwd.to == NULL)
			return stmt_error(ctx, stmt,
					  "missing destination interface");

		err = stmt_evaluate_arg(ctx, stmt, &ifindex_type,
					sizeof(uint32_t) * BITS_PER_BYTE,
					&stmt->fwd.to);
		if (err < 0)
			return err;
		break;
	default:
		return stmt_error(ctx, stmt, "unsupported family");
	}
	return 0;
}

static int stmt_evaluate_queue(struct eval_ctx *ctx, struct stmt *stmt)
{
	if (stmt->queue.queue != NULL) {
		if (stmt_evaluate_arg(ctx, stmt, &integer_type, 16,
				      &stmt->queue.queue) < 0)
			return -1;
		if (!expr_is_constant(stmt->queue.queue))
			return expr_error(ctx->msgs, stmt->queue.queue,
					  "queue number is not constant");
		if (stmt->queue.queue->ops->type != EXPR_RANGE &&
		    (stmt->queue.flags & NFT_QUEUE_FLAG_CPU_FANOUT))
			return expr_error(ctx->msgs, stmt->queue.queue,
					  "fanout requires a range to be "
					  "specified");
	}
	return 0;
}

static int stmt_evaluate_log(struct eval_ctx *ctx, struct stmt *stmt)
{
	if (stmt->log.flags & (STMT_LOG_GROUP | STMT_LOG_SNAPLEN |
			       STMT_LOG_QTHRESHOLD)) {
		if (stmt->log.flags & STMT_LOG_LEVEL)
			return stmt_error(ctx, stmt,
				  "level and group are mutually exclusive");
		if (stmt->log.logflags)
			return stmt_error(ctx, stmt,
				  "flags and group are mutually exclusive");
	}
	return 0;
}

static int stmt_evaluate_set(struct eval_ctx *ctx, struct stmt *stmt)
{
	expr_set_context(&ctx->ectx, NULL, 0);
	if (expr_evaluate(ctx, &stmt->set.set) < 0)
		return -1;
	if (stmt->set.set->ops->type != EXPR_SET_REF)
		return expr_error(ctx->msgs, stmt->set.set,
				  "Expression does not refer to a set");

	if (stmt_evaluate_arg(ctx, stmt,
			      stmt->set.set->set->keytype,
			      stmt->set.set->set->keylen,
			      &stmt->set.key) < 0)
		return -1;
	if (expr_is_constant(stmt->set.key))
		return expr_error(ctx->msgs, stmt->set.key,
				  "Key expression can not be constant");
	if (stmt->set.key->comment != NULL)
		return expr_error(ctx->msgs, stmt->set.key,
				  "Key expression comments are not supported");

	return 0;
}

static int stmt_evaluate_objref_map(struct eval_ctx *ctx, struct stmt *stmt)
{
	struct expr *map = stmt->objref.expr;
	struct expr *mappings;

	expr_set_context(&ctx->ectx, NULL, 0);
	if (expr_evaluate(ctx, &map->map) < 0)
		return -1;
	if (expr_is_constant(map->map))
		return expr_error(ctx->msgs, map->map,
				  "Map expression can not be constant");

	mappings = map->mappings;
	mappings->set_flags |= NFT_SET_OBJECT;

	switch (map->mappings->ops->type) {
	case EXPR_SET:
		mappings = implicit_set_declaration(ctx, "__objmap%d",
						    ctx->ectx.dtype,
						    ctx->ectx.len,
						    mappings);
		mappings->set->datatype = &string_type;
		mappings->set->datalen  = NFT_OBJ_MAXNAMELEN * BITS_PER_BYTE;
		mappings->set->objtype  = stmt->objref.type;

		map->mappings = mappings;

		ctx->set = mappings->set;
		if (expr_evaluate(ctx, &map->mappings->set->init) < 0)
			return -1;
		ctx->set = NULL;

		map->mappings->set->flags |=
			map->mappings->set->init->set_flags;
	case EXPR_SYMBOL:
		if (expr_evaluate(ctx, &map->mappings) < 0)
			return -1;
		if (map->mappings->ops->type != EXPR_SET_REF ||
		    !(map->mappings->set->flags & NFT_SET_OBJECT))
			return expr_error(ctx->msgs, map->mappings,
					  "Expression is not a map");
		break;
	default:
		BUG("invalid mapping expression %s\n",
		    map->mappings->ops->name);
	}

	if (!datatype_equal(map->map->dtype, map->mappings->set->keytype))
		return expr_binary_error(ctx->msgs, map->mappings, map->map,
					 "datatype mismatch, map expects %s, "
					 "mapping expression has type %s",
					 map->mappings->set->keytype->desc,
					 map->map->dtype->desc);

	map->dtype = map->mappings->set->datatype;
	map->flags |= EXPR_F_CONSTANT;

	/* Data for range lookups needs to be in big endian order */
	if (map->mappings->set->flags & NFT_SET_INTERVAL &&
	    byteorder_conversion(ctx, &map->map, BYTEORDER_BIG_ENDIAN) < 0)
		return -1;

	return 0;
}

static int stmt_evaluate_objref(struct eval_ctx *ctx, struct stmt *stmt)
{
	/* We need specific map evaluation for stateful objects. */
	if (stmt->objref.expr->ops->type == EXPR_MAP)
		return stmt_evaluate_objref_map(ctx, stmt);

	if (stmt_evaluate_arg(ctx, stmt,
			      &string_type, NFT_OBJ_MAXNAMELEN * BITS_PER_BYTE,
			      &stmt->objref.expr) < 0)
		return -1;

	if (!expr_is_constant(stmt->objref.expr))
		return expr_error(ctx->msgs, stmt->objref.expr,
				  "Counter expression must be constant");

	return 0;
}

int stmt_evaluate(struct eval_ctx *ctx, struct stmt *stmt)
{
#ifdef DEBUG
	if (debug_level & DEBUG_EVALUATION) {
		struct error_record *erec;
		erec = erec_create(EREC_INFORMATIONAL, &stmt->location,
				   "Evaluate %s", stmt->ops->name);
		erec_print(stdout, erec); stmt_print(stmt); printf("\n\n");
	}
#endif

	switch (stmt->ops->type) {
	case STMT_COUNTER:
	case STMT_LIMIT:
	case STMT_QUOTA:
	case STMT_NOTRACK:
		return 0;
	case STMT_EXPRESSION:
		return stmt_evaluate_expr(ctx, stmt);
	case STMT_VERDICT:
		return stmt_evaluate_verdict(ctx, stmt);
	case STMT_PAYLOAD:
		return stmt_evaluate_payload(ctx, stmt);
	case STMT_FLOW:
		return stmt_evaluate_flow(ctx, stmt);
	case STMT_META:
		return stmt_evaluate_meta(ctx, stmt);
	case STMT_CT:
		return stmt_evaluate_ct(ctx, stmt);
	case STMT_LOG:
		return stmt_evaluate_log(ctx, stmt);
	case STMT_REJECT:
		return stmt_evaluate_reject(ctx, stmt);
	case STMT_NAT:
		return stmt_evaluate_nat(ctx, stmt);
	case STMT_MASQ:
		return stmt_evaluate_masq(ctx, stmt);
	case STMT_REDIR:
		return stmt_evaluate_redir(ctx, stmt);
	case STMT_QUEUE:
		return stmt_evaluate_queue(ctx, stmt);
	case STMT_DUP:
		return stmt_evaluate_dup(ctx, stmt);
	case STMT_FWD:
		return stmt_evaluate_fwd(ctx, stmt);
	case STMT_SET:
		return stmt_evaluate_set(ctx, stmt);
	case STMT_OBJREF:
		return stmt_evaluate_objref(ctx, stmt);
	default:
		BUG("unknown statement type %s\n", stmt->ops->name);
	}
}

static int setelem_evaluate(struct eval_ctx *ctx, struct expr **expr)
{
	struct table *table;
	struct set *set;

	table = table_lookup_global(ctx);
	if (table == NULL)
		return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
				 ctx->cmd->handle.table);

	set = set_lookup(table, ctx->cmd->handle.set);
	if (set == NULL)
		return cmd_error(ctx, "Could not process rule: Set '%s' does not exist",
				 ctx->cmd->handle.set);

	ctx->set = set;
	expr_set_context(&ctx->ectx, set->keytype, set->keylen);
	if (expr_evaluate(ctx, expr) < 0)
		return -1;
	ctx->set = NULL;
	return 0;
}

static int set_evaluate(struct eval_ctx *ctx, struct set *set)
{
	struct table *table;
	const char *type;

	table = table_lookup_global(ctx);
	if (table == NULL)
		return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
				 ctx->cmd->handle.table);

	type = set->flags & NFT_SET_MAP ? "map" : "set";

	if (set->keytype == NULL)
		return set_error(ctx, set, "%s definition does not specify "
				 "key data type", type);

	set->keylen = set->keytype->size;
	if (set->keylen == 0)
		return set_error(ctx, set, "unqualified key data type "
				 "specified in %s definition", type);

	if (set->flags & NFT_SET_MAP) {
		if (set->datatype == NULL)
			return set_error(ctx, set, "map definition does not "
					 "specify mapping data type");

		set->datalen = set->datatype->size;
		if (set->datalen == 0 && set->datatype->type != TYPE_VERDICT)
			return set_error(ctx, set, "unqualified mapping data "
					 "type specified in map definition");
	} else if (set->flags & NFT_SET_OBJECT) {
		set->datatype = &string_type;
		set->datalen  = NFT_OBJ_MAXNAMELEN * BITS_PER_BYTE;
	}

	ctx->set = set;
	if (set->init != NULL) {
		expr_set_context(&ctx->ectx, set->keytype, set->keylen);
		if (expr_evaluate(ctx, &set->init) < 0)
			return -1;
	}
	ctx->set = NULL;

	if (set_lookup(table, set->handle.set) == NULL)
		set_add_hash(set_get(set), table);

	/* Default timeout value implies timeout support */
	if (set->timeout)
		set->flags |= NFT_SET_TIMEOUT;

	return 0;
}

static int rule_evaluate(struct eval_ctx *ctx, struct rule *rule)
{
	struct stmt *stmt, *tstmt = NULL;
	struct error_record *erec;

	proto_ctx_init(&ctx->pctx, rule->handle.family);
	memset(&ctx->ectx, 0, sizeof(ctx->ectx));

	ctx->rule = rule;
	list_for_each_entry(stmt, &rule->stmts, list) {
		if (tstmt != NULL)
			return stmt_binary_error(ctx, stmt, tstmt,
						 "Statement after terminal "
						 "statement has no effect");

		ctx->stmt = stmt;
		if (stmt_evaluate(ctx, stmt) < 0)
			return -1;
		if (stmt->flags & STMT_F_TERMINAL)
			tstmt = stmt;
	}

	erec = rule_postprocess(rule);
	if (erec != NULL) {
		erec_queue(erec, ctx->msgs);
		return -1;
	}

	return 0;
}

static uint32_t str2hooknum(uint32_t family, const char *hook)
{
	switch (family) {
	case NFPROTO_IPV4:
	case NFPROTO_BRIDGE:
	case NFPROTO_IPV6:
	case NFPROTO_INET:
		/* These families have overlapping values for each hook */
		if (!strcmp(hook, "prerouting"))
			return NF_INET_PRE_ROUTING;
		else if (!strcmp(hook, "input"))
			return NF_INET_LOCAL_IN;
		else if (!strcmp(hook, "forward"))
			return NF_INET_FORWARD;
		else if (!strcmp(hook, "postrouting"))
			return NF_INET_POST_ROUTING;
		else if (!strcmp(hook, "output"))
			return NF_INET_LOCAL_OUT;
		break;
	case NFPROTO_ARP:
		if (!strcmp(hook, "input"))
			return NF_ARP_IN;
		else if (!strcmp(hook, "forward"))
			return NF_ARP_FORWARD;
		else if (!strcmp(hook, "output"))
			return NF_ARP_OUT;
		break;
	case NFPROTO_NETDEV:
		if (!strcmp(hook, "ingress"))
			return NF_NETDEV_INGRESS;
		break;
	default:
		break;
	}

	return NF_INET_NUMHOOKS;
}

static int chain_evaluate(struct eval_ctx *ctx, struct chain *chain)
{
	struct table *table;
	struct rule *rule;

	table = table_lookup_global(ctx);
	if (table == NULL)
		return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
				 ctx->cmd->handle.table);

	if (chain == NULL) {
		if (chain_lookup(table, &ctx->cmd->handle) == NULL) {
			chain = chain_alloc(NULL);
			handle_merge(&chain->handle, &ctx->cmd->handle);
			chain_add_hash(chain, table);
		}
		return 0;
	} else {
		if (chain_lookup(table, &chain->handle) == NULL)
			chain_add_hash(chain_get(chain), table);
	}

	if (chain->flags & CHAIN_F_BASECHAIN) {
		chain->hooknum = str2hooknum(chain->handle.family,
					     chain->hookstr);
		if (chain->hooknum == NF_INET_NUMHOOKS)
			return chain_error(ctx, chain, "invalid hook %s",
					   chain->hookstr);
	}

	list_for_each_entry(rule, &chain->rules, list) {
		handle_merge(&rule->handle, &chain->handle);
		if (rule_evaluate(ctx, rule) < 0)
			return -1;
	}
	return 0;
}

static int table_evaluate(struct eval_ctx *ctx, struct table *table)
{
	struct chain *chain;
	struct set *set;

	if (table_lookup(&ctx->cmd->handle) == NULL) {
		if (table == NULL) {
			table = table_alloc();
			handle_merge(&table->handle, &ctx->cmd->handle);
			table_add_hash(table);
		} else {
			table_add_hash(table_get(table));
		}
	}

	if (ctx->cmd->table == NULL)
		return 0;

	ctx->table = table;
	list_for_each_entry(set, &table->sets, list) {
		handle_merge(&set->handle, &table->handle);
		if (set_evaluate(ctx, set) < 0)
			return -1;
	}
	list_for_each_entry(chain, &table->chains, list) {
		handle_merge(&chain->handle, &table->handle);
		if (chain_evaluate(ctx, chain) < 0)
			return -1;
	}
	ctx->table = NULL;
	return 0;
}

static int cmd_evaluate_add(struct eval_ctx *ctx, struct cmd *cmd)
{
	int ret;

	switch (cmd->obj) {
	case CMD_OBJ_SETELEM:
		ret = cache_update(cmd->op, ctx->msgs);
		if (ret < 0)
			return ret;

		return setelem_evaluate(ctx, &cmd->expr);
	case CMD_OBJ_SET:
		ret = cache_update(cmd->op, ctx->msgs);
		if (ret < 0)
			return ret;

		handle_merge(&cmd->set->handle, &cmd->handle);
		return set_evaluate(ctx, cmd->set);
	case CMD_OBJ_RULE:
		handle_merge(&cmd->rule->handle, &cmd->handle);
		return rule_evaluate(ctx, cmd->rule);
	case CMD_OBJ_CHAIN:
		ret = cache_update(cmd->op, ctx->msgs);
		if (ret < 0)
			return ret;

		return chain_evaluate(ctx, cmd->chain);
	case CMD_OBJ_TABLE:
		return table_evaluate(ctx, cmd->table);
	case CMD_OBJ_COUNTER:
	case CMD_OBJ_QUOTA:
		return 0;
	default:
		BUG("invalid command object type %u\n", cmd->obj);
	}
}

static int cmd_evaluate_delete(struct eval_ctx *ctx, struct cmd *cmd)
{
	int ret;

	switch (cmd->obj) {
	case CMD_OBJ_SETELEM:
		ret = cache_update(cmd->op, ctx->msgs);
		if (ret < 0)
			return ret;

		return setelem_evaluate(ctx, &cmd->expr);
	case CMD_OBJ_SET:
	case CMD_OBJ_RULE:
	case CMD_OBJ_CHAIN:
	case CMD_OBJ_TABLE:
	case CMD_OBJ_COUNTER:
	case CMD_OBJ_QUOTA:
		return 0;
	default:
		BUG("invalid command object type %u\n", cmd->obj);
	}
}

static int cmd_evaluate_list(struct eval_ctx *ctx, struct cmd *cmd)
{
	struct table *table;
	struct set *set;
	int ret;

	ret = cache_update(cmd->op, ctx->msgs);
	if (ret < 0)
		return ret;

	switch (cmd->obj) {
	case CMD_OBJ_TABLE:
		if (cmd->handle.table == NULL)
			return 0;

		table = table_lookup(&cmd->handle);
		if (table == NULL)
			return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
					 cmd->handle.table);
		return 0;
	case CMD_OBJ_SET:
		table = table_lookup(&cmd->handle);
		if (table == NULL)
			return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
					 cmd->handle.table);
		set = set_lookup(table, cmd->handle.set);
		if (set == NULL || set->flags & (NFT_SET_MAP | NFT_SET_EVAL))
			return cmd_error(ctx, "Could not process rule: Set '%s' does not exist",
					 cmd->handle.set);
		return 0;
	case CMD_OBJ_FLOWTABLE:
		table = table_lookup(&cmd->handle);
		if (table == NULL)
			return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
					 cmd->handle.table);
		set = set_lookup(table, cmd->handle.set);
		if (set == NULL || !(set->flags & NFT_SET_EVAL))
			return cmd_error(ctx, "Could not process rule: Flow table '%s' does not exist",
					 cmd->handle.set);
		return 0;
	case CMD_OBJ_MAP:
		table = table_lookup(&cmd->handle);
		if (table == NULL)
			return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
					 cmd->handle.table);
		set = set_lookup(table, cmd->handle.set);
		if (set == NULL || !(set->flags & NFT_SET_MAP))
			return cmd_error(ctx, "Could not process rule: Map '%s' does not exist",
					 cmd->handle.set);
		return 0;
	case CMD_OBJ_CHAIN:
		table = table_lookup(&cmd->handle);
		if (table == NULL)
			return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
					 cmd->handle.table);
		if (chain_lookup(table, &cmd->handle) == NULL)
			return cmd_error(ctx, "Could not process rule: Chain '%s' does not exist",
					 cmd->handle.chain);
		return 0;
	case CMD_OBJ_CHAINS:
	case CMD_OBJ_SETS:
	case CMD_OBJ_COUNTERS:
	case CMD_OBJ_QUOTAS:
	case CMD_OBJ_RULESET:
	case CMD_OBJ_FLOWTABLES:
	case CMD_OBJ_MAPS:
		return 0;
	default:
		BUG("invalid command object type %u\n", cmd->obj);
	}
}

static int cmd_evaluate_flush(struct eval_ctx *ctx, struct cmd *cmd)
{
	int ret;

	ret = cache_update(cmd->op, ctx->msgs);
	if (ret < 0)
		return ret;

	switch (cmd->obj) {
	case CMD_OBJ_RULESET:
		cache_flush();
		break;
	case CMD_OBJ_TABLE:
		/* Flushing a table does not empty the sets in the table nor remove
		 * any chains.
		 */
	case CMD_OBJ_CHAIN:
		/* Chains don't hold sets */
	case CMD_OBJ_SET:
		break;
	default:
		BUG("invalid command object type %u\n", cmd->obj);
	}
	return 0;
}

static int cmd_evaluate_rename(struct eval_ctx *ctx, struct cmd *cmd)
{
	struct table *table;
	int ret;

	switch (cmd->obj) {
	case CMD_OBJ_CHAIN:
		ret = cache_update(cmd->op, ctx->msgs);
		if (ret < 0)
			return ret;

		table = table_lookup(&ctx->cmd->handle);
		if (table == NULL)
			return cmd_error(ctx, "Could not process rule: Table '%s' does not exist",
					 ctx->cmd->handle.table);
		if (chain_lookup(table, &ctx->cmd->handle) == NULL)
			return cmd_error(ctx, "Could not process rule: Chain '%s' does not exist",
					 ctx->cmd->handle.chain);
		break;
	default:
		BUG("invalid command object type %u\n", cmd->obj);
	}
	return 0;
}

enum {
	CMD_MONITOR_EVENT_ANY,
	CMD_MONITOR_EVENT_NEW,
	CMD_MONITOR_EVENT_DEL,
	CMD_MONITOR_EVENT_TRACE,
	CMD_MONITOR_EVENT_MAX
};

static uint32_t monitor_flags[CMD_MONITOR_EVENT_MAX][CMD_MONITOR_OBJ_MAX] = {
	[CMD_MONITOR_EVENT_ANY] = {
		[CMD_MONITOR_OBJ_ANY]		= 0xffffffff,
		[CMD_MONITOR_OBJ_TABLES]	= (1 << NFT_MSG_NEWTABLE) |
						  (1 << NFT_MSG_DELTABLE),
		[CMD_MONITOR_OBJ_CHAINS]	= (1 << NFT_MSG_NEWCHAIN) |
						  (1 << NFT_MSG_DELCHAIN),
		[CMD_MONITOR_OBJ_RULES]		= (1 << NFT_MSG_NEWRULE) |
						  (1 << NFT_MSG_DELRULE),
		[CMD_MONITOR_OBJ_SETS]		= (1 << NFT_MSG_NEWSET) |
						  (1 << NFT_MSG_DELSET),
		[CMD_MONITOR_OBJ_ELEMS]		= (1 << NFT_MSG_NEWSETELEM) |
						  (1 << NFT_MSG_DELSETELEM),
	},
	[CMD_MONITOR_EVENT_NEW] = {
		[CMD_MONITOR_OBJ_ANY]		= (1 << NFT_MSG_NEWTABLE) |
						  (1 << NFT_MSG_NEWCHAIN) |
						  (1 << NFT_MSG_NEWRULE)  |
						  (1 << NFT_MSG_NEWSET)   |
						  (1 << NFT_MSG_NEWSETELEM),
		[CMD_MONITOR_OBJ_TABLES]	= (1 << NFT_MSG_NEWTABLE),
		[CMD_MONITOR_OBJ_CHAINS]	= (1 << NFT_MSG_NEWCHAIN),
		[CMD_MONITOR_OBJ_RULES]		= (1 << NFT_MSG_NEWRULE),
		[CMD_MONITOR_OBJ_SETS]		= (1 << NFT_MSG_NEWSET),
		[CMD_MONITOR_OBJ_ELEMS]		= (1 << NFT_MSG_NEWSETELEM),
	},
	[CMD_MONITOR_EVENT_DEL] = {
		[CMD_MONITOR_OBJ_ANY]		= (1 << NFT_MSG_DELTABLE) |
						  (1 << NFT_MSG_DELCHAIN) |
						  (1 << NFT_MSG_DELRULE)  |
						  (1 << NFT_MSG_DELSET)   |
						  (1 << NFT_MSG_DELSETELEM),
		[CMD_MONITOR_OBJ_TABLES]	= (1 << NFT_MSG_DELTABLE),
		[CMD_MONITOR_OBJ_CHAINS]	= (1 << NFT_MSG_DELCHAIN),
		[CMD_MONITOR_OBJ_RULES]		= (1 << NFT_MSG_DELRULE),
		[CMD_MONITOR_OBJ_SETS]		= (1 << NFT_MSG_DELSET),
		[CMD_MONITOR_OBJ_ELEMS]		= (1 << NFT_MSG_DELSETELEM),
	},
	[CMD_MONITOR_EVENT_TRACE] = {
		[CMD_MONITOR_OBJ_ANY]		= (1 << NFT_MSG_NEWTABLE) |
						  (1 << NFT_MSG_NEWCHAIN) |
						  (1 << NFT_MSG_NEWRULE)  |
						  (1 << NFT_MSG_DELTABLE) |
						  (1 << NFT_MSG_DELCHAIN) |
						  (1 << NFT_MSG_DELRULE)  |
						  (1 << NFT_MSG_TRACE),
		[CMD_MONITOR_OBJ_TABLES]	= (1 << NFT_MSG_NEWTABLE) |
						  (1 << NFT_MSG_DELTABLE),
		[CMD_MONITOR_OBJ_CHAINS]	= (1 << NFT_MSG_NEWCHAIN) |
						  (1 << NFT_MSG_DELCHAIN),
		[CMD_MONITOR_OBJ_RULES]		= (1 << NFT_MSG_NEWRULE) |
						  (1 << NFT_MSG_DELRULE),
	},
};

static int cmd_evaluate_monitor(struct eval_ctx *ctx, struct cmd *cmd)
{
	uint32_t event;
	int ret;

	ret = cache_update(cmd->op, ctx->msgs);
	if (ret < 0)
		return ret;

	if (cmd->monitor->event == NULL)
		event = CMD_MONITOR_EVENT_ANY;
	else if (strcmp(cmd->monitor->event, "new") == 0)
		event = CMD_MONITOR_EVENT_NEW;
	else if (strcmp(cmd->monitor->event, "destroy") == 0)
		event = CMD_MONITOR_EVENT_DEL;
	else if (strcmp(cmd->monitor->event, "trace") == 0)
		event = CMD_MONITOR_EVENT_TRACE;
	else {
		return monitor_error(ctx, cmd->monitor, "invalid event %s",
				     cmd->monitor->event);
	}

	cmd->monitor->flags = monitor_flags[event][cmd->monitor->type];
	return 0;
}

static int cmd_evaluate_export(struct eval_ctx *ctx, struct cmd *cmd)
{
	return cache_update(cmd->op, ctx->msgs);
}

#ifdef DEBUG
static const char *cmd_op_name[] = {
	[CMD_INVALID]	= "invalid",
	[CMD_ADD]	= "add",
	[CMD_REPLACE]	= "replace",
	[CMD_CREATE]	= "create",
	[CMD_INSERT]	= "insert",
	[CMD_DELETE]	= "delete",
	[CMD_LIST]	= "list",
	[CMD_FLUSH]	= "flush",
	[CMD_RENAME]	= "rename",
	[CMD_EXPORT]	= "export",
	[CMD_MONITOR]	= "monitor",
	[CMD_DESCRIBE]	= "describe",
};

static const char *cmd_op_to_name(enum cmd_ops op)
{
	if (op > CMD_DESCRIBE)
		return "unknown";

	return cmd_op_name[op];
}
#endif

int cmd_evaluate(struct eval_ctx *ctx, struct cmd *cmd)
{
#ifdef DEBUG
	if (debug_level & DEBUG_EVALUATION) {
		struct error_record *erec;
		erec = erec_create(EREC_INFORMATIONAL, &cmd->location,
				   "Evaluate %s", cmd_op_to_name(cmd->op));
		erec_print(stdout, erec); printf("\n\n");
	}
#endif

	ctx->cmd = cmd;
	switch (cmd->op) {
	case CMD_ADD:
	case CMD_REPLACE:
	case CMD_CREATE:
	case CMD_INSERT:
		return cmd_evaluate_add(ctx, cmd);
	case CMD_DELETE:
		return cmd_evaluate_delete(ctx, cmd);
	case CMD_LIST:
	case CMD_RESET:
		return cmd_evaluate_list(ctx, cmd);
	case CMD_FLUSH:
		return cmd_evaluate_flush(ctx, cmd);
	case CMD_RENAME:
		return cmd_evaluate_rename(ctx, cmd);
	case CMD_EXPORT:
		return cmd_evaluate_export(ctx, cmd);
	case CMD_DESCRIBE:
		return 0;
	case CMD_MONITOR:
		return cmd_evaluate_monitor(ctx, cmd);
	default:
		BUG("invalid command operation %u\n", cmd->op);
	};
}
