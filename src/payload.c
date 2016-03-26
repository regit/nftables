/*
 * Payload expression and related functions.
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
#include <stdint.h>
#include <string.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>

#include <rule.h>
#include <expression.h>
#include <statement.h>
#include <payload.h>
#include <gmputil.h>
#include <utils.h>

static void payload_expr_print(const struct expr *expr)
{
	const struct proto_desc *desc;
	const struct proto_hdr_template *tmpl;

	desc = expr->payload.desc;
	tmpl = expr->payload.tmpl;
	if (desc != NULL && tmpl != NULL)
		printf("%s %s", desc->name, tmpl->token);
	else
		printf("payload @%s,%u,%u",
		       proto_base_tokens[expr->payload.base],
		       expr->payload.offset, expr->len);
}

static bool payload_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->payload.desc   == e2->payload.desc &&
	       e1->payload.tmpl   == e2->payload.tmpl &&
	       e1->payload.base   == e2->payload.base &&
	       e1->payload.offset == e2->payload.offset;
}

static void payload_expr_clone(struct expr *new, const struct expr *expr)
{
	new->payload.desc   = expr->payload.desc;
	new->payload.tmpl   = expr->payload.tmpl;
	new->payload.base   = expr->payload.base;
	new->payload.offset = expr->payload.offset;
}

/**
 * payload_expr_pctx_update - update protocol context based on payload match
 *
 * @ctx:	protocol context
 * @expr:	relational payload expression
 *
 * Update protocol context for relational payload expressions.
 */
static void payload_expr_pctx_update(struct proto_ctx *ctx,
				     const struct expr *expr)
{
	const struct expr *left = expr->left, *right = expr->right;
	const struct proto_desc *base, *desc;
	unsigned int proto = 0;

	if (!(left->flags & EXPR_F_PROTOCOL))
		return;

	assert(expr->op == OP_EQ);

	/* Export the data in the correct byte order */
	assert(right->len / BITS_PER_BYTE <= sizeof(proto));
	mpz_export_data(constant_data_ptr(proto, right->len), right->value,
			right->byteorder, right->len / BITS_PER_BYTE);

	base = ctx->protocol[left->payload.base].desc;
	desc = proto_find_upper(base, proto);

	assert(desc->base <= PROTO_BASE_MAX);
	if (desc->base == base->base) {
		assert(base->length > 0);
		ctx->protocol[base->base].offset += base->length;
	}
	proto_ctx_update(ctx, desc->base, &expr->location, desc);
}

static const struct expr_ops payload_expr_ops = {
	.type		= EXPR_PAYLOAD,
	.name		= "payload",
	.print		= payload_expr_print,
	.cmp		= payload_expr_cmp,
	.clone		= payload_expr_clone,
	.pctx_update	= payload_expr_pctx_update,
};

struct expr *payload_expr_alloc(const struct location *loc,
				const struct proto_desc *desc,
				unsigned int type)
{
	const struct proto_hdr_template *tmpl;
	enum proto_bases base;
	struct expr *expr;
	unsigned int flags = 0;

	if (desc != NULL) {
		tmpl = &desc->templates[type];
		base = desc->base;
		if (type == desc->protocol_key)
			flags = EXPR_F_PROTOCOL;
	} else {
		tmpl = &proto_unknown_template;
		base = PROTO_BASE_INVALID;
		desc = &proto_unknown;
	}

	expr = expr_alloc(loc, &payload_expr_ops, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->flags |= flags;

	expr->payload.desc   = desc;
	expr->payload.tmpl   = tmpl;
	expr->payload.base   = base;
	expr->payload.offset = tmpl->offset;

	return expr;
}

void payload_init_raw(struct expr *expr, enum proto_bases base,
		      unsigned int offset, unsigned int len)
{
	expr->payload.base	= base;
	expr->payload.offset	= offset;
	expr->len		= len;
}

static void payload_stmt_print(const struct stmt *stmt)
{
	expr_print(stmt->payload.expr);
	printf(" set ");
	expr_print(stmt->payload.val);
}

static const struct stmt_ops payload_stmt_ops = {
	.type		= STMT_PAYLOAD,
	.name		= "payload",
	.print		= payload_stmt_print,
};

struct stmt *payload_stmt_alloc(const struct location *loc,
				struct expr *expr, struct expr *val)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &payload_stmt_ops);
	stmt->payload.expr = expr;
	stmt->payload.val  = val;
	return stmt;
}

static int payload_add_dependency(struct eval_ctx *ctx,
				  const struct proto_desc *desc,
				  const struct proto_desc *upper,
				  const struct expr *expr,
				  struct stmt **res)
{
	const struct proto_hdr_template *tmpl;
	struct expr *dep, *left, *right;
	struct stmt *stmt;
	int protocol = proto_find_num(desc, upper);

	if (protocol < 0)
		return expr_error(ctx->msgs, expr,
				  "conflicting protocols specified: %s vs. %s",
				  desc->name, upper->name);

	tmpl = &desc->templates[desc->protocol_key];
	if (tmpl->meta_key)
		left = meta_expr_alloc(&expr->location, tmpl->meta_key);
	else
		left = payload_expr_alloc(&expr->location, desc, desc->protocol_key);

	right = constant_expr_alloc(&expr->location, tmpl->dtype,
				    tmpl->dtype->byteorder, tmpl->len,
				    constant_data_ptr(protocol, tmpl->len));

	dep = relational_expr_alloc(&expr->location, OP_EQ, left, right);
	stmt = expr_stmt_alloc(&dep->location, dep);
	if (stmt_evaluate(ctx, stmt) < 0) {
		return expr_error(ctx->msgs, expr,
					  "dependency statement is invalid");
	}
	left->ops->pctx_update(&ctx->pctx, dep);
	*res = stmt;
	return 0;
}

/**
 * payload_gen_dependency - generate match expression on payload dependency
 *
 * @ctx:	evaluation context
 * @expr:	payload expression
 * @res:	dependency expression
 *
 * Generate matches on protocol dependencies. There are two different kinds
 * of dependencies:
 *
 * - A payload expression for a base above the hook base requires a match
 *   on the protocol value in the lower layer header.
 *
 * - A payload expression for a base below the hook base is invalid in the
 *   output path since the lower layer header does not exist when the packet
 *   is classified. In the input path a payload expressions for a base exactly
 *   one below the hook base is valid. In this case a match on the device type
 *   is required to verify that we're dealing with the expected protocol.
 *
 *   Note: since it is unknown to userspace which hooks a chain is called from,
 *   it is not explicitly verified. The NFT_META_IIFTYPE match will only match
 *   in the input path though.
 */
int payload_gen_dependency(struct eval_ctx *ctx, const struct expr *expr,
			   struct stmt **res)
{
	const struct hook_proto_desc *h = &hook_proto_desc[ctx->pctx.family];
	const struct proto_desc *desc;
	struct stmt *stmt;
	uint16_t type;

	if (expr->payload.base < h->base) {
		if (expr->payload.base < h->base - 1)
			return expr_error(ctx->msgs, expr,
					  "payload base is invalid for this "
					  "family");

		if (proto_dev_type(expr->payload.desc, &type) < 0)
			return expr_error(ctx->msgs, expr,
					  "protocol specification is invalid "
					  "for this family");

		stmt = meta_stmt_meta_iiftype(&expr->location, type);
		if (stmt_evaluate(ctx, stmt) < 0) {
			return expr_error(ctx->msgs, expr,
					  "dependency statement is invalid");
		}
		*res = stmt;
		return 0;
	}

	desc = ctx->pctx.protocol[expr->payload.base - 1].desc;
	/* Special case for mixed IPv4/IPv6 and bridge tables */
	if (desc == NULL) {
		switch (ctx->pctx.family) {
		case NFPROTO_INET:
			switch (expr->payload.base) {
			case PROTO_BASE_LL_HDR:
				desc = &proto_inet;
				break;
			case PROTO_BASE_TRANSPORT_HDR:
				desc = &proto_inet_service;
				break;
			default:
				break;
			}
			break;
		case NFPROTO_BRIDGE:
			switch (expr->payload.base) {
			case PROTO_BASE_LL_HDR:
				desc = &proto_eth;
				break;
			case PROTO_BASE_TRANSPORT_HDR:
				desc = &proto_inet_service;
				break;
			default:
				break;
			}
			break;
		case NFPROTO_NETDEV:
			switch (expr->payload.base) {
			case PROTO_BASE_LL_HDR:
				desc = &proto_netdev;
				break;
			case PROTO_BASE_TRANSPORT_HDR:
				desc = &proto_inet_service;
				break;
			default:
				break;
			}
			break;
		}
	}

	if (desc == NULL)
		return expr_error(ctx->msgs, expr,
				  "ambiguous payload specification: "
				  "no %s protocol specified",
				  proto_base_names[expr->payload.base - 1]);

	return payload_add_dependency(ctx, desc, expr->payload.desc, expr, res);
}

int exthdr_gen_dependency(struct eval_ctx *ctx, const struct expr *expr,
			  struct stmt **res)
{
	const struct proto_desc *desc;

	desc = ctx->pctx.protocol[PROTO_BASE_LL_HDR].desc;
	if (desc == NULL)
		return expr_error(ctx->msgs, expr,
				  "Cannot generate dependency: "
				  "no %s protocol specified",
				  proto_base_names[PROTO_BASE_LL_HDR]);

	return payload_add_dependency(ctx, desc, &proto_ip6, expr, res);
}

/**
 * payload_dependency_store - store a possibly redundant protocol match
 *
 * @ctx: payload dependency context
 * @stmt: payload match
 * @base: base of payload match
 */
void payload_dependency_store(struct payload_dep_ctx *ctx,
			      struct stmt *stmt, enum proto_bases base)
{
	ctx->pbase = base + 1;
	ctx->pdep  = stmt;
}

/**
 * __payload_dependency_kill - kill a redundant payload depedency
 *
 * @ctx: payload dependency context
 * @expr: higher layer payload expression
 *
 * Kill a redundant payload expression if a higher layer payload expression
 * implies its existance.
 */
void __payload_dependency_kill(struct payload_dep_ctx *ctx,
			       enum proto_bases base)
{
	if (ctx->pbase != PROTO_BASE_INVALID &&
	    ctx->pbase == base &&
	    ctx->pdep != NULL) {
		list_del(&ctx->pdep->list);
		stmt_free(ctx->pdep);

		ctx->pbase = PROTO_BASE_INVALID;
		if (ctx->pdep == ctx->prev)
			ctx->prev = NULL;
		ctx->pdep  = NULL;
	}
}

void payload_dependency_kill(struct payload_dep_ctx *ctx, struct expr *expr)
{
	__payload_dependency_kill(ctx, expr->payload.base);
}

/**
 * payload_expr_complete - fill in type information of a raw payload expr
 *
 * @expr:	the payload expression
 * @ctx:	protocol context
 *
 * Complete the type of a raw payload expression based on the context. If
 * insufficient information is available the expression remains unchanged.
 */
void payload_expr_complete(struct expr *expr, const struct proto_ctx *ctx)
{
	const struct proto_desc *desc;
	const struct proto_hdr_template *tmpl;
	unsigned int i;

	assert(expr->ops->type == EXPR_PAYLOAD);

	desc = ctx->protocol[expr->payload.base].desc;
	if (desc == NULL)
		return;
	assert(desc->base == expr->payload.base);

	for (i = 0; i < array_size(desc->templates); i++) {
		tmpl = &desc->templates[i];
		if (tmpl->offset != expr->payload.offset ||
		    tmpl->len    != expr->len)
			continue;
		expr->dtype	   = tmpl->dtype;
		expr->payload.desc = desc;
		expr->payload.tmpl = tmpl;
		return;
	}
}

static unsigned int mask_to_offset(const struct expr *mask)
{
	return mask ? mpz_scan1(mask->value, 0) : 0;
}

static unsigned int mask_length(const struct expr *mask)
{
	unsigned long off;

        off = mask_to_offset(mask);

	return mpz_scan0(mask->value, off + 1);
}

/**
 * payload_expr_trim - trim payload expression according to mask
 *
 * @expr:	the payload expression
 * @mask:	mask to use when searching templates
 * @ctx:	protocol context
 *
 * Walk the template list and determine if a match can be found without
 * using the provided mask.
 *
 * If the mask has to be used, trim the payload expression length accordingly,
 * adjust the payload offset and return true to let the caller know that the
 * mask can be removed. This function also returns the shift for the right hand
 * constant side of the expression.
 */
bool payload_expr_trim(struct expr *expr, struct expr *mask,
		       const struct proto_ctx *ctx, unsigned int *shift)
{
	unsigned int payload_offset = expr->payload.offset;
	unsigned int mask_offset = mask_to_offset(mask);
	unsigned int mask_len = mask_length(mask);
	const struct proto_hdr_template *tmpl;
	unsigned int payload_len = expr->len;
	const struct proto_desc *desc;
	unsigned int off, i, len = 0;

	assert(expr->ops->type == EXPR_PAYLOAD);

	desc = ctx->protocol[expr->payload.base].desc;
	if (desc == NULL)
		return false;

	assert(desc->base == expr->payload.base);

	if (ctx->protocol[expr->payload.base].offset) {
		assert(payload_offset >= ctx->protocol[expr->payload.base].offset);
		payload_offset -= ctx->protocol[expr->payload.base].offset;
	}

	off = round_up(mask->len, BITS_PER_BYTE) - mask_len;
	payload_offset += off;

	for (i = 1; i < array_size(desc->templates); i++) {
		tmpl = &desc->templates[i];
		if (tmpl->offset != payload_offset)
			continue;

		if (tmpl->len > payload_len)
			return false;

		payload_len -= tmpl->len;
		payload_offset += tmpl->len;
		len += tmpl->len;
		if (payload_len == 0)
			return false;

		if (mask_offset + len == mask_len) {
			expr->payload.offset += off;
			expr->len = len;
			*shift = mask_offset;
			return true;
		}
	}

	return false;
}

/**
 * payload_expr_expand - expand raw merged adjacent payload expressions into its
 * 			 original components
 *
 * @list:	list to append expanded payload expressions to
 * @expr:	the payload expression to expand
 * @ctx:	protocol context
 *
 * Expand a merged adjacent payload expression into its original components
 * by splitting elements off the beginning matching a payload template.
 *
 * Note: this requires all payload templates to be specified in ascending
 * 	 offset order.
 */
void payload_expr_expand(struct list_head *list, struct expr *expr,
			 const struct proto_ctx *ctx)
{
	const struct proto_hdr_template *tmpl;
	const struct proto_desc *desc;
	struct expr *new;
	unsigned int i;

	assert(expr->ops->type == EXPR_PAYLOAD);

	desc = ctx->protocol[expr->payload.base].desc;
	if (desc == NULL)
		goto raw;
	assert(desc->base == expr->payload.base);

	for (i = 1; i < array_size(desc->templates); i++) {
		tmpl = &desc->templates[i];
		if (tmpl->offset != expr->payload.offset)
			continue;

		if (tmpl->len <= expr->len) {
			new = payload_expr_alloc(&expr->location, desc, i);
			list_add_tail(&new->list, list);
			expr->len	     -= tmpl->len;
			expr->payload.offset += tmpl->len;
			if (expr->len == 0)
				return;
		} else
			break;
	}
raw:
	new = payload_expr_alloc(&expr->location, NULL, 0);
	payload_init_raw(new, expr->payload.base, expr->payload.offset,
			 expr->len);
	list_add_tail(&new->list, list);
}

static bool payload_is_adjacent(const struct expr *e1, const struct expr *e2)
{
	if (e1->payload.base		 == e2->payload.base &&
	    e1->payload.offset + e1->len == e2->payload.offset)
		return true;
	return false;
}

/**
 * payload_can_merge - return whether two payload expressions can be merged
 *
 * @e1:		first payload expression
 * @e2:		second payload expression
 */
bool payload_can_merge(const struct expr *e1, const struct expr *e2)
{
	unsigned int total;

	if (!payload_is_adjacent(e1, e2))
		return false;

	if (e1->payload.offset % BITS_PER_BYTE || e1->len % BITS_PER_BYTE ||
	    e2->payload.offset % BITS_PER_BYTE || e2->len % BITS_PER_BYTE)
		return false;

	total = e1->len + e2->len;
	if (total < e1->len || total > (NFT_REG_SIZE * BITS_PER_BYTE))
		return false;

	return true;
}

/**
 * payload_expr_join - join two adjacent payload expressions
 *
 * @e1:		first payload expression
 * @e2:		second payload expression
 */
struct expr *payload_expr_join(const struct expr *e1, const struct expr *e2)
{
	struct expr *expr;

	assert(payload_is_adjacent(e1, e2));

	expr = payload_expr_alloc(&internal_location, NULL, 0);
	expr->payload.base   = e1->payload.base;
	expr->payload.offset = e1->payload.offset;
	expr->len	     = e1->len + e2->len;
	return expr;
}
