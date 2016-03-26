#ifndef NFTABLES_PAYLOAD_H
#define NFTABLES_PAYLOAD_H

#include <nftables.h>
#include <proto.h>

extern struct expr *payload_expr_alloc(const struct location *loc,
				       const struct proto_desc *desc,
				       unsigned int type);
extern void payload_init_raw(struct expr *expr, enum proto_bases base,
			     unsigned int offset, unsigned int len);

struct eval_ctx;
struct stmt;
extern int payload_gen_dependency(struct eval_ctx *ctx, const struct expr *expr,
				  struct stmt **res);
extern int exthdr_gen_dependency(struct eval_ctx *ctx, const struct expr *expr,
				  struct stmt **res);

/**
 * struct payload_dep_ctx - payload protocol dependency tracking
 *
 * @pbase: protocol base of last dependency match
 * @pdep: last dependency match
 * @prev: previous statement
 */
struct payload_dep_ctx {
	enum proto_bases	pbase;
	struct stmt		*pdep;
	struct stmt		*prev;
};

extern void payload_dependency_store(struct payload_dep_ctx *ctx,
				     struct stmt *stmt,
				     enum proto_bases base);
extern void __payload_dependency_kill(struct payload_dep_ctx *ctx,
				      enum proto_bases base);
extern void payload_dependency_kill(struct payload_dep_ctx *ctx,
				    struct expr *expr);

extern bool payload_can_merge(const struct expr *e1, const struct expr *e2);
extern struct expr *payload_expr_join(const struct expr *e1,
				      const struct expr *e2);

bool payload_expr_trim(struct expr *expr, struct expr *mask,
		       const struct proto_ctx *ctx, unsigned int *shift);
extern void payload_expr_expand(struct list_head *list, struct expr *expr,
				const struct proto_ctx *ctx);
extern void payload_expr_complete(struct expr *expr,
				  const struct proto_ctx *ctx);

#endif /* NFTABLES_PAYLOAD_H */
