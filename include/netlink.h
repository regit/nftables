#ifndef NFTABLES_NETLINK_H
#define NFTABLES_NETLINK_H

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>

#include <linux/netlink.h>
#include <linux/netfilter/nf_tables.h>

#include <rule.h>

struct netlink_parse_ctx {
	struct list_head	*msgs;
	struct table		*table;
	struct rule		*rule;
	struct stmt		*stmt;
	struct expr		*registers[1 + NFT_REG32_15 - NFT_REG32_00 + 1];
};

struct rule_pp_ctx {
	struct proto_ctx	pctx;
	struct payload_dep_ctx	pdctx;
	struct stmt		*stmt;
};

extern const struct input_descriptor indesc_netlink;
extern const struct location netlink_location;

/** 
 * struct netlink_ctx
 *
 * @msgs:	message queue
 * @list:	list of parsed rules/chains/tables
 * @set:	current set
 * @data:	pointer to pass data to callback
 * @seqnum:	sequence number
 */
struct netlink_ctx {
	struct list_head	*msgs;
	struct list_head	list;
	struct set		*set;
	const void		*data;
	uint32_t		seqnum;
	bool			batch_supported;
};

extern struct nftnl_table *alloc_nftnl_table(const struct handle *h);
extern struct nftnl_chain *alloc_nftnl_chain(const struct handle *h);
extern struct nftnl_rule *alloc_nftnl_rule(const struct handle *h);
extern struct nftnl_expr *alloc_nft_expr(const char *name);
extern struct nftnl_set *alloc_nftnl_set(const struct handle *h);

struct nft_data_linearize {
	uint32_t	len;
	uint32_t	value[4];
	char		chain[NFT_CHAIN_MAXNAMELEN];
	int		verdict;
};

struct nft_data_delinearize {
	uint32_t	len;
	const uint32_t	*value;
	const char	*chain;
	int		verdict;
};

static inline unsigned int netlink_register_space(unsigned int size)
{
	return div_round_up(size, NFT_REG32_SIZE * BITS_PER_BYTE);
}

static inline unsigned int netlink_padded_len(unsigned int size)
{
	return netlink_register_space(size) * NFT_REG32_SIZE * BITS_PER_BYTE;
}

static inline unsigned int netlink_padding_len(unsigned int size)
{
	return netlink_padded_len(size) - size;
}

extern void netlink_gen_data(const struct expr *expr,
			     struct nft_data_linearize *data);
extern void netlink_gen_raw_data(const mpz_t value, enum byteorder byteorder,
				 unsigned int len,
				 struct nft_data_linearize *data);

extern struct expr *netlink_alloc_value(const struct location *loc,
				        const struct nft_data_delinearize *nld);
extern struct expr *netlink_alloc_data(const struct location *loc,
				       const struct nft_data_delinearize *nld,
				       enum nft_registers dreg);

extern void netlink_linearize_rule(nft_context_t *nft_ctx,
				   struct nftnl_rule *nlr,
				   const struct rule *rule);
extern struct rule *netlink_delinearize_rule(nft_context_t *nft_ctx,
					     struct nftnl_rule *r);

extern int netlink_add_rule(nft_context_t *nft_ctx, const struct handle *h,
			    const struct rule *rule, uint32_t flags);
extern int netlink_delete_rule(nft_context_t *nft_ctx, const struct handle *h,
			       const struct location *loc);
extern int netlink_add_rule_list(nft_context_t *nft_ctx, const struct handle *h,
				 const struct list_head *rule_list);
extern int netlink_add_rule_batch(nft_context_t *nft_ctx,
				  const struct handle *h,
				  const struct rule *rule, uint32_t flags);
extern int netlink_del_rule_batch(nft_context_t *nft_ctx,
				  const struct handle *h,
				  const struct location *loc);
extern int netlink_replace_rule_batch(nft_context_t *nft_ctx,
				      const struct handle *h,
				      const struct rule *rule,
				      const struct location *loc);

extern int netlink_add_chain(nft_context_t *nft_ctx, const struct handle *h,
			     const struct location *loc,
			     const struct chain *chain, bool excl);
extern int netlink_rename_chain(nft_context_t *nft_ctx, const struct handle *h,
				const struct location *loc, const char *name);
extern int netlink_delete_chain(nft_context_t *nft_ctx, const struct handle *h,
				const struct location *loc);
extern int netlink_list_chains(nft_context_t *nft_ctx,
			       const struct handle *h,
			       const struct location *loc);
extern int netlink_get_chain(nft_context_t *nft_ctx, const struct handle *h,
			     const struct location *loc);
extern int netlink_list_chain(nft_context_t *nft_ctx, const struct handle *h,
			      const struct location *loc);
extern int netlink_flush_chain(nft_context_t *nft_ctx, const struct handle *h,
			       const struct location *loc);

extern int netlink_add_table(nft_context_t *nft_ctx, const struct handle *h,
			     const struct location *loc,
			     const struct table *table, bool excl);
extern int netlink_delete_table(nft_context_t *nft_ctx, const struct handle *h,
				const struct location *loc);
extern int netlink_list_tables(nft_context_t *nft_ctx, const struct handle *h,
			       const struct location *loc);
extern int netlink_get_table(nft_context_t *nft_ctx, const struct handle *h,
			     const struct location *loc, struct table *table);
extern int netlink_list_table(nft_context_t *nft_ctx,
			      const struct handle *h,
			      const struct location *loc);
extern int netlink_flush_table(nft_context_t *nft_ctx, const struct handle *h,
			       const struct location *loc);

extern int netlink_add_set(nft_context_t *nft_ctx, const struct handle *h,
			   struct set *set);
extern int netlink_delete_set(nft_context_t *nft_ctx, const struct handle *h,
			      const struct location *loc);
extern int netlink_list_sets(nft_context_t *nft_ctx, const struct handle *h,
			     const struct location *loc);
extern int netlink_get_set(nft_context_t *nft_ctx, const struct handle *h,
			   const struct location *loc);

extern struct stmt *netlink_parse_set_expr(const struct set *set,
					   const struct nftnl_expr *nle);

extern int netlink_add_setelems(nft_context_t *nft_ctx, const struct handle *h,
				const struct expr *expr);
extern int netlink_delete_setelems(nft_context_t *nft_ctx, const struct handle *h,
				   const struct expr *expr);
extern int netlink_get_setelems(nft_context_t *nft_ctx, const struct handle *h,
				const struct location *loc, struct set *set);

extern void netlink_dump_table(const struct nftnl_table *nlt);
extern void netlink_dump_chain(const struct nftnl_chain *nlc);
extern void netlink_dump_rule(const struct nftnl_rule *nlr);
extern void netlink_dump_expr(const struct nftnl_expr *nle);
extern void netlink_dump_set(const struct nftnl_set *nls);

extern int netlink_batch_send(struct list_head *err_list);

extern void netlink_genid_get(nft_context_t *ctx);
extern void netlink_restart(nft_context_t *ctx);
#define netlink_abi_error()	\
	__netlink_abi_error(__FILE__, __LINE__, strerror(errno));
extern void __noreturn __netlink_abi_error(const char *file, int line, const char *reason);
extern int netlink_io_error(nft_context_t *nft_ctx,
			    const struct location *loc, const char *fmt, ...);
#define netlink_init_error()	\
	__netlink_init_error(__FILE__, __LINE__, strerror(errno));
extern void __noreturn __netlink_init_error(const char *file, int line, const char *reason);

extern int netlink_flush_ruleset(nft_context_t *nft_ctx,
				 const struct handle *h,
				 const struct location *loc);

extern struct nftnl_ruleset *netlink_dump_ruleset(nft_context_t *nft_ctx,
						const struct handle *h,
						const struct location *loc);
struct netlink_mon_handler {
	uint32_t		monitor_flags;
	uint32_t		format;
	struct netlink_ctx	*ctx;
	const struct location	*loc;
	bool			cache_needed;
};

extern int netlink_monitor(struct netlink_mon_handler *monhandler);
bool netlink_batch_supported(void);

struct mnl_socket *netlink_nfsock_open(void);

#endif /* NFTABLES_NETLINK_H */
