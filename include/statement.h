#ifndef NFTABLES_STATEMENT_H
#define NFTABLES_STATEMENT_H

#include <list.h>
#include <expression.h>

extern struct stmt *expr_stmt_alloc(const struct location *loc,
				    struct expr *expr);

extern struct stmt *verdict_stmt_alloc(const struct location *loc,
				       struct expr *expr);

struct objref_stmt {
	uint32_t		type;
	struct expr		*expr;
};

struct stmt *objref_stmt_alloc(const struct location *loc);

struct counter_stmt {
	uint64_t		packets;
	uint64_t		bytes;
};

extern struct stmt *counter_stmt_alloc(const struct location *loc);

struct payload_stmt {
	struct expr			*expr;
	struct expr			*val;
};

extern struct stmt *payload_stmt_alloc(const struct location *loc,
				       struct expr *payload, struct expr *expr);

#include <meta.h>
struct meta_stmt {
	enum nft_meta_keys		key;
	const struct meta_template	*tmpl;
	struct expr			*expr;
};

extern struct stmt *meta_stmt_alloc(const struct location *loc,
				    enum nft_meta_keys key,
				    struct expr *expr);

enum {
	STMT_LOG_PREFIX		= (1 << 0),
	STMT_LOG_SNAPLEN	= (1 << 1),
	STMT_LOG_GROUP		= (1 << 2),
	STMT_LOG_QTHRESHOLD	= (1 << 3),
	STMT_LOG_LEVEL		= (1 << 4),
};

struct log_stmt {
	const char		*prefix;
	unsigned int		snaplen;
	uint16_t		group;
	uint16_t		qthreshold;
	uint32_t		level;
	uint32_t		logflags;
	uint32_t		flags;
};

extern struct stmt *log_stmt_alloc(const struct location *loc);


struct limit_stmt {
	uint64_t		rate;
	uint64_t		unit;
	enum nft_limit_type	type;
	uint32_t		burst;
	uint32_t		flags;
};

extern struct stmt *limit_stmt_alloc(const struct location *loc);
extern void __limit_stmt_print(const struct limit_stmt *limit);

struct reject_stmt {
	struct expr		*expr;
	enum nft_reject_types	type;
	int8_t			icmp_code;
	unsigned int		family;
};

extern struct stmt *reject_stmt_alloc(const struct location *loc);

struct nat_stmt {
	enum nft_nat_types	type;
	struct expr		*addr;
	struct expr		*proto;
	uint32_t		flags;
};

extern struct stmt *nat_stmt_alloc(const struct location *loc);

struct masq_stmt {
	uint32_t		flags;
	struct expr		*proto;
};

extern struct stmt *masq_stmt_alloc(const struct location *loc);

struct redir_stmt {
	struct expr		*proto;
	uint32_t		flags;
};

extern struct stmt *redir_stmt_alloc(const struct location *loc);

struct queue_stmt {
	struct expr		*queue;
	uint16_t		flags;
};

extern struct stmt *queue_stmt_alloc(const struct location *loc);

struct quota_stmt {
	uint64_t		bytes;
	uint64_t		used;
	uint32_t		flags;
};

struct stmt *quota_stmt_alloc(const struct location *loc);

#include <ct.h>
struct ct_stmt {
	enum nft_ct_keys		key;
	const struct ct_template	*tmpl;
	struct expr			*expr;
};

extern struct stmt *ct_stmt_alloc(const struct location *loc,
				  enum nft_ct_keys key,
				  struct expr *expr);
struct dup_stmt {
	struct expr		*to;
	struct expr		*dev;
};

struct stmt *dup_stmt_alloc(const struct location *loc);
uint32_t dup_stmt_type(const char *type);

struct fwd_stmt {
	struct expr		*to;
};

struct stmt *fwd_stmt_alloc(const struct location *loc);
uint32_t fwd_stmt_type(const char *type);

struct set_stmt {
	struct expr		*set;
	struct expr		*key;
	enum nft_dynset_ops	op;
};

extern struct stmt *set_stmt_alloc(const struct location *loc);

struct flow_stmt {
	struct expr		*set;
	struct expr		*key;
	struct stmt		*stmt;
	const char		*table;
};

extern struct stmt *flow_stmt_alloc(const struct location *loc);

/**
 * enum nft_xt_type - xtables statement types
 *
 * @NFT_XT_MATCH:	match
 * @NFT_XT_TARGET:	target
 * @NFT_XT_WATCHER:	watcher (only for the bridge family)
 */
enum nft_xt_type {
	NFT_XT_MATCH = 0,
	NFT_XT_TARGET,
	NFT_XT_WATCHER,
	NFT_XT_MAX
};

struct xtables_match;
struct xtables_target;

struct xt_stmt {
	const char			*name;
	enum nft_xt_type		type;
	uint32_t			proto;
	union {
		struct xtables_match	*match;
		struct xtables_target	*target;
	};
	const char			*opts;
	void				*entry;
};

extern struct stmt *xt_stmt_alloc(const struct location *loc);

/**
 * enum stmt_types - statement types
 *
 * @STMT_INVALID:	uninitialised
 * @STMT_EXPRESSION:	expression statement (relational)
 * @STMT_VERDICT:	verdict statement
 * @STMT_FLOW:		flow statement
 * @STMT_COUNTER:	counters
 * @STMT_PAYLOAD:	payload statement
 * @STMT_META:		meta statement
 * @STMT_LIMIT:		limit statement
 * @STMT_LOG:		log statement
 * @STMT_REJECT:	REJECT statement
 * @STMT_NAT:		NAT statement
 * @STMT_MASQ:		masquerade statement
 * @STMT_REDIR:		redirect statement
 * @STMT_QUEUE:		QUEUE statement
 * @STMT_CT:		conntrack statement
 * @STMT_SET:		set statement
 * @STMT_DUP:		dup statement
 * @STMT_FWD:		forward statement
 * @STMT_XT:		XT statement
 * @STMT_QUOTA:		quota statement
 * @STMT_NOTRACK:	notrack statement
 * @STMT_OBJREF:	stateful object reference statement
 */
enum stmt_types {
	STMT_INVALID,
	STMT_EXPRESSION,
	STMT_VERDICT,
	STMT_FLOW,
	STMT_COUNTER,
	STMT_PAYLOAD,
	STMT_META,
	STMT_LIMIT,
	STMT_LOG,
	STMT_REJECT,
	STMT_NAT,
	STMT_MASQ,
	STMT_REDIR,
	STMT_QUEUE,
	STMT_CT,
	STMT_SET,
	STMT_DUP,
	STMT_FWD,
	STMT_XT,
	STMT_QUOTA,
	STMT_NOTRACK,
	STMT_OBJREF,
};

/**
 * struct stmt_ops
 *
 * @type:	statement type
 * @name:	name
 * @destroy:	destructor
 * @print:	function to print statement
 */
struct stmt;
struct stmt_ops {
	enum stmt_types		type;
	const char		*name;
	void			(*destroy)(struct stmt *stmt);
	void			(*print)(const struct stmt *stmt);
};

enum stmt_flags {
	STMT_F_TERMINAL		= 0x1,
	STMT_F_STATEFUL		= 0x2,
};

/**
 * struct stmt
 *
 * @list:	rule list node
 * @ops:	statement ops
 * @location:	location where the statement was defined
 * @flags:	statement flags
 * @union:	type specific data
 */
struct stmt {
	struct list_head		list;
	const struct stmt_ops		*ops;
	struct location			location;
	enum stmt_flags			flags;

	union {
		struct expr		*expr;
		struct flow_stmt	flow;
		struct counter_stmt	counter;
		struct payload_stmt	payload;
		struct meta_stmt	meta;
		struct log_stmt		log;
		struct limit_stmt	limit;
		struct reject_stmt	reject;
		struct nat_stmt		nat;
		struct masq_stmt	masq;
		struct redir_stmt	redir;
		struct queue_stmt	queue;
		struct quota_stmt	quota;
		struct ct_stmt		ct;
		struct set_stmt		set;
		struct dup_stmt		dup;
		struct fwd_stmt		fwd;
		struct xt_stmt		xt;
		struct objref_stmt	objref;
	};
};

extern struct stmt *stmt_alloc(const struct location *loc,
			       const struct stmt_ops *ops);
int stmt_evaluate(struct eval_ctx *ctx, struct stmt *stmt);
extern void stmt_free(struct stmt *stmt);
extern void stmt_list_free(struct list_head *list);
extern void stmt_print(const struct stmt *stmt);

const char *get_rate(uint64_t byte_rate, uint64_t *rate);

#endif /* NFTABLES_STATEMENT_H */
