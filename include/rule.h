#ifndef NFTABLES_RULE_H
#define NFTABLES_RULE_H

#include <stdint.h>
#include <nftables.h>
#include <list.h>

/**
 * struct handle_spec - handle ID
 *
 * @location:	location this handle was defined at
 * @id:		handle ID value
 */
struct handle_spec {
	struct location		location;
	uint64_t		id;
};

/**
 * struct position_spec - position ID
 *
 * @location:	location this position was defined at
 * @id:		position ID value
 */
struct position_spec {
	struct location		location;
	uint64_t		id;
};

/**
 * struct handle - handle for tables, chains, rules and sets
 *
 * @family:	protocol family
 * @table:	table name
 * @chain:	chain name (chains and rules only)
 * @set:	set name (sets only)
 * @obj:	stateful object name (stateful object only)
 * @handle:	rule handle (rules only)
 * @position:	rule position (rules only)
 * @set_id:	set ID (sets only)
 */
struct handle {
	uint32_t		family;
	const char		*table;
	const char		*chain;
	const char		*set;
	const char		*obj;
	struct handle_spec	handle;
	struct position_spec	position;
	uint32_t		set_id;
};

extern void handle_merge(struct handle *dst, const struct handle *src);
extern void handle_free(struct handle *h);

/**
 * struct scope
 *
 * @parent:	pointer to parent scope
 * @symbols:	symbols bound in the scope
 */
struct scope {
	const struct scope	*parent;
	struct list_head	symbols;
};

extern struct scope *scope_init(struct scope *scope, const struct scope *parent);
extern void scope_release(const struct scope *scope);

/**
 * struct symbol
 *
 * @list:	scope symbol list node
 * @identifier:	identifier
 * @expr:	initializer
 */
struct symbol {
	struct list_head	list;
	const char		*identifier;
	struct expr		*expr;
};

extern void symbol_bind(struct scope *scope, const char *identifier,
			struct expr *expr);
extern struct symbol *symbol_lookup(const struct scope *scope,
				    const char *identifier);

enum table_flags {
	TABLE_F_DORMANT		= (1 << 0),
};

/**
 * struct table - nftables table
 *
 * @list:	list node
 * @handle:	table handle
 * @location:	location the table was defined at
 * @chains:	chains contained in the table
 * @sets:	sets contained in the table
 * @objs:	stateful objects contained in the table
 * @flags:	table flags
 * @refcnt:	table reference counter
 */
struct table {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	struct scope		scope;
	struct list_head	chains;
	struct list_head	sets;
	struct list_head	objs;
	enum table_flags 	flags;
	unsigned int		refcnt;
};

extern struct table *table_alloc(void);
extern struct table *table_get(struct table *table);
extern void table_free(struct table *table);
extern void table_add_hash(struct table *table);
extern struct table *table_lookup(const struct handle *h);

/**
 * enum chain_flags - chain flags
 *
 * @CHAIN_F_BASECHAIN:	chain is a base chain
 */
enum chain_flags {
	CHAIN_F_BASECHAIN	= 0x1,
};

/**
 * struct chain - nftables chain
 *
 * @list:	list node in table list
 * @handle:	chain handle
 * @location:	location the chain was defined at
 * @refcnt:	reference counter
 * @flags:	chain flags
 * @hookstr:	unified and human readable hook name (base chains)
 * @hooknum:	hook number (base chains)
 * @priority:	hook priority (base chains)
 * @policy:	default chain policy (base chains)
 * @type:	chain type
 * @dev:	device (if any)
 * @rules:	rules contained in the chain
 */
struct chain {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	unsigned int		refcnt;
	uint32_t		flags;
	const char		*hookstr;
	unsigned int		hooknum;
	int			priority;
	int			policy;
	const char		*type;
	const char		*dev;
	struct scope		scope;
	struct list_head	rules;
};

extern const char *chain_type_name_lookup(const char *name);
extern const char *chain_hookname_lookup(const char *name);
extern struct chain *chain_alloc(const char *name);
extern struct chain *chain_get(struct chain *chain);
extern void chain_free(struct chain *chain);
extern void chain_add_hash(struct chain *chain, struct table *table);
extern struct chain *chain_lookup(const struct table *table,
				  const struct handle *h);

extern const char *family2str(unsigned int family);
extern const char *hooknum2str(unsigned int family, unsigned int hooknum);
extern void chain_print_plain(const struct chain *chain);

/**
 * struct rule - nftables rule
 *
 * @list:	list node in chain list
 * @handle:	rule handle
 * @location:	location the rule was defined at
 * @stmt:	list of statements
 * @num_stmts:	number of statements in stmts list
 * @comment:	comment
 */
struct rule {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	struct list_head	stmts;
	unsigned int		num_stmts;
	const char		*comment;
};

extern struct rule *rule_alloc(const struct location *loc,
			       const struct handle *h);
extern void rule_free(struct rule *rule);
extern void rule_print(const struct rule *rule);
extern struct rule *rule_lookup(const struct chain *chain, uint64_t handle);

/**
 * struct set - nftables set
 *
 * @list:	table set list node
 * @handle:	set handle
 * @location:	location the set was defined/declared at
 * @refcnt:	reference count
 * @flags:	bitmask of set flags
 * @gc_int:	garbage collection interval
 * @timeout:	default timeout value
 * @keytype:	key data type
 * @keylen:	key length
 * @datatype:	mapping data type
 * @datalen:	mapping data len
 * @init:	initializer
 * @policy:	set mechanism policy
 * @desc:	set mechanism desc
 */
struct set {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	unsigned int		refcnt;
	uint32_t		flags;
	uint32_t		gc_int;
	uint64_t		timeout;
	const struct datatype	*keytype;
	unsigned int		keylen;
	const struct datatype	*datatype;
	unsigned int		datalen;
	struct expr		*init;
	uint32_t		policy;
	struct {
		uint32_t	size;
	} desc;
};

extern struct set *set_alloc(const struct location *loc);
extern struct set *set_get(struct set *set);
extern void set_free(struct set *set);
extern void set_add_hash(struct set *set, struct table *table);
extern struct set *set_lookup(const struct table *table, const char *name);
extern struct set *set_lookup_global(uint32_t family, const char *table,
				     const char *name);
extern void set_print(const struct set *set);
extern void set_print_plain(const struct set *s);

#include <statement.h>

struct counter {
	uint64_t	packets;
	uint64_t	bytes;
};

struct quota {
	uint64_t	bytes;
	uint64_t	used;
	uint32_t	flags;
};

/**
 * struct obj - nftables stateful object statement
 *
 * @list:	table set list node
 * @location:	location the stateful object was defined/declared at
 * @handle:	counter handle
 * @type:	type of stateful object
 */
struct obj {
	struct list_head		list;
	struct location			location;
	struct handle			handle;
	uint32_t			type;

	union {
		struct counter		counter;
		struct quota		quota;
	};
};

struct obj *obj_alloc(const struct location *loc);
void obj_free(struct obj *obj);
void obj_add_hash(struct obj *obj, struct table *table);
void obj_print(const struct obj *n);
const char *obj_type_name(enum stmt_types type);

/**
 * enum cmd_ops - command operations
 *
 * @CMD_INVALID:	invalid
 * @CMD_ADD:		add object (non-exclusive)
 * @CMD_REPLACE,	replace object
 * @CMD_CREATE:		create object (exclusive)
 * @CMD_INSERT:		insert object
 * @CMD_DELETE:		delete object
 * @CMD_LIST:		list container
 * @CMD_FLUSH:		flush container
 * @CMD_RENAME:		rename object
 * @CMD_EXPORT:		export the ruleset in a given format
 * @CMD_MONITOR:	event listener
 * @CMD_DESCRIBE:	describe an expression
 */
enum cmd_ops {
	CMD_INVALID,
	CMD_ADD,
	CMD_REPLACE,
	CMD_CREATE,
	CMD_INSERT,
	CMD_DELETE,
	CMD_LIST,
	CMD_FLUSH,
	CMD_RENAME,
	CMD_EXPORT,
	CMD_MONITOR,
	CMD_DESCRIBE,
};

/**
 * enum cmd_obj - command objects
 *
 * @CMD_OBJ_INVALID:	invalid
 * @CMD_OBJ_SETELEM:	set element(s)
 * @CMD_OBJ_SET:	set
 * @CMD_OBJ_SETS:	multiple sets
 * @CMD_OBJ_RULE:	rule
 * @CMD_OBJ_CHAIN:	chain
 * @CMD_OBJ_CHAINS:	multiple chains
 * @CMD_OBJ_TABLE:	table
 * @CMD_OBJ_RULESET:	ruleset
 * @CMD_OBJ_EXPR:	expression
 * @CMD_OBJ_MONITOR:	monitor
 * @CMD_OBJ_EXPORT:	export
 * @CMD_OBJ_COUNTER:	counter
 * @CMD_OBJ_COUNTERS:	multiple counters
 * @CMD_OBJ_QUOTA:	quota
 * @CMD_OBJ_QUOTAS:	multiple quotas
 */
enum cmd_obj {
	CMD_OBJ_INVALID,
	CMD_OBJ_SETELEM,
	CMD_OBJ_SET,
	CMD_OBJ_SETS,
	CMD_OBJ_RULE,
	CMD_OBJ_CHAIN,
	CMD_OBJ_CHAINS,
	CMD_OBJ_TABLE,
	CMD_OBJ_RULESET,
	CMD_OBJ_EXPR,
	CMD_OBJ_MONITOR,
	CMD_OBJ_EXPORT,
	CMD_OBJ_FLOWTABLE,
	CMD_OBJ_FLOWTABLES,
	CMD_OBJ_MAP,
	CMD_OBJ_MAPS,
	CMD_OBJ_COUNTER,
	CMD_OBJ_COUNTERS,
	CMD_OBJ_QUOTA,
	CMD_OBJ_QUOTAS,
};

struct export {
	uint32_t	format;
};

struct export *export_alloc(uint32_t format);
void export_free(struct export *e);

enum {
	CMD_MONITOR_OBJ_ANY,
	CMD_MONITOR_OBJ_TABLES,
	CMD_MONITOR_OBJ_CHAINS,
	CMD_MONITOR_OBJ_RULES,
	CMD_MONITOR_OBJ_SETS,
	CMD_MONITOR_OBJ_ELEMS,
	CMD_MONITOR_OBJ_MAX
};

struct monitor {
	struct location	location;
	uint32_t	format;
	uint32_t	flags;
	uint32_t	type;
	const char	*event;
};

struct monitor *monitor_alloc(uint32_t format, uint32_t type, const char *event);
void monitor_free(struct monitor *m);

/**
 * struct cmd - command statement
 *
 * @list:	list node
 * @location:	location of the statement
 * @op:		operation
 * @obj:	object type to perform operation on
 * @handle:	handle for operations working without full objects
 * @seqnum:	sequence number to match netlink errors
 * @union:	object
 * @arg:	argument data
 * @format:	info about the export/import format
 */
struct cmd {
	struct list_head	list;
	struct location		location;
	enum cmd_ops		op;
	enum cmd_obj		obj;
	struct handle		handle;
	uint32_t		seqnum;
	union {
		void		*data;
		struct expr	*expr;
		struct set	*set;
		struct rule	*rule;
		struct chain	*chain;
		struct table	*table;
		struct monitor	*monitor;
		struct export	*export;
	};
	const void		*arg;
};

extern struct cmd *cmd_alloc(enum cmd_ops op, enum cmd_obj obj,
			     const struct handle *h, const struct location *loc,
			     void *data);
extern void cmd_free(struct cmd *cmd);

#include <payload.h>
#include <expression.h>

/**
 * struct eval_ctx - evaluation context
 *
 * @msgs:	message queue
 * @cmd:	current command
 * @table:	current table
 * @rule:	current rule
 * @set:	current set
 * @stmt:	current statement
 * @ectx:	expression context
 * @pctx:	payload context
 */
struct eval_ctx {
	struct list_head	*msgs;
	struct cmd		*cmd;
	struct table		*table;
	struct rule		*rule;
	struct set		*set;
	struct stmt		*stmt;
	struct expr_ctx		ectx;
	struct proto_ctx	pctx;
};

extern int cmd_evaluate(struct eval_ctx *ctx, struct cmd *cmd);

extern struct error_record *rule_postprocess(struct rule *rule);

struct netlink_ctx;
extern int do_command(struct netlink_ctx *ctx, struct cmd *cmd);

extern int cache_update(enum cmd_ops cmd, struct list_head *msgs);
extern void cache_flush(void);
extern void cache_release(void);

enum udata_type {
	UDATA_TYPE_COMMENT,
	__UDATA_TYPE_MAX,
};
#define UDATA_TYPE_MAX (__UDATA_TYPE_MAX - 1)

#define UDATA_COMMENT_MAXLEN 128

#endif /* NFTABLES_RULE_H */
