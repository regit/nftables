#ifndef NFTABLES_META_H
#define NFTABLES_META_H

/**
 * struct meta_template - template for meta expressions and statements
 *
 * @token:	parser token for the expression
 * @dtype:	data type of the expression
 * @len:	length of the expression
 * @byteorder:	byteorder
 */
struct meta_template {
	const char		*token;
	const struct datatype	*dtype;
	enum byteorder		byteorder;
	unsigned int		len;
};

#define META_TEMPLATE(__token, __dtype, __len, __byteorder) {	\
	.token		= (__token),				\
	.dtype		= (__dtype),				\
	.len		= (__len),				\
	.byteorder	= (__byteorder),			\
}

extern struct expr *meta_expr_alloc(const struct location *loc,
				    enum nft_meta_keys key);

struct stmt *meta_stmt_meta_iiftype(const struct location *loc, uint16_t type);

const struct datatype ifindex_type;

struct error_record *meta_key_parse(const struct location *loc,
				    const char *name,
				    unsigned int *value);

#endif /* NFTABLES_META_H */
