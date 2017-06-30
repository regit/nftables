#ifndef NFTABLES_FIB_H
#define NFTABLES_FIB_H

extern struct expr *fib_expr_alloc(const struct location *loc,
				   unsigned int flags,
				   unsigned int result);
extern const struct datatype fib_addr_type;

#endif /* NFTABLES_FIB_H */
