#ifndef NFTABLES_TCPOPT_H
#define NFTABLES_TCPOPT_H

#include <proto.h>
#include <exthdr.h>

extern struct expr *tcpopt_expr_alloc(const struct location *loc,
				      const char *option_str,
				      const unsigned int option_num,
				      const char *optioni_field);

extern void tcpopt_init_raw(struct expr *expr, uint8_t type,
			    unsigned int offset, unsigned int len);

extern bool tcpopt_find_template(struct expr *expr, const struct expr *mask,
				 unsigned int *shift);

extern const struct exthdr_desc tcpopt_eol;
extern const struct exthdr_desc tcpopt_nop;
extern const struct exthdr_desc tcpopt_maxseg;
extern const struct exthdr_desc tcpopt_window;
extern const struct exthdr_desc tcpopt_sack_permitted;
extern const struct exthdr_desc tcpopt_sack;
extern const struct exthdr_desc tcpopt_timestamp;

#endif /* NFTABLES_TCPOPT_H */
