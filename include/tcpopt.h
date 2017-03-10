#ifndef NFTABLES_TCPOPT_H
#define NFTABLES_TCPOPT_H

#include <proto.h>
#include <exthdr.h>

extern struct expr *tcpopt_expr_alloc(const struct location *loc,
				      uint8_t type, uint8_t field);

extern void tcpopt_init_raw(struct expr *expr, uint8_t type,
			    unsigned int offset, unsigned int len,
			    uint32_t flags);

extern bool tcpopt_find_template(struct expr *expr, const struct expr *mask,
				 unsigned int *shift);

enum tcpopt_hdr_types {
	TCPOPTHDR_INVALID,
	TCPOPTHDR_EOL,
	TCPOPTHDR_NOOP,
	TCPOPTHDR_MAXSEG,
	TCPOPTHDR_WINDOW,
	TCPOPTHDR_SACK_PERMITTED,
	TCPOPTHDR_SACK0,
	TCPOPTHDR_SACK1,
	TCPOPTHDR_SACK2,
	TCPOPTHDR_SACK3,
	TCPOPTHDR_TIMESTAMP,
	TCPOPTHDR_ECHO,
	TCPOPTHDR_ECHO_REPLY,
};

enum tcpopt_hdr_fields {
	TCPOPTHDR_FIELD_INVALID,
	TCPOPTHDR_FIELD_KIND,
	TCPOPTHDR_FIELD_LENGTH,
	TCPOPTHDR_FIELD_SIZE,
	TCPOPTHDR_FIELD_COUNT,
	TCPOPTHDR_FIELD_LEFT,
	TCPOPTHDR_FIELD_RIGHT,
	TCPOPTHDR_FIELD_TSVAL,
	TCPOPTHDR_FIELD_TSECR,
};

extern const struct exthdr_desc tcpopt_eol;
extern const struct exthdr_desc tcpopt_nop;
extern const struct exthdr_desc tcpopt_maxseg;
extern const struct exthdr_desc tcpopt_window;
extern const struct exthdr_desc tcpopt_sack_permitted;
extern const struct exthdr_desc tcpopt_sack;
extern const struct exthdr_desc tcpopt_timestamp;

#endif /* NFTABLES_TCPOPT_H */
