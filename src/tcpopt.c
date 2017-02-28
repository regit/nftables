#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <utils.h>
#include <headers.h>
#include <expression.h>
#include <tcpopt.h>

static const struct proto_hdr_template tcpopt_unknown_template =
	PROTO_HDR_TEMPLATE("unknown", &invalid_type, BYTEORDER_INVALID, 0, 0);

#define PHT(__token, __offset, __len) \
	PROTO_HDR_TEMPLATE(__token, &integer_type, BYTEORDER_BIG_ENDIAN, \
			   __offset, __len)
const struct exthdr_desc tcpopt_eol = {
	.name		= "eol",
	.type		= TCPOPT_EOL,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",  0,    8),
	},
};

const struct exthdr_desc tcpopt_nop = {
	.name		= "noop",
	.type		= TCPOPT_NOP,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,   8),
	},
};

const struct exthdr_desc tcptopt_maxseg = {
	.name		= "maxseg",
	.type		= TCPOPT_MAXSEG,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,  8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8,  8),
		[TCPOPTHDR_FIELD_SIZE]		= PHT("size",  16, 16),
	},
};

const struct exthdr_desc tcpopt_window = {
	.name		= "window",
	.type		= TCPOPT_WINDOW,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,  8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8,  8),
		[TCPOPTHDR_FIELD_COUNT]		= PHT("count", 16,  8),
	},
};

const struct exthdr_desc tcpopt_sack_permitted = {
	.name		= "sack-permitted",
	.type		= TCPOPT_SACK_PERMITTED,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0, 8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8, 8),
	},
};

const struct exthdr_desc tcpopt_sack = {
	.name		= "sack",
	.type		= TCPOPT_SACK,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,   8),
		[TCPOPTHDR_FIELD_LENGTH]		= PHT("length", 8,   8),
		[TCPOPTHDR_FIELD_LEFT]		= PHT("left",  16,  32),
		[TCPOPTHDR_FIELD_RIGHT]		= PHT("right", 48,  32),
	},
};

const struct exthdr_desc tcpopt_timestamp = {
	.name		= "timestamp",
	.type		= TCPOPT_TIMESTAMP,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,  8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8,  8),
		[TCPOPTHDR_FIELD_TSVAL]		= PHT("tsval",  16, 32),
		[TCPOPTHDR_FIELD_TSECR]		= PHT("tsecr",  48, 32),
	},
};
#undef PHT

#define TCPOPT_OBSOLETE ((struct exthdr_desc *)NULL)
#define TCPOPT_ECHO 6
#define TCPOPT_ECHO_REPLY 7
const struct exthdr_desc *tcpopt_protocols[] = {
	[TCPOPT_EOL]		= &tcpopt_eol,
	[TCPOPT_NOP]		= &tcpopt_nop,
	[TCPOPT_MAXSEG]		= &tcptopt_maxseg,
	[TCPOPT_WINDOW]		= &tcpopt_window,
	[TCPOPT_SACK_PERMITTED]	= &tcpopt_sack_permitted,
	[TCPOPT_SACK]		= &tcpopt_sack,
	[TCPOPT_ECHO]		= TCPOPT_OBSOLETE,
	[TCPOPT_ECHO_REPLY]	= TCPOPT_OBSOLETE,
	[TCPOPT_TIMESTAMP]	= &tcpopt_timestamp,
};

static unsigned int calc_offset(const struct exthdr_desc *desc,
				const struct proto_hdr_template *tmpl,
				unsigned int num)
{
	if (!desc || tmpl == &tcpopt_unknown_template)
		return 0;

	switch (desc->type) {
	case TCPOPT_SACK:
		/* Make sure, offset calculations only apply to left and right
		 * fields
		 */
		return (tmpl->offset < 16) ? 0 : num * 64;
	default:
		return 0;
	}
}


static unsigned int calc_offset_reverse(const struct exthdr_desc *desc,
					const struct proto_hdr_template *tmpl,
					unsigned int offset)
{
	if (!desc || tmpl == &tcpopt_unknown_template)
		return offset;

	switch (desc->type) {
	case TCPOPT_SACK:
		/* We can safely ignore the first left/right field */
		return offset < 80 ? offset : (offset % 64);
	default:
		return offset;
	}
}

static const struct exthdr_desc *tcpopthdr_protocols[] = {
	[TCPOPTHDR_EOL]			= &tcpopt_eol,
	[TCPOPTHDR_NOOP]		= &tcpopt_nop,
	[TCPOPTHDR_MAXSEG]		= &tcptopt_maxseg,
	[TCPOPTHDR_WINDOW]		= &tcpopt_window,
	[TCPOPTHDR_SACK_PERMITTED]	= &tcpopt_sack_permitted,
	[TCPOPTHDR_SACK0]		= &tcpopt_sack,
	[TCPOPTHDR_SACK1]		= &tcpopt_sack,
	[TCPOPTHDR_SACK2]		= &tcpopt_sack,
	[TCPOPTHDR_SACK3]		= &tcpopt_sack,
	[TCPOPTHDR_ECHO]		= TCPOPT_OBSOLETE,
	[TCPOPTHDR_ECHO_REPLY]		= TCPOPT_OBSOLETE,
	[TCPOPTHDR_TIMESTAMP]		= &tcpopt_timestamp,
};

static uint8_t tcpopt_optnum[] = {
	[TCPOPTHDR_SACK0]	= 0,
	[TCPOPTHDR_SACK1]	= 1,
	[TCPOPTHDR_SACK2]	= 2,
	[TCPOPTHDR_SACK3]	= 3,
};

static uint8_t tcpopt_find_optnum(uint8_t optnum)
{
	if (optnum > TCPOPTHDR_SACK3)
		return 0;

	return tcpopt_optnum[optnum];
}

struct expr *tcpopt_expr_alloc(const struct location *loc, uint8_t type,
			       uint8_t field)
{
	const struct proto_hdr_template *tmpl;
	const struct exthdr_desc *desc;
	struct expr *expr;
	uint8_t optnum;

	desc = tcpopthdr_protocols[type];
	tmpl = &desc->templates[field];
	if (!tmpl)
		return NULL;

	optnum = tcpopt_find_optnum(type);

	expr = expr_alloc(loc, &exthdr_expr_ops, tmpl->dtype,
			  BYTEORDER_BIG_ENDIAN, tmpl->len);
	expr->exthdr.desc   = desc;
	expr->exthdr.tmpl   = tmpl;
	expr->exthdr.op     = NFT_EXTHDR_OP_TCPOPT;
	expr->exthdr.offset = calc_offset(desc, tmpl, optnum);

	return expr;
}

void tcpopt_init_raw(struct expr *expr, uint8_t type, unsigned int offset,
		     unsigned int len)
{
	const struct proto_hdr_template *tmpl;
	unsigned int i, off;

	assert(expr->ops->type == EXPR_EXTHDR);

	expr->len = len;
	expr->exthdr.offset = offset;

	assert(type < array_size(tcpopt_protocols));
	expr->exthdr.desc = tcpopt_protocols[type];
	assert(expr->exthdr.desc != TCPOPT_OBSOLETE);

	for (i = 0; i < array_size(expr->exthdr.desc->templates); ++i) {
		tmpl = &expr->exthdr.desc->templates[i];
		/* We have to reverse calculate the offset for the sack options
		 * at this point
		 */
		off = calc_offset_reverse(expr->exthdr.desc, tmpl, offset);
		if (tmpl->offset != off || tmpl->len != len)
			continue;

		expr->dtype       = tmpl->dtype;
		expr->exthdr.tmpl = tmpl;
		expr->exthdr.op   = NFT_EXTHDR_OP_TCPOPT;
		break;
	}
}

bool tcpopt_find_template(struct expr *expr, const struct expr *mask,
			  unsigned int *shift)
{
	if (expr->exthdr.tmpl != &tcpopt_unknown_template)
		return false;

	tcpopt_init_raw(expr, expr->exthdr.desc->type, expr->exthdr.offset,
			expr->len);

	if (expr->exthdr.tmpl == &tcpopt_unknown_template)
		return false;

	return true;
}
