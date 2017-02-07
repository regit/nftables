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

/* We do not need to export these enums, because the tcpopts are parsed at
 * runtime and not by bison.
 */
enum tcpopt_eol_hdr_fields {
	TCPOPT_EOLHDR_KIND,
};

enum tcpopt_nop_hdr_fields {
	TCPOPT_NOPHDR_KIND,
};

enum tcpopt_maxseg_hdr_fields {
	TCPOPT_MAXSEGHDR_KIND,
	TCPOPT_MAXSEGHDR_LENGTH,
	TCPOPT_MAXSEGHDR_SIZE,
};

enum tcpopt_window_hdr_fields {
	TCPOPT_WINDOWHDR_KIND,
	TCPOPT_WINDOWHDR_LENGTH,
	TCPOPT_WINDOWHDR_COUNT,
};

enum tcpopt_sack_permitted_hdr_fields {
	TCPOPT_SACKPERMHDR_KIND,
	TCPOPT_SACKPERMHDR_LENGTH,
};

enum tcpopt_sack_hdr_fields {
	TCPOPT_SACKHDR_KIND,
	TCPOPT_SACKHDR_LENGTH,
	TCPOPT_SACKHDR_LEFT,
	TCPOPT_SACKHDR_RIGHT,
};

enum tcpopt_timestamp_hdr_fields {
	TCPOPT_TIMESTAMPSHDR_KIND,
	TCPOPT_TIMESTAMPSHDR_LENGTH,
	TCPOPT_TIMESTAMPSHDR_TSVAL,
	TCPOPT_TIMESTAMPSHDR_TSECR,
};

static const struct proto_hdr_template tcpopt_unknown_template =
	PROTO_HDR_TEMPLATE("unknown", &invalid_type, BYTEORDER_INVALID, 0, 0);

#define PHT(__token, __offset, __len) \
	PROTO_HDR_TEMPLATE(__token, &integer_type, BYTEORDER_BIG_ENDIAN, \
			   __offset, __len)
const struct exthdr_desc tcpopt_eol = {
	.name		= "eol",
	.type		= TCPOPT_EOL,
	.templates	= {
		[TCPOPT_EOLHDR_KIND]		= PHT("kind",  0,    8),
	},
};

const struct exthdr_desc tcpopt_nop = {
	.name		= "noop",
	.type		= TCPOPT_NOP,
	.templates	= {
		[TCPOPT_NOPHDR_KIND]		= PHT("kind",   0,   8),
	},
};

const struct exthdr_desc tcptopt_maxseg = {
	.name		= "maxseg",
	.type		= TCPOPT_MAXSEG,
	.templates	= {
		[TCPOPT_MAXSEGHDR_KIND]		= PHT("kind",   0,  8),
		[TCPOPT_MAXSEGHDR_LENGTH]	= PHT("length", 8,  8),
		[TCPOPT_MAXSEGHDR_SIZE]		= PHT("size",  16, 16),
	},
};

const struct exthdr_desc tcpopt_window = {
	.name		= "window",
	.type		= TCPOPT_WINDOW,
	.templates	= {
		[TCPOPT_WINDOWHDR_KIND]		= PHT("kind",   0,  8),
		[TCPOPT_WINDOWHDR_LENGTH]	= PHT("length", 8,  8),
		[TCPOPT_WINDOWHDR_COUNT]	= PHT("count", 16,  8),
	},
};

const struct exthdr_desc tcpopt_sack_permitted = {
	.name		= "sack_permitted",
	.type		= TCPOPT_SACK_PERMITTED,
	.templates	= {
		[TCPOPT_SACKPERMHDR_KIND]	= PHT("kind",   0, 8),
		[TCPOPT_SACKPERMHDR_LENGTH]	= PHT("length", 8, 8),
	},
};

const struct exthdr_desc tcpopt_sack = {
	.name		= "sack",
	.type		= TCPOPT_SACK,
	.templates	= {
		[TCPOPT_SACKHDR_KIND]		= PHT("kind",   0,   8),
		[TCPOPT_SACKHDR_LENGTH]		= PHT("length", 8,   8),
		[TCPOPT_SACKHDR_LEFT]		= PHT("left",  16,  32),
		[TCPOPT_SACKHDR_RIGHT]		= PHT("right", 48,  32),
	},
};

const struct exthdr_desc tcpopt_timestamp = {
	.name		= "timestamp",
	.type		= TCPOPT_TIMESTAMP,
	.templates	= {
		[TCPOPT_TIMESTAMPSHDR_KIND]	= PHT("kind",   0,  8),
		[TCPOPT_TIMESTAMPSHDR_LENGTH]	= PHT("length", 8,  8),
		[TCPOPT_TIMESTAMPSHDR_TSVAL]	= PHT("tsval",  16, 32),
		[TCPOPT_TIMESTAMPSHDR_TSECR]	= PHT("tsecr",  48, 32),
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


struct expr *tcpopt_expr_alloc(const struct location *loc,
			       const char *option_str,
			       const unsigned int option_num,
			       const char *option_field)
{
	const struct proto_hdr_template *tmp, *tmpl = &tcpopt_unknown_template;
	const struct exthdr_desc *desc = NULL;
	struct expr *expr;
	unsigned int i, j;

	for (i = 0; i < array_size(tcpopt_protocols); ++i) {
		if (tcpopt_protocols[i] == TCPOPT_OBSOLETE)
			continue;

		if (!tcpopt_protocols[i]->name ||
		    strcmp(option_str, tcpopt_protocols[i]->name))
			continue;

		for (j = 0; j < array_size(tcpopt_protocols[i]->templates); ++j) {
			tmp = &tcpopt_protocols[i]->templates[j];
			if (!tmp->token || strcmp(option_field, tmp->token))
				continue;

			desc = tcpopt_protocols[i];
			tmpl = tmp;
			goto found;
		}
	}

found:
	/* tmpl still points to tcpopt_unknown_template if nothing was found and
	 * desc is null
	 */
	expr = expr_alloc(loc, &exthdr_expr_ops, tmpl->dtype,
			  BYTEORDER_BIG_ENDIAN, tmpl->len);
	expr->exthdr.desc   = desc;
	expr->exthdr.tmpl   = tmpl;
	expr->exthdr.op     = NFT_EXTHDR_OP_TCPOPT;
	expr->exthdr.offset = calc_offset(desc, tmpl, option_num);

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
