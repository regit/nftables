#ifndef NFTABLES_EREC_H
#define NFTABLES_EREC_H

#include <nftables.h>
#include <utils.h>

/**
 * enum error_record_types
 *
 * @EREC_INFORMATIONAL:	informational message
 * @EREC_WARNING:	warning message
 * @EREC_ERROR:		error message
 */
enum error_record_types {
	EREC_INFORMATIONAL,
	EREC_WARNING,
	EREC_ERROR,
};

#define EREC_MSGBUFSIZE		1024
#define EREC_LOCATIONS_MAX	3

/**
 * struct error_record
 *
 * @list:		message queue node
 * @type:		error record type
 * @num_locations:	number of locations
 * @locations:		location(s) of error
 * @msg:		message
 */
struct error_record {
	struct list_head	list;
	enum error_record_types	type;
	unsigned int		num_locations;
	struct location		locations[EREC_LOCATIONS_MAX];
	char			*msg;
};

extern struct error_record *erec_vcreate(enum error_record_types type,
					 const struct location *loc,
					 const char *fmt, va_list ap)
					 __gmp_fmtstring(3, 0);
extern struct error_record *erec_create(enum error_record_types type,
					const struct location *loc,
					const char *fmt, ...) __gmp_fmtstring(3, 4);
extern void erec_add_location(struct error_record *erec,
			      const struct location *loc);

#define error(loc, fmt, args...) \
	erec_create(EREC_ERROR, (loc), (fmt), ## args)
#define warning(loc, fmt, args...) \
	erec_create(EREC_WARNING, (loc), (fmt), ## args)

static inline void erec_queue(struct error_record *erec,
			      struct list_head *queue)
{
	list_add_tail(&erec->list, queue);
}

extern void erec_print(FILE *f, const struct error_record *erec);
extern void erec_print_list(FILE *f, struct list_head *list);
void erec_free_list(struct list_head *list);

struct eval_ctx;

extern int __fmtstring(4, 5) __stmt_binary_error(struct eval_ctx *ctx,
						 const struct location *l1,
						 const struct location *l2,
						 const char *fmt, ...);

#define stmt_error(ctx, s1, fmt, args...) \
	__stmt_binary_error(ctx, &(s1)->location, NULL, fmt, ## args)
#define stmt_binary_error(ctx, s1, s2, fmt, args...) \
	__stmt_binary_error(ctx, &(s1)->location, &(s2)->location, fmt, ## args)

#endif /* NFTABLES_EREC_H */
