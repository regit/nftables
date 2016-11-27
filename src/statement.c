/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <statement.h>
#include <utils.h>
#include <list.h>
#include <xt.h>

#include <netinet/in.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/nf_log.h>

struct stmt *stmt_alloc(const struct location *loc,
			const struct stmt_ops *ops)
{
	struct stmt *stmt;

	stmt = xzalloc(sizeof(*stmt));
	init_list_head(&stmt->list);
	stmt->location = *loc;
	stmt->ops      = ops;
	return stmt;
}

void stmt_free(struct stmt *stmt)
{
	if (stmt == NULL)
		return;
	if (stmt->ops->destroy)
		stmt->ops->destroy(stmt);
	xfree(stmt);
}

void stmt_list_free(struct list_head *list)
{
	struct stmt *i, *next;

	list_for_each_entry_safe(i, next, list, list) {
		list_del(&i->list);
		stmt_free(i);
	}
}

void stmt_print(const struct stmt *stmt)
{
	stmt->ops->print(stmt);
}

static void expr_stmt_print(const struct stmt *stmt)
{
	expr_print(stmt->expr);
}

static void expr_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->expr);
}

static const struct stmt_ops expr_stmt_ops = {
	.type		= STMT_EXPRESSION,
	.name		= "expression",
	.print		= expr_stmt_print,
	.destroy	= expr_stmt_destroy,
};

struct stmt *expr_stmt_alloc(const struct location *loc, struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &expr_stmt_ops);
	stmt->expr = expr;
	return stmt;
}

static const struct stmt_ops verdict_stmt_ops = {
	.type		= STMT_VERDICT,
	.name		= "verdict",
	.print		= expr_stmt_print,
	.destroy	= expr_stmt_destroy,
};

struct stmt *verdict_stmt_alloc(const struct location *loc, struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &verdict_stmt_ops);
	stmt->expr = expr;
	return stmt;
}

static void flow_stmt_print(const struct stmt *stmt)
{
	printf("flow ");
	if (stmt->flow.set) {
		expr_print(stmt->flow.set);
		printf(" ");
	}
	printf("{ ");
	expr_print(stmt->flow.key);
	printf(" ");
	stmt_print(stmt->flow.stmt);
	printf("} ");
}

static void flow_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->flow.key);
	expr_free(stmt->flow.set);
	stmt_free(stmt->flow.stmt);
}

static const struct stmt_ops flow_stmt_ops = {
	.type		= STMT_FLOW,
	.name		= "flow",
	.print		= flow_stmt_print,
	.destroy	= flow_stmt_destroy,
};

struct stmt *flow_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &flow_stmt_ops);
}

static void counter_stmt_print(const struct stmt *stmt)
{
	printf("counter packets %" PRIu64 " bytes %" PRIu64,
	       stmt->counter.packets, stmt->counter.bytes);
}

static const struct stmt_ops counter_stmt_ops = {
	.type		= STMT_COUNTER,
	.name		= "counter",
	.print		= counter_stmt_print,
};

struct stmt *counter_stmt_alloc(const struct location *loc)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &counter_stmt_ops);
	stmt->flags |= STMT_F_STATEFUL;
	return stmt;
}

static const char *objref_type[NFT_OBJECT_MAX + 1] = {
	[NFT_OBJECT_COUNTER]	= "counter",
	[NFT_OBJECT_QUOTA]	= "quota",
};

static const char *objref_type_name(uint32_t type)
{
	if (type > NFT_OBJECT_MAX)
		return "unknown";

	return objref_type[type];
}

static void objref_stmt_print(const struct stmt *stmt)
{
	printf("%s name ", objref_type_name(stmt->objref.type));
	expr_print(stmt->objref.expr);
}

static const struct stmt_ops objref_stmt_ops = {
	.type		= STMT_OBJREF,
	.name		= "objref",
	.print		= objref_stmt_print,
};

struct stmt *objref_stmt_alloc(const struct location *loc)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &objref_stmt_ops);
	return stmt;
}

static const char *syslog_level[LOG_DEBUG + 1] = {
	[LOG_EMERG]	= "emerg",
	[LOG_ALERT]	= "alert",
	[LOG_CRIT]	= "crit",
	[LOG_ERR]       = "err",
	[LOG_WARNING]	= "warn",
	[LOG_NOTICE]	= "notice",
	[LOG_INFO]	= "info",
	[LOG_DEBUG]	= "debug",
};

static const char *log_level(uint32_t level)
{
	if (level > LOG_DEBUG)
		return "unknown";

	return syslog_level[level];
}

static void log_stmt_print(const struct stmt *stmt)
{
	printf("log");
	if (stmt->log.flags & STMT_LOG_PREFIX)
		printf(" prefix \"%s\"", stmt->log.prefix);
	if (stmt->log.flags & STMT_LOG_GROUP)
		printf(" group %u", stmt->log.group);
	if (stmt->log.flags & STMT_LOG_SNAPLEN)
		printf(" snaplen %u", stmt->log.snaplen);
	if (stmt->log.flags & STMT_LOG_QTHRESHOLD)
		printf(" queue-threshold %u", stmt->log.qthreshold);
	if ((stmt->log.flags & STMT_LOG_LEVEL) &&
	    stmt->log.level != LOG_WARNING)
		printf(" level %s", log_level(stmt->log.level));

	if ((stmt->log.logflags & NF_LOG_MASK) == NF_LOG_MASK) {
		printf(" flags all");
	} else {
		if (stmt->log.logflags & (NF_LOG_TCPSEQ | NF_LOG_TCPOPT)) {
			const char *delim = " ";

			printf(" flags tcp");
			if (stmt->log.logflags & NF_LOG_TCPSEQ) {
				printf(" sequence");
				delim = ",";
			}
			if (stmt->log.logflags & NF_LOG_TCPOPT)
				printf("%soptions", delim);
		}
		if (stmt->log.logflags & NF_LOG_IPOPT)
			printf(" flags ip options");
		if (stmt->log.logflags & NF_LOG_UID)
			printf(" flags skuid");
		if (stmt->log.logflags & NF_LOG_MACDECODE)
			printf(" flags ether");
	}
}

static void log_stmt_destroy(struct stmt *stmt)
{
	xfree(stmt->log.prefix);
}

static const struct stmt_ops log_stmt_ops = {
	.type		= STMT_LOG,
	.name		= "log",
	.print		= log_stmt_print,
	.destroy	= log_stmt_destroy,
};

struct stmt *log_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &log_stmt_ops);
}

static const char *get_unit(uint64_t u)
{
	switch (u) {
	case 1: return "second";
	case 60: return "minute";
	case 60 * 60: return "hour";
	case 60 * 60 * 24: return "day";
	case 60 * 60 * 24 * 7: return "week";
	}

	return "error";
}

static const char *data_unit[] = {
	"bytes",
	"kbytes",
	"mbytes",
	NULL
};

const char *get_rate(uint64_t byte_rate, uint64_t *rate)
{
	uint64_t res, prev, rest;
	int i;

	res = prev = byte_rate;
	for (i = 0;; i++) {
		rest = res % 1024;
		res /= 1024;
		if (res <= 1 && rest != 0)
			break;
		if (data_unit[i + 1] == NULL)
			break;
		prev = res;
	}
	*rate = prev;
	return data_unit[i];
}

static void limit_stmt_print(const struct stmt *stmt)
{
	bool inv = stmt->limit.flags & NFT_LIMIT_F_INV;
	const char *data_unit;
	uint64_t rate;

	switch (stmt->limit.type) {
	case NFT_LIMIT_PKTS:
		printf("limit rate %s%" PRIu64 "/%s",
		       inv ? "over " : "", stmt->limit.rate,
		       get_unit(stmt->limit.unit));
		if (stmt->limit.burst > 0)
			printf(" burst %u packets", stmt->limit.burst);
		break;
	case NFT_LIMIT_PKT_BYTES:
		data_unit = get_rate(stmt->limit.rate, &rate);

		printf("limit rate %s%" PRIu64 " %s/%s",
		       inv ? "over " : "", rate, data_unit,
		       get_unit(stmt->limit.unit));
		if (stmt->limit.burst > 0) {
			uint64_t burst;

			data_unit = get_rate(stmt->limit.burst, &burst);
			printf(" burst %"PRIu64" %s", burst, data_unit);
		}
		break;
	}
}

static const struct stmt_ops limit_stmt_ops = {
	.type		= STMT_LIMIT,
	.name		= "limit",
	.print		= limit_stmt_print,
};

struct stmt *limit_stmt_alloc(const struct location *loc)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &limit_stmt_ops);
	stmt->flags |= STMT_F_STATEFUL;
	return stmt;
}

static void queue_stmt_print(const struct stmt *stmt)
{
	const char *delim = " ";

	printf("queue");
	if (stmt->queue.queue != NULL) {
		printf(" num ");
		expr_print(stmt->queue.queue);
	}
	if (stmt->queue.flags & NFT_QUEUE_FLAG_BYPASS) {
		printf("%sbypass", delim);
		delim = ",";
	}
	if (stmt->queue.flags & NFT_QUEUE_FLAG_CPU_FANOUT)
		printf("%sfanout", delim);

}

static const struct stmt_ops queue_stmt_ops = {
	.type		= STMT_QUEUE,
	.name		= "queue",
	.print		= queue_stmt_print,
};

struct stmt *queue_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &queue_stmt_ops);
}

static void quota_stmt_print(const struct stmt *stmt)
{
	bool inv = stmt->quota.flags & NFT_QUOTA_F_INV;
	const char *data_unit;
	uint64_t bytes, used;

	data_unit = get_rate(stmt->quota.bytes, &bytes);
	printf("quota %s%"PRIu64" %s",
	       inv ? "over " : "", bytes, data_unit);

	if (stmt->quota.used) {
		data_unit = get_rate(stmt->quota.used, &used);
		printf(" used %"PRIu64" %s", used, data_unit);
	}
}

static const struct stmt_ops quota_stmt_ops = {
	.type		= STMT_QUOTA,
	.name		= "quota",
	.print		= quota_stmt_print,
};

struct stmt *quota_stmt_alloc(const struct location *loc)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &quota_stmt_ops);
	stmt->flags |= STMT_F_STATEFUL;
	return stmt;
}

static void reject_stmt_print(const struct stmt *stmt)
{
	printf("reject");
	switch (stmt->reject.type) {
	case NFT_REJECT_TCP_RST:
		printf(" with tcp reset");
		break;
	case NFT_REJECT_ICMPX_UNREACH:
		if (stmt->reject.icmp_code == NFT_REJECT_ICMPX_PORT_UNREACH)
			break;
		printf(" with icmpx type ");
		expr_print(stmt->reject.expr);
		break;
	case NFT_REJECT_ICMP_UNREACH:
		switch (stmt->reject.family) {
		case NFPROTO_IPV4:
			if (stmt->reject.icmp_code == ICMP_PORT_UNREACH)
				break;
			printf(" with icmp type ");
			expr_print(stmt->reject.expr);
			break;
		case NFPROTO_IPV6:
			if (stmt->reject.icmp_code == ICMP6_DST_UNREACH_NOPORT)
				break;
			printf(" with icmpv6 type ");
			expr_print(stmt->reject.expr);
			break;
		}
		break;
	}
}

static const struct stmt_ops reject_stmt_ops = {
	.type		= STMT_REJECT,
	.name		= "reject",
	.print		= reject_stmt_print,
};

struct stmt *reject_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &reject_stmt_ops);
}

static void print_nf_nat_flags(uint32_t flags)
{
	const char *delim = " ";

	if (flags == 0)
		return;

	if (flags & NF_NAT_RANGE_PROTO_RANDOM) {
		printf("%srandom", delim);
		delim = ",";
	}

	if (flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY) {
		printf("%sfully-random", delim);
		delim = ",";
	}

	if (flags & NF_NAT_RANGE_PERSISTENT)
		printf("%spersistent", delim);
}

static void nat_stmt_print(const struct stmt *stmt)
{
	static const char *nat_types[] = {
		[NFT_NAT_SNAT]	= "snat",
		[NFT_NAT_DNAT]	= "dnat",
	};

	printf("%s to ", nat_types[stmt->nat.type]);
	if (stmt->nat.addr) {
		if (stmt->nat.proto) {
			if (stmt->nat.addr->ops->type == EXPR_VALUE &&
			    stmt->nat.addr->dtype->type == TYPE_IP6ADDR) {
				printf("[");
				expr_print(stmt->nat.addr);
				printf("]");
			} else if (stmt->nat.addr->ops->type == EXPR_RANGE &&
				   stmt->nat.addr->left->dtype->type == TYPE_IP6ADDR) {
				printf("[");
				expr_print(stmt->nat.addr->left);
				printf("]-[");
				expr_print(stmt->nat.addr->right);
				printf("]");
			}
		} else {
			expr_print(stmt->nat.addr);
		}
	}

	if (stmt->nat.proto) {
		printf(":");
		expr_print(stmt->nat.proto);
	}

	print_nf_nat_flags(stmt->nat.flags);
}

static void nat_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->nat.addr);
	expr_free(stmt->nat.proto);
}

static const struct stmt_ops nat_stmt_ops = {
	.type		= STMT_NAT,
	.name		= "nat",
	.print		= nat_stmt_print,
	.destroy	= nat_stmt_destroy,
};

struct stmt *nat_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &nat_stmt_ops);
}

static void masq_stmt_print(const struct stmt *stmt)
{
	printf("masquerade");

	if (stmt->masq.proto) {
		printf(" to :");
		expr_print(stmt->masq.proto);
	}

	print_nf_nat_flags(stmt->masq.flags);
}

static void masq_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->masq.proto);
}

static const struct stmt_ops masq_stmt_ops = {
	.type		= STMT_MASQ,
	.name		= "masq",
	.print		= masq_stmt_print,
	.destroy	= masq_stmt_destroy,
};

struct stmt *masq_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &masq_stmt_ops);
}

static void redir_stmt_print(const struct stmt *stmt)
{
	printf("redirect");

	if (stmt->redir.proto) {
		printf(" to :");
		expr_print(stmt->redir.proto);
	}

	print_nf_nat_flags(stmt->redir.flags);
}

static void redir_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->redir.proto);
}

static const struct stmt_ops redir_stmt_ops = {
	.type		= STMT_REDIR,
	.name		= "redir",
	.print		= redir_stmt_print,
	.destroy	= redir_stmt_destroy,
};

struct stmt *redir_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &redir_stmt_ops);
}

static const char * const set_stmt_op_names[] = {
	[NFT_DYNSET_OP_ADD]	= "add",
	[NFT_DYNSET_OP_UPDATE]	= "update",
};

static void set_stmt_print(const struct stmt *stmt)
{
	printf("set %s ", set_stmt_op_names[stmt->set.op]);
	expr_print(stmt->set.key);
	printf(" ");
	expr_print(stmt->set.set);
}

static void set_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->set.key);
	expr_free(stmt->set.set);
}

static const struct stmt_ops set_stmt_ops = {
	.type		= STMT_SET,
	.name		= "set",
	.print		= set_stmt_print,
	.destroy	= set_stmt_destroy,
};

struct stmt *set_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &set_stmt_ops);
}

static void dup_stmt_print(const struct stmt *stmt)
{
	printf("dup");
	if (stmt->dup.to != NULL) {
		printf(" to ");
		expr_print(stmt->dup.to);

		if (stmt->dup.dev != NULL) {
			printf(" device ");
			expr_print(stmt->dup.dev);
		}
	}
}

static void dup_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->dup.to);
	expr_free(stmt->dup.dev);
}

static const struct stmt_ops dup_stmt_ops = {
	.type		= STMT_DUP,
	.name		= "dup",
	.print		= dup_stmt_print,
	.destroy	= dup_stmt_destroy,
};

struct stmt *dup_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &dup_stmt_ops);
}

static void fwd_stmt_print(const struct stmt *stmt)
{
	printf("fwd to ");
	expr_print(stmt->fwd.to);
}

static void fwd_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->fwd.to);
}

static const struct stmt_ops fwd_stmt_ops = {
	.type		= STMT_FWD,
	.name		= "fwd",
	.print		= fwd_stmt_print,
	.destroy	= fwd_stmt_destroy,
};

struct stmt *fwd_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &fwd_stmt_ops);
}

static void xt_stmt_print(const struct stmt *stmt)
{
	xt_stmt_xlate(stmt);
}

static void xt_stmt_destroy(struct stmt *stmt)
{
	xfree(stmt->xt.name);
	xfree(stmt->xt.opts);
	xt_stmt_release(stmt);
}

static const struct stmt_ops xt_stmt_ops = {
	.type		= STMT_XT,
	.name		= "xt",
	.print		= xt_stmt_print,
	.destroy	= xt_stmt_destroy,
};

struct stmt *xt_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &xt_stmt_ops);
}
