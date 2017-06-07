/*
 * Copyright (c) 2007-2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

%{

#include <dirent.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <sys/stat.h>

#include <nftables.h>
#include <erec.h>
#include <rule.h>
#include <parser.h>
#include "parser_bison.h"

#define YY_NO_INPUT

/*
 * Work around flex behaviour when reaching the end of buffer: normally, flex
 * regexes are greedy, when reaching the end of buffer however it tries to
 * match whatever is left in the buffer and only backs up in case it doesn't
 * match *any* pattern. Since we accept unquoted strings, this means any partial
 * token will be recognized as string.
 *
 * Make sure to only pass input to flex linewise to avoid this.
 */
#define YY_INPUT(buf,result,max_size)						\
{										\
	long n = 0;								\
	errno = 0;								\
	while ((result = fread(buf, 1, max_size, yyin)) == 0 &&			\
		ferror(yyin)) {							\
		if (errno != EINTR) {						\
			YY_FATAL_ERROR("input in flex scanner failed");		\
			break;							\
		}								\
		errno = 0;							\
		clearerr(yyin);							\
	}									\
	if (result > 1) {							\
		while (result > 1 && 						\
		       (buf[result - 1] != '\n' &&  buf[result - 1] != ' '))	\
			result--, n++;						\
		result--, n++;							\
		fseek(yyin, -n, SEEK_CUR);					\
	}									\
}

static void scanner_pop_buffer(yyscan_t scanner);


static void init_pos(struct parser_state *state)
{
	state->indesc->lineno		= 1;
	state->indesc->column		= 1;
	state->indesc->token_offset	= 0;
	state->indesc->line_offset 	= 0;
}

static void update_pos(struct parser_state *state, struct location *loc,
		       int len)
{
	loc->indesc			= state->indesc;
	loc->first_line			= state->indesc->lineno;
	loc->last_line			= state->indesc->lineno;
	loc->first_column		= state->indesc->column;
	loc->last_column		= state->indesc->column + len - 1;
	state->indesc->column		+= len;
}

static void update_offset(struct parser_state *state, struct location *loc,
			  unsigned int len)
{
	state->indesc->token_offset	+= len;
	loc->token_offset		= state->indesc->token_offset;
	loc->line_offset		= state->indesc->line_offset;
}

static void reset_pos(struct parser_state *state, struct location *loc)
{
	state->indesc->line_offset	= state->indesc->token_offset;
	state->indesc->lineno		+= 1;
	state->indesc->column		= 1;
}

#define YY_USER_ACTION {					\
	update_pos(yyget_extra(yyscanner), yylloc, yyleng);	\
	update_offset(yyget_extra(yyscanner), yylloc, yyleng);	\
}

/* avoid warnings with -Wmissing-prototypes */
extern int	yyget_column(yyscan_t);
extern void	yyset_column(int, yyscan_t);

%}

space		[ ]
tab		\t
newline		\n
digit		[0-9]
hexdigit	[0-9a-fA-F]
decstring	{digit}+
hexstring	0[xX]{hexdigit}+
letter		[a-zA-Z]
string		({letter}|[_.])({letter}|{digit}|[/\-_\.])*
quotedstring	\"[^"]*\"
asteriskstring	({string}\*|{string}\\\*)
comment		#.*$
slash		\/

timestring	([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?

hex4		([[:xdigit:]]{1,4})
v680		(({hex4}:){7}{hex4})
v670		((:)((:{hex4}){7}))
v671		((({hex4}:){1})((:{hex4}){6}))
v672		((({hex4}:){2})((:{hex4}){5}))
v673		((({hex4}:){3})((:{hex4}){4}))
v674		((({hex4}:){4})((:{hex4}){3}))
v675		((({hex4}:){5})((:{hex4}){2}))
v676		((({hex4}:){6})(:{hex4}{1}))
v677		((({hex4}:){7})(:))
v67		({v670}|{v671}|{v672}|{v673}|{v674}|{v675}|{v676}|{v677})
v660		((:)((:{hex4}){6}))
v661		((({hex4}:){1})((:{hex4}){5}))
v662		((({hex4}:){2})((:{hex4}){4}))
v663		((({hex4}:){3})((:{hex4}){3}))
v664		((({hex4}:){4})((:{hex4}){2}))
v665		((({hex4}:){5})((:{hex4}){1}))
v666		((({hex4}:){6})(:))
v66		({v660}|{v661}|{v662}|{v663}|{v664}|{v665}|{v666})
v650		((:)((:{hex4}){5}))
v651		((({hex4}:){1})((:{hex4}){4}))
v652		((({hex4}:){2})((:{hex4}){3}))
v653		((({hex4}:){3})((:{hex4}){2}))
v654		((({hex4}:){4})(:{hex4}{1}))
v655		((({hex4}:){5})(:))
v65		({v650}|{v651}|{v652}|{v653}|{v654}|{v655})
v640		((:)((:{hex4}){4}))
v641		((({hex4}:){1})((:{hex4}){3}))
v642		((({hex4}:){2})((:{hex4}){2}))
v643		((({hex4}:){3})((:{hex4}){1}))
v644		((({hex4}:){4})(:))
v64		({v640}|{v641}|{v642}|{v643}|{v644})
v630		((:)((:{hex4}){3}))
v631		((({hex4}:){1})((:{hex4}){2}))
v632		((({hex4}:){2})((:{hex4}){1}))
v633		((({hex4}:){3})(:))
v63		({v630}|{v631}|{v632}|{v633})
v620		((:)((:{hex4}){2}))
v621		((({hex4}:){1})((:{hex4}){1}))
v622		((({hex4}:){2})(:))
v62		({v620}|{v621}|{v622})
v610		((:)(:{hex4}{1}))
v611		((({hex4}:){1})(:))
v61		({v610}|{v611})
v60		(::)

macaddr		(([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2})
ip4addr		(([[:digit:]]{1,3}"."){3}([[:digit:]]{1,3}))
ip6addr		({v680}|{v67}|{v66}|{v65}|{v64}|{v63}|{v62}|{v61}|{v60})
ip6addr_rfc2732	(\[{ip6addr}\])

classid		({hexdigit}{1,4}:{hexdigit}{1,4})
addrstring	({macaddr}|{ip4addr}|{ip6addr})

%option prefix="nft_"
%option outfile="lex.yy.c"
%option reentrant
%option noyywrap
%option nounput
%option bison-bridge
%option bison-locations
%option debug
%option yylineno
%option nodefault
%option warn

%%

"=="			{ return EQ; }
"eq"			{ return EQ; }
"!="			{ return NEQ; }
"ne"			{ return NEQ; }
"<="			{ return LTE; }
"le"			{ return LTE; }
"<"			{ return LT; }
"lt"			{ return LT; }
">="			{ return GTE; }
"ge"			{ return GTE; }
">"			{ return GT; }
"gt"			{ return GT; }
","			{ return COMMA; }
"."			{ return DOT; }
":"			{ return COLON; }
";"			{ return SEMICOLON; }
"{"			{ return '{'; }
"}"			{ return '}'; }
"["			{ return '['; }
"]"			{ return ']'; }
"("			{ return '('; }
")"			{ return ')'; }
"<<"			{ return LSHIFT; }
"lshift"		{ return LSHIFT; }
">>"			{ return RSHIFT; }
"rshift"		{ return RSHIFT; }
"^"			{ return CARET; }
"xor"			{ return CARET; }
"&"			{ return AMPERSAND; }
"and"			{ return AMPERSAND; }
"|"			{ return '|'; }
"or"			{ return '|'; }
"!"			{ return NOT; }
"not"			{ return NOT; }
"/"			{ return SLASH; }
"-"			{ return DASH; }
"*"			{ return ASTERISK; }
"@"			{ return AT; }
"$"			{ return '$'; }
"="			{ return '='; }
"vmap"			{ return VMAP; }

"include"		{ return INCLUDE; }
"define"		{ return DEFINE; }

"describe"		{ return DESCRIBE; }

"hook"			{ return HOOK; }
"device"		{ return DEVICE; }
"table"			{ return TABLE; }
"tables"		{ return TABLES; }
"chain"			{ return CHAIN; }
"chains"		{ return CHAINS; }
"rule"			{ return RULE; }
"rules"			{ return RULES; }
"sets"			{ return SETS; }
"set"			{ return SET; }
"element"		{ return ELEMENT; }
"map"			{ return MAP; }
"maps"			{ return MAPS; }
"handle"		{ return HANDLE; }
"ruleset"		{ return RULESET; }

"accept"		{ return ACCEPT; }
"drop"			{ return DROP; }
"continue"		{ return CONTINUE; }
"jump"			{ return JUMP; }
"goto"			{ return GOTO; }
"return"		{ return RETURN; }
"to"			{ return TO; }

"inet"			{ return INET; }
"netdev"		{ return NETDEV; }

"add"			{ return ADD; }
"replace"		{ return REPLACE; }
"update"		{ return UPDATE; }
"create"		{ return CREATE; }
"insert"		{ return INSERT; }
"delete"		{ return DELETE; }
"list"			{ return LIST; }
"reset"			{ return RESET; }
"flush"			{ return FLUSH; }
"rename"		{ return RENAME; }
"export"		{ return EXPORT; }
"monitor"		{ return MONITOR; }

"position"		{ return POSITION; }
"comment"		{ return COMMENT; }

"constant"		{ return CONSTANT; }
"interval"		{ return INTERVAL; }
"timeout"		{ return TIMEOUT; }
"gc-interval"		{ return GC_INTERVAL; }
"elements"		{ return ELEMENTS; }

"policy"		{ return POLICY; }
"size"			{ return SIZE; }
"performance"		{ return PERFORMANCE; }
"memory"		{ return MEMORY; }

"flow"			{ return FLOW; }

"counter"		{ return COUNTER; }
"name"			{ return NAME; }
"packets"		{ return PACKETS; }
"bytes"			{ return BYTES; }
"avgpkt"		{ return AVGPKT; }

"counters"		{ return COUNTERS; }
"quotas"		{ return QUOTAS; }

"log"			{ return LOG; }
"prefix"		{ return PREFIX; }
"group"			{ return GROUP; }
"snaplen"		{ return SNAPLEN; }
"queue-threshold"	{ return QUEUE_THRESHOLD; }
"level"			{ return LEVEL; }

"queue"			{ return QUEUE;}
"num"			{ return QUEUENUM;}
"bypass"		{ return BYPASS;}
"fanout"		{ return FANOUT;}

"limit"			{ return LIMIT; }
"rate"			{ return RATE; }
"burst"			{ return BURST; }
"until"			{ return UNTIL; }
"over"			{ return OVER; }

"quota"			{ return QUOTA; }
"used"			{ return USED; }

"nanosecond"		{ return NANOSECOND; }
"microsecond"		{ return MICROSECOND; }
"millisecond"		{ return MILLISECOND; }
"second"		{ return SECOND; }
"minute"		{ return MINUTE; }
"hour"			{ return HOUR; }
"day"			{ return DAY; }
"week"			{ return WEEK; }

"reject"		{ return _REJECT; }
"with"			{ return WITH; }
"icmpx"			{ return ICMPX; }

"snat"			{ return SNAT; }
"dnat"			{ return DNAT; }
"masquerade"		{ return MASQUERADE; }
"redirect"		{ return REDIRECT; }
"random"		{ return RANDOM; }
"fully-random"		{ return FULLY_RANDOM; }
"persistent"		{ return PERSISTENT; }

"ll"			{ return LL_HDR; }
"nh"			{ return NETWORK_HDR; }
"th"			{ return TRANSPORT_HDR; }

"bridge"		{ return BRIDGE; }

"ether"			{ return ETHER; }
"saddr"			{ return SADDR; }
"daddr"			{ return DADDR; }
"type"			{ return TYPE; }

"vlan"			{ return VLAN; }
"id"			{ return ID; }
"cfi"			{ return CFI; }
"pcp"			{ return PCP; }

"arp"			{ return ARP; }
"htype"			{ return HTYPE; }
"ptype"			{ return PTYPE; }
"hlen"			{ return HLEN; }
"plen"			{ return PLEN; }
"operation"		{ return OPERATION; }

"ip"			{ return IP; }
"version"		{ return HDRVERSION; }
"hdrlength"		{ return HDRLENGTH; }
"dscp"			{ return DSCP; }
"ecn"			{ return ECN; }
"length"		{ return LENGTH; }
"frag-off"		{ return FRAG_OFF; }
"ttl"			{ return TTL; }
"protocol"		{ return PROTOCOL; }
"checksum"		{ return CHECKSUM; }

"echo"			{ return ECHO; }
"eol"			{ return EOL; }
"maxseg"		{ return MAXSEG; }
"noop"			{ return NOOP; }
"sack"			{ return SACK; }
"sack0"			{ return SACK0; }
"sack1"			{ return SACK1; }
"sack2"			{ return SACK2; }
"sack3"			{ return SACK3; }
"sack-permitted"	{ return SACK_PERMITTED; }
"timestamp"		{ return TIMESTAMP; }

"kind"			{ return KIND; }
"count"			{ return COUNT; }
"left"			{ return LEFT; }
"right"			{ return RIGHT; }
"tsval"			{ return TSVAL; }
"tsecr"			{ return TSECR; }

"icmp"			{ return ICMP; }
"code"			{ return CODE; }
"sequence"		{ return SEQUENCE; }
"gateway"		{ return GATEWAY; }
"mtu"			{ return MTU; }

"ip6"			{ return IP6; }
"priority"		{ return PRIORITY; }
"flowlabel"		{ return FLOWLABEL; }
"nexthdr"		{ return NEXTHDR; }
"hoplimit"		{ return HOPLIMIT; }

"icmpv6"		{ return ICMP6; }
"param-problem"		{ return PPTR; }
"max-delay"		{ return MAXDELAY; }

"ah"			{ return AH; }
"reserved"		{ return RESERVED; }
"spi"			{ return SPI; }

"esp"			{ return ESP; }

"comp"			{ return COMP; }
"flags"			{ return FLAGS; }
"cpi"			{ return CPI; }

"udp"			{ return UDP; }
"udplite"		{ return UDPLITE; }
"sport"			{ return SPORT; }
"dport"			{ return DPORT; }

"tcp"			{ return TCP; }
"ackseq"		{ return ACKSEQ; }
"doff"			{ return DOFF; }
"window"		{ return WINDOW; }
"urgptr"		{ return URGPTR; }
"option"		{ return OPTION; }

"dccp"			{ return DCCP; }

"sctp"			{ return SCTP; }
"vtag"			{ return VTAG; }

"rt"			{ return RT; }
"rt0"			{ return RT0; }
"rt2"			{ return RT2; }
"seg-left"		{ return SEG_LEFT; }
"addr"			{ return ADDR; }

"hbh"			{ return HBH; }

"frag"			{ return FRAG; }
"reserved2"		{ return RESERVED2; }
"more-fragments"	{ return MORE_FRAGMENTS; }

"dst"			{ return DST; }

"mh"			{ return MH; }

"meta"			{ return META; }
"mark"			{ return MARK; }
"iif"			{ return IIF; }
"iifname"		{ return IIFNAME; }
"iiftype"		{ return IIFTYPE; }
"oif"			{ return OIF; }
"oifname"		{ return OIFNAME; }
"oiftype"		{ return OIFTYPE; }
"skuid"			{ return SKUID; }
"skgid"			{ return SKGID; }
"nftrace"		{ return NFTRACE; }
"rtclassid"		{ return RTCLASSID; }
"ibriport"		{ return IBRIPORT; }
"obriport"		{ return OBRIPORT; }
"pkttype"		{ return PKTTYPE; }
"cpu"			{ return CPU; }
"iifgroup"		{ return IIFGROUP; }
"oifgroup"		{ return OIFGROUP; }
"cgroup"		{ return CGROUP; }

"classid"		{ return CLASSID; }
"nexthop"		{ return NEXTHOP; }

"ct"			{ return CT; }
"l3proto"		{ return L3PROTOCOL; }
"proto-src"		{ return PROTO_SRC; }
"proto-dst"		{ return PROTO_DST; }
"zone"			{ return ZONE; }

"numgen"		{ return NUMGEN; }
"inc"			{ return INC; }
"mod"			{ return MOD; }
"offset"		{ return OFFSET; }

"jhash"			{ return JHASH; }
"symhash"		{ return SYMHASH; }
"seed"			{ return SEED; }

"dup"			{ return DUP; }
"fwd"			{ return FWD; }

"fib"			{ return FIB; }

"notrack"		{ return NOTRACK; }

"options"		{ return OPTIONS; }
"all"			{ return ALL; }

"xml"			{ return XML; }
"json"			{ return JSON; }

"exists"		{ return EXISTS; }
"missing"		{ return MISSING; }

"exthdr"		{ return EXTHDR; }

{addrstring}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

{ip6addr_rfc2732}	{
				yytext[yyleng - 1] = '\0';
				yylval->string = xstrdup(yytext + 1);
				return STRING;
			}

{timestring}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

{decstring}		{
				errno = 0;
				yylval->val = strtoull(yytext, NULL, 0);
				if (errno != 0) {
					yylval->string = xstrdup(yytext);
					return STRING;
				}
				return NUM;
			}

{hexstring}		{
				errno = 0;
				yylval->val = strtoull(yytext, NULL, 0);
				if (errno != 0) {
					yylval->string = xstrdup(yytext);
					return STRING;
				}
				return NUM;
			}

{classid}/[ \t\n:\-},]	{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

{quotedstring}		{
				yytext[yyleng - 1] = '\0';
				yylval->string = xstrdup(yytext + 1);
				return QUOTED_STRING;
			}

{asteriskstring}	{
				yylval->string = xstrdup(yytext);
				return ASTERISK_STRING;
			}

{string}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

\\{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
			}

{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
				return NEWLINE;
			}

{tab}			{
				/*
				 * Compensate difference between visible length
				 * and real length.
				 */
				struct parser_state *state = yyget_extra(yyscanner);
				unsigned int diff;

				diff = TABSIZE - strlen("\t");
				diff -= (state->indesc->column -
					 strlen("\t") - 1) % TABSIZE;

				update_pos(state, yylloc, diff);
			}

{space}+
{comment}

<<EOF>> 		{
				update_pos(yyget_extra(yyscanner), yylloc, 1);
				scanner_pop_buffer(yyscanner);
				if (YY_CURRENT_BUFFER == NULL)
					return TOKEN_EOF;
			}

.			{ return JUNK; }

%%

static void scanner_pop_buffer(yyscan_t scanner)
{
	struct parser_state *state = yyget_extra(scanner);

	yypop_buffer_state(scanner);
	state->indesc = &state->indescs[--state->indesc_idx - 1];
}

static struct error_record *scanner_push_file(void *scanner, const char *filename,
					      FILE *f, const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	YY_BUFFER_STATE b;

	if (state->indesc_idx == MAX_INCLUDE_DEPTH) {
		fclose(f);
		return error(loc, "Include nested too deeply, max %u levels",
			     MAX_INCLUDE_DEPTH);
	}

	b = yy_create_buffer(f, YY_BUF_SIZE, scanner);
	yypush_buffer_state(b, scanner);

	state->indesc = &state->indescs[state->indesc_idx++];
	if (loc != NULL)
		state->indesc->location = *loc;
	state->indesc->type	= INDESC_FILE;
	state->indesc->name	= xstrdup(filename);
	state->indesc->fd	= fileno(f);
	init_pos(state);
	return NULL;
}

static int include_file(void *scanner, const char *filename,
			const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct error_record *erec;
	FILE *f;

	f = fopen(filename, "r");
	if (f == NULL) {
		erec = error(loc, "Could not open file \"%s\": %s\n",
			     filename, strerror(errno));
		goto err;
	}

	erec = scanner_push_file(scanner, filename, f, loc);
	if (erec != NULL)
		goto err;
	return 0;
err:
	erec_queue(erec, state->msgs);
	return -1;
}

int scanner_read_file(void *scanner, const char *filename,
		      const struct location *loc)
{
	return include_file(scanner, filename, loc);
}

static int directoryfilter(const struct dirent *de)
{
	if (strcmp(de->d_name, ".") == 0 ||
	    strcmp(de->d_name, "..") == 0)
		return 0;

	/* Accept other filenames. If we want to enable filtering based on
	 * filename suffix (*.nft), this would be the place to do it.
	 */
	return 1;
}

static void free_scandir_des(struct dirent **des, int n_des)
{
	int i;

	for (i = 0; i < n_des; i++)
		free(des[i]);

	free(des);
}

static int include_directory(void *scanner, const char *dirname,
			     const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct dirent **des = NULL;
	struct error_record *erec;
	int ret, n_des = 0, i;
	char dirbuf[PATH_MAX];
	FILE *f;

	if (!dirname[0] || dirname[strlen(dirname)-1] != '/') {
		erec = error(loc, "Include directory name \"%s\" does not end in '/'",
			     dirname);
		goto err;
	}

	/* If the path is a directory, assume that all files there need
	 * to be included. Sort the file list in alphabetical order.
	 */
	n_des = scandir(dirname, &des, directoryfilter, alphasort);
	if (n_des < 0) {
		erec = error(loc, "Failed to scan directory contents for \"%s\"",
			     dirname);
		goto err;
	} else if (n_des == 0) {
		/* nothing to do */
		free(des);
		return 0;
	}

	/* We need to push the files in reverse order, so that they will be
	 * popped in the correct order.
	 */
	for (i = n_des - 1; i >= 0; i--) {
		ret = snprintf(dirbuf, sizeof(dirbuf), "%s/%s", dirname,
			       des[i]->d_name);
		if (ret < 0 || ret >= PATH_MAX) {
			erec = error(loc, "Too long file path \"%s/%s\"\n",
				     dirname, des[i]->d_name);
			goto err;
		}

		f = fopen(dirbuf, "r");
		if (f == NULL) {
			erec = error(loc, "Could not open file \"%s\": %s\n",
				     dirbuf, strerror(errno));
			goto err;
		}

		erec = scanner_push_file(scanner, des[i]->d_name, f, loc);
		if (erec != NULL)
			goto err;
	}
	free_scandir_des(des, n_des);
	return 0;
err:
	free_scandir_des(des, n_des);
	erec_queue(erec, state->msgs);
	return -1;
}

static int include_dentry(void *scanner, const char *filename,
			  const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct error_record *erec;
	struct stat st;
	int ret;

	ret = stat(filename, &st);
	if (ret == -1 && errno == ENOENT) {
		/* Could not find the directory or file, keep on searching.
		 * Return value '1' indicates to the caller that we should still
		 * search in the next include directory.
		 */
		return 1;
	} else if (ret == 0) {
		if (S_ISDIR(st.st_mode))
			return include_directory(scanner, filename, loc);
		else if (S_ISREG(st.st_mode))
			return include_file(scanner, filename, loc);
		else {
			errno = EINVAL;
			ret = -1;
		}
	}

	/* Process error for failed stat and cases where the file is not a
	 * directory or (a link to) a regular file.
	 */
	erec = error(loc, "Failed to access file \"%s\": %s\n",
			filename, strerror(errno));
	erec_queue(erec, state->msgs);
	return ret;
}

static bool search_in_include_path(const char *filename)
{
	return (strncmp(filename, "./", strlen("./")) != 0 &&
		strncmp(filename, "../", strlen("../")) != 0 &&
		filename[0] != '/');
}

int scanner_include_file(void *scanner, const char *filename,
			 const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct error_record *erec;
	char buf[PATH_MAX];
	unsigned int i;
	int ret;

	if (search_in_include_path(filename)) {
		for (i = 0; i < INCLUDE_PATHS_MAX; i++) {
			if (include_paths[i] == NULL)
				break;
			ret = snprintf(buf, sizeof(buf), "%s/%s",
				       include_paths[i], filename);
			if (ret < 0 || ret >= PATH_MAX) {
				erec = error(loc, "Too long file path \"%s/%s\"\n",
					     include_paths[i], filename);
				erec_queue(erec, state->msgs);
				return -1;
			}

			ret = include_dentry(scanner, buf, loc);
			if (ret == 0)
				return 0;
			else if (ret != 1)
				/* error has been processed already */
				return -1;
		}
	} else {
		ret = include_dentry(scanner, filename, loc);
		if (ret == 0)
			return 0;
		else if (ret != 1)
			return -1;
		/* else fall through to "not found" processing */
	}

	erec = error(loc, "Did not find \"%s\"\n", filename);
	erec_queue(erec, state->msgs);
	return -1;
}

void scanner_push_buffer(void *scanner, const struct input_descriptor *indesc,
			 const char *buffer)
{
	struct parser_state *state = yyget_extra(scanner);
	YY_BUFFER_STATE b;

	state->indesc = &state->indescs[state->indesc_idx++];
	memcpy(state->indesc, indesc, sizeof(*state->indesc));
	state->indesc->data = buffer;

	b = yy_scan_string(buffer, scanner);
	assert(b != NULL);
	init_pos(state);
}

void *scanner_init(struct parser_state *state)
{
	yyscan_t scanner;

	state->indesc = state->indescs;

	yylex_init(&scanner);
	yyset_extra(state, scanner),
	yyset_out(NULL, scanner);

	return scanner;
}

void scanner_destroy(struct parser_state *scanner)
{
	struct parser_state *state = yyget_extra(scanner);

	/* Can't free indesc name - locations might still be in use */
	while (state->indesc_idx--)
		yypop_buffer_state(scanner);

	yylex_destroy(scanner);
}
