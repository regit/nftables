/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>

#include <nftables.h>
#include <nftables/nftables.h>
#include <utils.h>
#include <parser.h>
#include <rule.h>
#include <netlink.h>
#include <erec.h>
#include <mnl.h>
#include <iface.h>
#include <cli.h>

unsigned int max_errors = 10;
#ifdef DEBUG
unsigned int debug_level;
#endif

static unsigned int num_include_paths = 1;

enum opt_vals {
	OPT_HELP		= 'h',
	OPT_VERSION		= 'v',
	OPT_CHECK		= 'c',
	OPT_FILE		= 'f',
	OPT_INTERACTIVE		= 'i',
	OPT_INCLUDEPATH		= 'I',
	OPT_NUMERIC		= 'n',
	OPT_STATELESS		= 's',
	OPT_IP2NAME		= 'N',
	OPT_DEBUG		= 'd',
	OPT_HANDLE_OUTPUT	= 'a',
	OPT_ECHO		= 'e',
	OPT_INVALID		= '?',
};

#define OPTSTRING	"hvcf:iI:vnsNae"

static const struct option options[] = {
	{
		.name		= "help",
		.val		= OPT_HELP,
	},
	{
		.name		= "version",
		.val		= OPT_VERSION,
	},
	{
		.name		= "check",
		.val		= OPT_CHECK,
	},
	{
		.name		= "file",
		.val		= OPT_FILE,
		.has_arg	= 1,
	},
	{
		.name		= "interactive",
		.val		= OPT_INTERACTIVE,
	},
	{
		.name		= "numeric",
		.val		= OPT_NUMERIC,
	},
	{
		.name		= "stateless",
		.val		= OPT_STATELESS,
	},
	{
		.name		= "reversedns",
		.val		= OPT_IP2NAME,
	},
	{
		.name		= "includepath",
		.val		= OPT_INCLUDEPATH,
		.has_arg	= 1,
	},
#ifdef DEBUG
	{
		.name		= "debug",
		.val		= OPT_DEBUG,
		.has_arg	= 1,
	},
#endif
	{
		.name		= "handle",
		.val		= OPT_HANDLE_OUTPUT,
	},
	{
		.name		= "echo",
		.val		= OPT_ECHO,
	},
	{
		.name		= NULL
	}
};

static void show_help(const char *name)
{
	printf(
"Usage: %s [ options ] [ cmds... ]\n"
"\n"
"Options:\n"
"  -h, --help			Show this help\n"
"  -v, --version			Show version information\n"
"\n"
"  -c, --check			Check commands validity without actually applying the changes.\n"
"  -f, --file <filename>		Read input from <filename>\n"
"  -i, --interactive		Read input from interactive CLI\n"
"\n"
"  -n, --numeric			When specified once, show network addresses numerically (default behaviour).\n"
"  				Specify twice to also show Internet services (port numbers) numerically.\n"
"				Specify three times to also show protocols, user IDs, and group IDs numerically.\n"
"  -s, --stateless		Omit stateful information of ruleset.\n"
"  -N				Translate IP addresses to names.\n"
"  -a, --handle			Output rule handle.\n"
"  -e, --echo			Echo what has been added, inserted or replaced.\n"
"  -I, --includepath <directory>	Add <directory> to the paths searched for include files. Default is: %s\n"
#ifdef DEBUG
"  --debug <level [,level...]>	Specify debugging level (scanner, parser, eval, netlink, mnl, proto-ctx, segtree, all)\n"
#endif
"\n",
	name, DEFAULT_INCLUDE_PATH);
}

#ifdef DEBUG
static const struct {
	const char		*name;
	enum debug_level	level;
} debug_param[] = {
	{
		.name		= "scanner",
		.level		= DEBUG_SCANNER,
	},
	{
		.name		= "parser",
		.level		= DEBUG_PARSER,
	},
	{
		.name		= "eval",
		.level		= DEBUG_EVALUATION,
	},
	{
		.name		= "netlink",
		.level		= DEBUG_NETLINK,
	},
	{
		.name		= "mnl",
		.level		= DEBUG_MNL,
	},
	{
		.name		= "proto-ctx",
		.level		= DEBUG_PROTO_CTX,
	},
	{
		.name		= "segtree",
		.level		= DEBUG_SEGTREE,
	},
	{
		.name		= "all",
		.level		= ~0,
	},
};
#endif

int main(int argc, char * const *argv)
{
	struct parser_state state;
	struct nft_cache cache;
	LIST_HEAD(msgs);
	char *buf = NULL, *filename = NULL;
	unsigned int len;
	bool interactive = false;
	int i, val, rc = NFT_EXIT_SUCCESS;
	struct nft_ctx *nft;

	memset(&cache, 0, sizeof(cache));
	init_list_head(&cache.list);

	nft_global_init();
	nft = nft_context_new();
	while (1) {
		val = getopt_long(argc, argv, OPTSTRING, options, NULL);
		if (val == -1)
			break;

		switch (val) {
		case OPT_HELP:
			show_help(argv[0]);
			exit(NFT_EXIT_SUCCESS);
		case OPT_VERSION:
			printf("%s v%s (%s)\n",
			       PACKAGE_NAME, PACKAGE_VERSION, RELEASE_NAME);
			exit(NFT_EXIT_SUCCESS);
		case OPT_CHECK:
			nft->check = true;
			break;
		case OPT_FILE:
			filename = optarg;
			break;
		case OPT_INTERACTIVE:
			interactive = true;
			break;
		case OPT_INCLUDEPATH:
			if (num_include_paths >= INCLUDE_PATHS_MAX) {
				fprintf(stderr, "Too many include paths "
						"specified, max. %u\n",
					INCLUDE_PATHS_MAX - 1);
				exit(NFT_EXIT_FAILURE);
			}
			include_paths[num_include_paths++] = optarg;
			break;
		case OPT_NUMERIC:
			if (++nft->output.numeric > NUMERIC_ALL) {
				fprintf(stderr, "Too many numeric options "
						"used, max. %u\n",
					NUMERIC_ALL);
				exit(NFT_EXIT_FAILURE);
			}
			break;
		case OPT_STATELESS:
			nft->output.stateless++;
			break;
		case OPT_IP2NAME:
			nft->output.ip2name++;
			break;
#ifdef DEBUG
		case OPT_DEBUG:
			for (;;) {
				unsigned int i;
				char *end;

				end = strchr(optarg, ',');
				if (end)
					*end = '\0';

				for (i = 0; i < array_size(debug_param); i++) {
					if (strcmp(debug_param[i].name, optarg))
						continue;
					debug_level |= debug_param[i].level;
					break;
				}

				if (i == array_size(debug_param)) {
					fprintf(stderr, "invalid debug parameter `%s'\n",
						optarg);
					exit(NFT_EXIT_FAILURE);
				}

				if (end == NULL)
					break;
				optarg = end + 1;
			}
			break;
#endif
		case OPT_HANDLE_OUTPUT:
			nft->output.handle++;
			break;
		case OPT_ECHO:
			nft->output.echo++;
			break;
		case OPT_INVALID:
			exit(NFT_EXIT_FAILURE);
		}
	}

	if (optind != argc) {
		for (len = 0, i = optind; i < argc; i++)
			len += strlen(argv[i]) + strlen(" ");

		buf = xzalloc(len + 2);
		for (i = optind; i < argc; i++) {
			strcat(buf, argv[i]);
			if (i + 1 < argc)
				strcat(buf, " ");
		}
		strcat(buf, "\n");
		rc = nft_run_command_from_buffer(nft, &cache, buf, len + 2);
		if (rc < 0)
			return rc;
		goto out;
	} else if (filename != NULL) {
		rc = nft_run_command_from_filename(nft, &cache, filename);
		if (rc < 0)
			return rc;
		goto out;
	} else if (interactive) {
		if (cli_init(nft, nft->nf_sock, &cache, &state) < 0) {
			fprintf(stderr, "%s: interactive CLI not supported in this build\n",
				argv[0]);
			exit(NFT_EXIT_FAILURE);
		}
		return 0;
	} else {
		fprintf(stderr, "%s: no command specified\n", argv[0]);
		exit(NFT_EXIT_FAILURE);
	}

out:
	xfree(buf);
	cache_release(&cache);
	iface_cache_release();
	nft_context_free(nft);
	nft_global_deinit();

	return rc;
}
