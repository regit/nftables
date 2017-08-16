/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <string.h>
#include <errno.h>
#include <nftables.h>
#include <parser.h>
#include <iface.h>
#include <netlink.h>
#include <erec.h>
#include <libmnl/libmnl.h>
#include <mnl.h>
#include <netlink.h>
#include <nftables_common.h>

#include <nftables/nftables.h>

#include <unistd.h>
#include <fcntl.h>


unsigned int max_errors = 1;
unsigned int numeric_output;
unsigned int ip2name_output;
unsigned int handle_output;
#ifdef DEBUG
unsigned int debug_level;
#endif

const char *include_paths[INCLUDE_PATHS_MAX] = { DEFAULT_INCLUDE_PATH };

/**
 * Init cache structure.
 *
 * This needs to be called once by process to do the initialization
 * phase of some structures.
 */
void nft_global_init(void)
{
	mark_table_init();
	realm_table_rt_init();
	devgroup_table_init();
	realm_table_meta_init();
	ct_label_table_init();
	gmp_init();
#ifdef HAVE_LIBXTABLES
	xt_init();
#endif
}

/**
 * Deinit global structures
 *
 * To be call one before exiting the nftables tasks
 */
void nft_global_deinit(void)
{
	iface_cache_release();
	ct_label_table_exit();
	realm_table_rt_exit();
	devgroup_table_exit();
	realm_table_meta_exit();
	mark_table_exit();
}

/**
 * Set number of consecutive errors to handle
 *
 * This can be useful if you send complex command to nftables
 * and want to debug it but it causes memory leak.
 */
int nft_global_set_max_errors(unsigned int errors)
{
	max_errors = errors;
	return 0;
}

__attribute__((format(printf, 2, 0)))
static int nft_print(void *ctx, const char *fmt, ...)
{
	va_list arg;
	va_start(arg, fmt);
	vfprintf(stdout, fmt, arg);
	va_end(arg);

	return 0;
} 

/**
 * Allocate a nftables context
 *
 */
struct nft_ctx *nft_context_new(void)
{
	struct nft_ctx *ctx = NULL;
	ctx = malloc(sizeof(struct nft_ctx));
	if (ctx == NULL)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->nf_sock = netlink_open_sock();

	init_list_head(&ctx->cache.list);
	init_list_head(&ctx->output.msgs);

	ctx->output.ctx = ctx;
	ctx->output.print = nft_print;
	return ctx;
}

/** 
 * Set print function for your application
 *
 * Command such as `list ruleset` can trigger an output. This function
 * allows you to define which function should be used.
 */
void nft_context_set_print_func(struct nft_ctx *nft,
				int (*print)(void *ctx, const char *fmt, ...),
				void *ctx)
{
	if (nft) {
		nft->output.print = print;
		nft->output.ctx = ctx;
	}
}

/**
 * Free a nftables context
 */
void nft_context_free(struct nft_ctx *nft)
{
	if (nft == NULL)
		return;
	netlink_close_sock(nft->nf_sock);
	cache_release(&nft->cache);
	erec_free_list(&nft->output.msgs);
	xfree(nft);
}

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

/**
 * Get current errors and write them in provided buffer
 */
int nft_get_error(struct nft_ctx *nft, char *err_buf, size_t err_buf_len)
{
	FILE *errfile = fmemopen(err_buf, err_buf_len, "w");
	erec_print_list(errfile, &nft->output.msgs);
	fclose(errfile);
	return 0;	
}

/**
 * Run nftables command contained in provided buffer
 */
int nft_run_command_from_buffer(struct nft_ctx *nft,
				char *buf, size_t buflen)
{
	int rc = NFT_EXIT_SUCCESS;
	struct parser_state state;
	void *scanner;

	parser_init(nft->nf_sock, &nft->cache, &state, &nft->output.msgs);
	scanner = scanner_init(&state);
	scanner_push_buffer(scanner, &indesc_cmdline, buf);
		
	if (nft_run(nft, nft->nf_sock, &nft->cache, scanner,
		    &state, &nft->output.msgs) != 0)
		rc = NFT_EXIT_FAILURE;

	scanner_destroy(scanner);
	return rc;
}

/**
 * Run all nftables commands contained in a file
 */
int nft_run_command_from_filename(struct nft_ctx *nft, const char *filename)
{
	int rc = NFT_EXIT_SUCCESS;
	struct parser_state state;
	LIST_HEAD(msgs);
	void *scanner;

	rc = cache_update(nft->nf_sock, &nft->cache, CMD_INVALID, &msgs);
	if (rc < 0)
		return rc;
	parser_init(nft->nf_sock, &nft->cache, &state, &nft->output.msgs);
	scanner = scanner_init(&state);
	if (scanner_read_file(scanner, filename, &internal_location) < 0)
		return NFT_EXIT_FAILURE;
	if (nft_run(nft, nft->nf_sock, &nft->cache, scanner,
		    &state, &nft->output.msgs) != 0)
		rc = NFT_EXIT_FAILURE;

	scanner_destroy(scanner);
	return rc;
}

/**
 * Start a batch
 */
struct nft_batch *nft_batch_start(struct nft_ctx *nft)
{
	struct nft_batch *batch = malloc(sizeof(*batch));
	if (batch == NULL)
		return NULL;

	batch->batch = mnl_batch_init();
	mnl_batch_begin(batch->batch, mnl_seqnum_alloc(&nft->cache.seqnum));

	return batch;
}

/**
 * Add a command to a already created batch
 */
int nft_batch_add(struct nft_ctx *nft, struct nft_batch *batch,
		  const char * buf, size_t buflen)
{
	int rc = NFT_EXIT_SUCCESS;
	int ret = 0;
	struct parser_state state;
	void *scanner;
	struct cmd *cmd, *next;
	struct netlink_ctx *ctx = &batch->nl_ctx;
	uint32_t seqnum;
	bool batch_supported = netlink_batch_supported(nft->nf_sock, &seqnum);

	parser_init(nft->nf_sock, &nft->cache, &state, &nft->output.msgs);
	scanner = scanner_init(&state);
	scanner_push_buffer(scanner, &indesc_cmdline, buf);
		
	ret = nft_parse(scanner, &state);
	if (ret != 0 || state.nerrs > 0) {
		rc = -1;
		goto err1;
	} 

	list_for_each_entry(cmd, &state.cmds, list) {
		nft_cmd_expand(cmd);
		memset(ctx, 0, sizeof(*ctx));
		ctx->msgs = &nft->output.msgs;
		ctx->seqnum = cmd->seqnum = mnl_seqnum_alloc(&seqnum);
		ctx->batch = batch->batch;
		ctx->batch_supported = batch_supported;
		ctx->octx = &nft->output;
		ctx->nf_sock = nft->nf_sock;
		ctx->cache = &nft->cache;
		init_list_head(&ctx->list);
		ret = do_command(ctx, cmd);
		if (ret < 0)
			return -1;
	}

	list_for_each_entry_safe(cmd, next, &state.cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}
err1:
	scanner_destroy(scanner);
	return rc;
}

/**
 * Commit a batch to the kernel
 */
int nft_batch_commit(struct nft_ctx *nft, struct nft_batch *batch)
{
	int ret = 0;

	mnl_batch_end(batch->batch, mnl_seqnum_alloc(&nft->cache.seqnum));
	LIST_HEAD(err_list);

	if (!mnl_batch_ready(batch->batch))
		goto out;

	batch->nl_ctx.batch = batch->batch;
	if (!mnl_batch_ready(batch->batch))
		goto out;

	ret = netlink_batch_send(&batch->nl_ctx, &err_list);
out:
	return ret;

}

/**
 * Free ressources allocated to a batch
 */
void nft_batch_free(struct nft_batch *batch)
{
	if (batch == NULL)
		return;
	mnl_batch_reset(batch->batch);
	xfree(batch);
}
