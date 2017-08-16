/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

/**
 *  \defgroup libnftables libnftables
 *
 *  libnftables is a high level nftables library that is meant to
 *  be useful for frontend to nftables.
 *
 *  The synopsis of the library for a basic usage is the following
 *
 *  ```C
 *	// init once the library cache
 *	nft_global_init();
 *	// create the nftables context
 *	nft = nft_context_new();
 *	// now you can run nftables commands
 *	rc = nft_run_command_from_buffer(nft, CMD, sizeof(CMD));
 *	if (rc != NFT_EXIT_SUCCESS) {
 *		// use the following function to get errors
 *		nft_get_error(nft, err_buf, sizeof(err_buf));
 *		printf("%s\n", err_buf);
 *		return -1;
 *	}
 *	// once you're done with the context, free allocated ressources
 *	nft_context_free(nft);
 *	// call deinit when you will not need anymore the library
 *	nft_global_deinit();
 *  ```
 *  The library can be used to \ref run_commands "run commands" and has support
 *  for \ref batch "batched commands".
 *
 *  @{
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
 * To be called once before exiting the nftables tasks
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
 *
 * \param errors number of errors message to queue
 * \return NFT_EXIT_SUCCESS if success NFT_EXIT_FAILURE if not
 */
int nft_global_set_max_errors(unsigned int errors)
{
	max_errors = errors;
	return NFT_EXIT_SUCCESS;
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
 * \return a struct nft_ctx or NULL in case of error
 */
struct nft_ctx *nft_context_new(void)
{
	struct nft_ctx *ctx = NULL;
	ctx = calloc(1, sizeof(struct nft_ctx));
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
 *
 * \param nft a initialized struct nft_ctx
 * \param print a print function
 * \param ctx a pointer that will be passed as first argument of print function call
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
 *
 * \param nft a struct nft_ctx to be freed
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
 *
 * \return NFT_EXIT_SUCCESS if there is error, NFT_EXIT_FAILURE if no error available
 */
int nft_get_error(struct nft_ctx *nft, char *err_buf, size_t err_buf_len)
{
	FILE *errfile = fmemopen(err_buf, err_buf_len, "w");
	*err_buf = '\0';
	erec_print_list(errfile, &nft->output.msgs);
	fclose(errfile);
	if (!strlen(err_buf))
		return NFT_EXIT_FAILURE;
	return NFT_EXIT_SUCCESS;
}


/**
 * \defgroup run_commands Run nftables commands
 *
 * Once a nftables context has been initialized with nft_context_new()
 * it is possible to run nftables commands via the following
 * functions:
 * * nft_run_command_from_buffer(): run command from a buffer
 * * nft_run_command_from_filename(): run commands contained in a filename
 *
 * It is also possible to run multiple commands via \ref batch
 *
 * @{
 */

/**
 * Run nftables command contained in provided buffer
 *
 * This function accept nft command with the same syntax
 * as `nft` in interactive mode. For instance, this is a valid
 * command if your ruleset has a `filter output` chain:
 *
 * ```C
 * char ADD[] = "add rule filter output counter drop";
 * ```
 *
 * \param nft a pointer to a initialized struct nft_ctx
 * \param buf buffer containing the command to execute
 * \param buflen the length of the buffer
 * \return NFT_EXIT_SUCCESS if success NFT_EXIT_FAILURE if not
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
 *
 * This function provides away to programmatically get an equivalent
 * of the `-f` option of `nft`. For instance
 * For instance, this is a valid content for a file
 * if your ruleset has a `filter output` chain:
 *
 * ```
 *	table filter {
 *		chain output {
 *			counter drop
 *		}
 *	}
 * ```
 *
 * \param nft a pointer to a initialized struct nft_ctx
 * \param filename path to the file containing  nft rules
 * \return NFT_EXIT_SUCCESS if success NFT_EXIT_FAILURE if not
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
 * @}
 */

/**
 * \defgroup batch Batch support
 *
 * Nftables supports batch or transsaction. It is possible to prepare
 * multiple commands and then run it at once. If one of the commands fails
 * then the complete set of commands is not added to the firewall ruleset.
 *
 * libnftables support transaction and the synopsis of the usage it the
 * following:
 * * create a transaction with nft_batch_start()
 * * add command to the batch with nft_batch_add()
 * * commit the batch to kernel with nft_batch_commit()
 *
 * The following example code shows how to use it:
 *
 * ```C
 *      char ADD1[] = "add rule nat postrouting ip saddr 1.2.3.4 masquerade";
 *      char ADD2[] = "add rule filter forward ip saddr 1.2.3.4 accept";
 *	// start a batch using an existing nftables context
 *	batch = nft_batch_start(nft);
 *	// add first command to the batch
 *	if (nft_batch_add(nft, batch, ADD1, strlen(ADD1)) != NFT_EXIT_SUCCESS) {
 *		// standard error handling
 *		nft_get_error(nft, err_buf, sizeof(err_buf));
 *		printf("%s\n", err_buf);
 *		// free the batch
 *		nft_batch_free(batch);
 *		return -1;
 *	}
 *	// add second command
 *	if (nft_batch_add(nft, batch, ADD2, strlen(ADD2)) != NFT_EXIT_SUCCESS) {
 *		// error handling
 *		nft_batch_free(batch);
 *		return -1;
 *	}
 *	// send this batch of two commands to kernel and get result
 *	ret = nft_batch_commit(nft, batch);
 *	if (ret != 0) {
 *		// error handling
 *		nft_batch_free(batch);
 *		return -1;
 *	}
 * ```
 *
 *  @{
 */

/**
 * Start a batch
 *
 * \param nft a pointer to an initalized struct nft_ctx
 * \return a pointer to an allocated and initialized struct nft_batch or NULL if error
 */
struct nft_batch *nft_batch_start(struct nft_ctx *nft)
{
	uint32_t seqnum;
	bool batch_supported = netlink_batch_supported(nft->nf_sock, &seqnum);
	struct nft_batch *batch = NULL;

	if (!batch_supported)
		return NULL;

	batch = calloc(1, sizeof(*batch));
	if (batch == NULL)
		return NULL;

	batch->batch = mnl_batch_init();
	mnl_batch_begin(batch->batch, mnl_seqnum_alloc(&nft->cache.seqnum));

	batch->nl_ctx.msgs = &nft->output.msgs;
	batch->nl_ctx.batch = batch->batch;
	batch->nl_ctx.batch_supported = batch_supported;
	batch->nl_ctx.octx = &nft->output;
	batch->nl_ctx.nf_sock = nft->nf_sock;
	batch->nl_ctx.cache = &nft->cache;
	init_list_head(&batch->nl_ctx.list);
	return batch;
}

/**
 * Add a command to an already created batch
 *
 * \param nft nftables context initialized with nft_context_new()
 * \param batch nftables batch initialized with nft_batch_start()
 * \param buf buffer with command to execute
 * \param buflen length of buffer string
 * \return NFT_EXIT_SUCCESS in case of success or NFT_EXIT_FAILURE
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

	parser_init(nft->nf_sock, &nft->cache, &state, &nft->output.msgs);
	scanner = scanner_init(&state);
	scanner_push_buffer(scanner, &indesc_cmdline, buf);
		
	ret = nft_parse(scanner, &state);
	if (ret != 0 || state.nerrs > 0) {
		rc = NFT_EXIT_FAILURE;
		goto err1;
	} 

	list_for_each_entry(cmd, &state.cmds, list) {
		nft_cmd_expand(cmd);
		ctx->seqnum = cmd->seqnum = mnl_seqnum_alloc(&seqnum);
		ret = do_command(ctx, cmd);
		if (ret < 0)
			return NFT_EXIT_FAILURE;
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
 *
 * \param nft nftables context initialized with nft_context_new()
 * \param batch nftables batch with commands added via nft_batch_add()
 * \return NFT_EXIT_SUCCESS in case of success or NFT_EXIT_FAILURE
 */
int nft_batch_commit(struct nft_ctx *nft, struct nft_batch *batch)
{
	int ret = 0;
	LIST_HEAD(err_list);

	mnl_batch_end(batch->batch, mnl_seqnum_alloc(&nft->cache.seqnum));

	if (!mnl_batch_ready(batch->batch)) {
		ret = -1;
		goto out;
	}

	ret = netlink_batch_send(&batch->nl_ctx, &err_list);
	if (ret == -1) {
		struct mnl_err *err, *tmp;
		list_for_each_entry_safe(err, tmp, &err_list, head) {
			netlink_io_error(&batch->nl_ctx, NULL,
					 "Could not process rule: %s",
					 strerror(err->err));
			/* multiple errno but let's return one */
			ret = -err->err;
			mnl_err_list_free(err);
		}
	}
out:
	return ret;
}

/**
 * Free ressources allocated to a batch
 *
 * \param batch nftables batch initialized with nft_batch_start()
 */
void nft_batch_free(struct nft_batch *batch)
{
	if (batch == NULL)
		return;
	mnl_batch_reset(batch->batch);
	xfree(batch);
}

/**
 * @}
 */

/**
 * @}
 */
