#include <nftables/nftables.h>
#include <string.h>
#include <errno.h>
#include <nftables.h>
#include <parser.h>
#include <iface.h>
#include <netlink.h>
#include <erec.h>
#include <libmnl/libmnl.h>
#include <mnl.h>

#include <unistd.h>
#include <fcntl.h>


unsigned int max_errors = 10;
unsigned int numeric_output;
unsigned int ip2name_output;
unsigned int handle_output;
#ifdef DEBUG
unsigned int debug_level;
#endif


const char *include_paths[INCLUDE_PATHS_MAX];

const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

void nft_global_init(void)
{
	meta_init();
	devgroup_table_init();
	realm_table_init();
	ct_init();
	ct_label_table_init();
	mark_table_init();
	exthdr_init();
	gmp_init();
	proto_init();
}

void nft_global_deinit(void)
{
	mark_table_exit();
	realm_table_exit();
	devgroup_table_exit();
}

nft_context_t * nft_open()
{
	nft_context_t *ctx = NULL;
	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(*ctx));

	ctx->nl_ctx = malloc(sizeof(*ctx->nl_ctx));
	if (ctx->nl_ctx == NULL) {
		free(ctx);
		return NULL;
	}

	ctx->nf_sock = netlink_nfsock_open();
	fcntl(mnl_socket_get_fd(ctx->nf_sock), F_SETFL, O_NONBLOCK);

	ctx->batch_supported = netlink_batch_supported(ctx);

	init_list_head(&ctx->cmds);
	init_list_head(&ctx->msgs);

	ctx->indesc = &indesc_cmdline;

	return ctx;
}

static int nft_netlink(nft_context_t *nft_ctx, struct parser_state *state,
		       struct list_head *msgs)
{
	struct netlink_ctx ctx;
	struct cmd *cmd;
	struct mnl_err *err, *tmp;
	LIST_HEAD(err_list);
	uint32_t batch_seqnum;
	bool batch_supported = netlink_batch_supported(nft_ctx);
	int ret = 0;

	mnl_batch_init(nft_ctx);

	batch_seqnum = mnl_batch_begin(nft_ctx);
	list_for_each_entry(cmd, &state->cmds, list) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.msgs = msgs;
		ctx.seqnum = cmd->seqnum = mnl_seqnum_alloc(nft_ctx);
		ctx.batch_supported = batch_supported;
		init_list_head(&ctx.list);
		/* FIXME ? */
		nft_ctx->nl_ctx = &ctx;
		ret = do_command(nft_ctx, cmd);
		if (ret < 0)
			goto out;
	}
	mnl_batch_end(nft_ctx);

	if (!mnl_batch_ready(nft_ctx))
		goto out;

	ret = mnl_batch_talk(nft_ctx, &err_list);

	list_for_each_entry_safe(err, tmp, &err_list, head) {
		list_for_each_entry(cmd, &state->cmds, list) {
			if (err->seqnum == cmd->seqnum ||
			    err->seqnum == batch_seqnum) {
				netlink_io_error(nft_ctx, &cmd->location,
						 "Could not process rule: %s",
						 strerror(err->err));
				ret = -1;
				errno = err->err;
				if (err->seqnum == cmd->seqnum) {
					mnl_err_list_free(err);
					break;
				}
			}
		}
	}
out:
	mnl_batch_reset(nft_ctx);
	return ret;
}

int nft_run(nft_context_t *ctx, void *scanner, struct parser_state *state, struct list_head *msgs)
{
	struct cmd *cmd, *next;
	int ret;

	ret = nft_parse(scanner, state);
	if (ret != 0 || state->nerrs > 0) {
		ret = -1;
		goto err1;
	}
	ret = nft_netlink(ctx, state, msgs);
err1:
	list_for_each_entry_safe(cmd, next, &state->cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}

	return ret;
}

int nft_run_command(nft_context_t *ctx, const char * buf, size_t buflen)
{
	struct parser_state state;
	void *scanner;
	LIST_HEAD(msgs);
	int rc = NFT_EXIT_SUCCESS;

	parser_init(&state, &msgs, ctx);
	scanner = scanner_init(&state);
	scanner_push_buffer(scanner, ctx->indesc, buf);

	if (nft_run(ctx, scanner, &state, &msgs) != 0)
		rc = NFT_EXIT_FAILURE;

	scanner_destroy(scanner);
	erec_print_list(stderr, &msgs);
	cache_release(ctx);
	iface_cache_release();

	return rc;
}


/** FIXME return -1 if a transaction is already started */
int nft_transaction_start(nft_context_t *ctx)
{
	mnl_batch_init(ctx);
	ctx->batch_seqnum = mnl_batch_begin(ctx);

	return 0;
}

int nft_transaction_add(nft_context_t *ctx, const char * buf, size_t buflen)
{
	struct parser_state state;
	void *scanner;
	struct cmd *cmd;
	LIST_HEAD(msgs);
	int ret = NFT_EXIT_SUCCESS;
	struct netlink_ctx cctx;

	parser_init(&state, &msgs, ctx);
	scanner = scanner_init(&state);
	scanner_push_buffer(scanner, ctx->indesc, buf);

	ret = nft_parse(scanner, &state);
	if (ret != 0 || state.nerrs > 0) {
		ret = NFT_EXIT_FAILURE;
		goto out;
	}

	list_for_each_entry(cmd, &state.cmds, list) {
		memset(&cctx, 0, sizeof(cctx));
		cctx.msgs = &msgs;
		cctx.seqnum = cmd->seqnum = mnl_seqnum_alloc(ctx);
		cctx.batch_supported = ctx->batch_supported;
		init_list_head(&cctx.list);
		/* FIXME ? */
		ctx->nl_ctx = &cctx;
		ret = do_command(ctx, cmd);
		if (ret < 0) {
			ret = NFT_EXIT_FAILURE;
			goto out;
		}
	}

	/* add cmds to context for error handling */
	list_splice_init(&state.cmds, &ctx->cmds);
	list_splice_init(&msgs, &ctx->msgs);

out:
	ctx->nl_ctx = NULL;
	scanner_destroy(scanner);
	return ret;
}

int nft_transaction_commit(nft_context_t *ctx)
{
	int ret = 0;
	struct mnl_err *err, *tmp;
	LIST_HEAD(msgs);

	mnl_batch_end(ctx);
	LIST_HEAD(err_list);
	struct cmd *cmd;
	struct netlink_ctx nl_ctx;

	if (!mnl_batch_ready(ctx))
		goto out;

	memset(&nl_ctx, 0, sizeof(nl_ctx));
	init_list_head(&nl_ctx.list);
	init_list_head(&msgs);
	nl_ctx.msgs = &msgs;
	ctx->nl_ctx = &nl_ctx;

	ret = mnl_batch_talk(ctx, &err_list);

	list_for_each_entry_safe(err, tmp, &err_list, head) {
		list_for_each_entry(cmd, &ctx->cmds, list) {
			if (err->seqnum == cmd->seqnum ||
			    err->seqnum == ctx->batch_seqnum) {
				netlink_io_error(ctx, &cmd->location,
						 "Could not process rule: %s",
						 strerror(err->err));
				ret = -1;
				errno = err->err;
				if (err->seqnum == cmd->seqnum) {
					mnl_err_list_free(err);
					break;
				}
			}
		}
	}
out:
	list_splice_init(&msgs, &ctx->msgs);
	ctx->nl_ctx = NULL;
	mnl_batch_reset(ctx);
	return ret;

}


int nft_print_error(nft_context_t *nft_ctx)
{
	erec_print_list(stderr, &nft_ctx->msgs);
	return 0;
}

int nft_close(nft_context_t *ctx)
{
	if (!ctx)
		return -1;

	if (ctx->nl_ctx) {
		free(ctx->nl_ctx);
	}
	mnl_socket_close(ctx->nf_sock);
	if (ctx->mon_sock)
		mnl_socket_close(ctx->mon_sock);
	return 0;
}
