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

const char *include_paths[INCLUDE_PATHS_MAX] = { DEFAULT_INCLUDE_PATH };


void nft_global_init(void)
{
	meta_init();
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

	return ctx;
}

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

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

	/* TODO switch to a thread safe version */
	mnl_batch_init();

	batch_seqnum = mnl_batch_begin();
	list_for_each_entry(cmd, &state->cmds, list) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.msgs = msgs;
		ctx.seqnum = cmd->seqnum = mnl_seqnum_alloc();
		ctx.batch_supported = batch_supported;
		init_list_head(&ctx.list);
		ret = do_command(nft_ctx, cmd);
		if (ret < 0)
			goto out;
	}
	mnl_batch_end();

	if (!mnl_batch_ready())
		goto out;

	ret = mnl_batch_talk(nft_ctx->nf_sock, &err_list);

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
	mnl_batch_reset();
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
	scanner_push_buffer(scanner, &indesc_cmdline, buf);

	if (nft_run(ctx, scanner, &state, &msgs) != 0)
		rc = NFT_EXIT_FAILURE;

	scanner_destroy(scanner);
	erec_print_list(stderr, &msgs);
	cache_release(ctx);
	iface_cache_release();

	return rc;
}

int nft_close(nft_context_t *ctx)
{
	if (!ctx)
		return -1;

	if (ctx->nl_ctx) {
		free(ctx->nl_ctx);
	}
	mnl_socket_close(ctx->nf_sock);
	return 0;
}
