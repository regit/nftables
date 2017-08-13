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
#include <nftables_common.h>
#include <netlink.h>
#include <parser.h>
#include <mnl.h>

static int nft_netlink(struct nft_ctx *nft, struct nft_cache *cache,
		       struct parser_state *state, struct list_head *msgs,
		       struct mnl_socket *nf_sock)
{
	uint32_t batch_seqnum, seqnum = 0;
	struct nftnl_batch *batch;
	struct netlink_ctx ctx;
	struct cmd *cmd;
	struct mnl_err *err, *tmp;
	LIST_HEAD(err_list);
	bool batch_supported = netlink_batch_supported(nf_sock, &seqnum);
	int ret = 0;

	batch = mnl_batch_init();

	batch_seqnum = mnl_batch_begin(batch, mnl_seqnum_alloc(&seqnum));
	list_for_each_entry(cmd, &state->cmds, list) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.msgs = msgs;
		ctx.seqnum = cmd->seqnum = mnl_seqnum_alloc(&seqnum);
		ctx.batch = batch;
		ctx.batch_supported = batch_supported;
		ctx.octx = &nft->output;
		ctx.nf_sock = nf_sock;
		ctx.cache = cache;
		init_list_head(&ctx.list);
		ret = do_command(&ctx, cmd);
		if (ret < 0)
			goto out;
	}
	if (!nft->check)
		mnl_batch_end(batch, mnl_seqnum_alloc(&seqnum));

	if (!mnl_batch_ready(batch))
		goto out;

	ret = netlink_batch_send(&ctx, &err_list);

	list_for_each_entry_safe(err, tmp, &err_list, head) {
		list_for_each_entry(cmd, &state->cmds, list) {
			if (err->seqnum == cmd->seqnum ||
			    err->seqnum == batch_seqnum) {
				netlink_io_error(&ctx, &cmd->location,
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
	mnl_batch_reset(batch);
	return ret;
}

int nft_run(struct nft_ctx *nft, struct mnl_socket *nf_sock,
	    struct nft_cache *cache, void *scanner, struct parser_state *state,
	    struct list_head *msgs)
{
	struct cmd *cmd, *next;
	int ret;

	ret = nft_parse(scanner, state);
	if (ret != 0 || state->nerrs > 0) {
		ret = -1;
		goto err1;
	}

	list_for_each_entry(cmd, &state->cmds, list)
		nft_cmd_expand(cmd);

	ret = nft_netlink(nft, cache, state, msgs, nf_sock);
err1:
	list_for_each_entry_safe(cmd, next, &state->cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}

	return ret;
}


