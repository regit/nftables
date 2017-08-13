/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

int nft_run(struct nft_ctx *nft, struct mnl_socket *nf_sock, void *scanner,
	    struct parser_state *state, struct list_head *msgs);
