#ifndef LIB_NFTABLES_H
#define LIB_NFTABLES_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <nftables/list.h>

typedef struct _nft_context {
	struct netlink_ctx *nl_ctx;
	struct mnl_socket *nf_sock;
	struct mnl_socket *mon_sock;
	struct nftnl_batch *batch;
	struct list_head cmds;
	int seq;
	unsigned int batch_seqnum;
	bool cache_initialized;
	bool batch_supported;
} nft_context_t;

void nft_global_init(void);
void nft_global_deinit(void);
nft_context_t * nft_open(void);
int nft_run_command(nft_context_t *ctx, const char * buf, size_t buflen);
int nft_close(nft_context_t *ctx);

int nft_transaction_start(nft_context_t *ctx);
int nft_transaction_add(nft_context_t *ctx, const char * buf, size_t buflen);
int nft_transaction_commit(nft_context_t *ctx);

#endif
