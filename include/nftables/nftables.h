#ifndef LIB_NFTABLES_H
#define LIB_NFTABLES_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct _nft_context {
	struct netlink_ctx *nl_ctx;
	struct mnl_socket *nf_sock;
	struct nftnl_batch *batch;
	bool cache_initialized;
} nft_context_t;

void nft_global_init(void);
void nft_global_deinit(void);
nft_context_t * nft_open(void);
int nft_run_command(nft_context_t *ctx, const char * buf, size_t buflen);
int nft_close(nft_context_t *ctx);

#endif
