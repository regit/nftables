#ifndef LIB_NFTABLES_H
#define LIB_NFTABLES_H

#include <stdlib.h>

typedef struct _nft_context {
	struct mnl_socket *nf_sock;
	struct netlink_ctx *nl_ctx;
} nft_context_t;

nft_context_t * nft_init(void);
int nft_run_command(nft_context_t *ctx, const char * buf, size_t buflen);
int nft_close(nft_context_t *ctx);

#endif
