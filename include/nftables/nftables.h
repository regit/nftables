#ifndef LIB_NFTABLES_H
#define LIB_NFTABLES_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

enum nftables_exit_codes {
	NFT_EXIT_SUCCESS	= 0,
	NFT_EXIT_FAILURE	= 1,
	NFT_EXIT_NOMEM		= 2,
	NFT_EXIT_NONL		= 3,
};

void nft_global_init(void);
void nft_global_deinit(void);

struct nft_ctx *nft_context_new(void);
void nft_context_free(struct nft_ctx *nft);

int nft_run_command_from_buffer(struct nft_ctx *nft, struct nft_cache *cache,
				const char *buf, size_t buflen);
int nft_run_command_from_filename(struct nft_ctx *nft, struct nft_cache *cache,
				  const char *filename);

#endif
