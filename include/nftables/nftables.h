#ifndef LIB_NFTABLES_H
#define LIB_NFTABLES_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

void nft_global_init(void);
void nft_global_deinit(void);

struct nft_ctx *nft_context_new(void);
void nft_context_free(struct nft_ctx *nft);

int nft_run_command_from_buffer(struct nft_ctx *nft, struct nft_cache *cache,
				const char *buf, size_t buflen);

#endif
