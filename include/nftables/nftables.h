typedef struct _nft_context {
	int version;
} nft_context_t;

nft_context_t * nft_init();
int nft_run_command(nft_context_t *ctx, const char * buf, size_t buflen);
int nft_close(nft_context_t *ctx);
