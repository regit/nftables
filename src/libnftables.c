#include <nftables/nftables.h>
#include <nftables.h>

unsigned int max_errors = 10;
unsigned int numeric_output;
unsigned int ip2name_output;
unsigned int handle_output;
#ifdef DEBUG
unsigned int debug_level;
#endif

const char *include_paths[INCLUDE_PATHS_MAX] = { DEFAULT_INCLUDE_PATH };



nft_context_t * nft_init()
{
	return NULL;
}

int nft_run_command(nft_context_t *ctx, const char * buf, size_t buflen)
{
	return -1;
}

int nft_close(nft_context_t *ctx)
{
	return 0;
}
