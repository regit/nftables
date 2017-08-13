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

void nft_global_init(void)
{
	mark_table_init();
	realm_table_rt_init();
	devgroup_table_init();
	realm_table_meta_init();
	ct_label_table_init();
	gmp_init();
#ifdef HAVE_LIBXTABLES
	xt_init();
#endif
}

void nft_global_deinit(void)
{
	ct_label_table_exit();
	realm_table_rt_exit();
	devgroup_table_exit();
	realm_table_meta_exit();
	mark_table_exit();
}

struct nft_ctx *nft_context_new(void)
{
	struct nft_ctx *ctx = NULL;
	ctx = malloc(sizeof(struct nft_ctx));
	if (ctx == NULL)
		return NULL;
	ctx->nf_sock = netlink_open_sock();

	return ctx;
}


void nft_context_free(struct nft_ctx *nft)
{
	if (nft == NULL)
		return;
	netlink_close_sock(nft->nf_sock);
	free(nft);
}