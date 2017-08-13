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
	netlink_close_sock(nft->nf_sock);
	free(nft);
}

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

int nft_run_command_from_buffer(struct nft_ctx *nft, const char *buf,
				size_t buflen)
{
	int rc = NFT_EXIT_SUCCESS;
	struct parser_state state;
	LIST_HEAD(msgs);
	void *scanner;

	parser_init(nft->nf_sock, &state, &msgs);
	scanner = scanner_init(&state);
	scanner_push_buffer(scanner, &indesc_cmdline, buf);
		
	if (nft_run(nft, nft->nf_sock, scanner, &state, &msgs) != 0)
		rc = NFT_EXIT_FAILURE;

	return rc;
}
