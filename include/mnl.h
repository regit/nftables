#ifndef _NFTABLES_MNL_H_
#define _NFTABLES_MNL_H_

#include <list.h>
#include <nftables/nftables.h>

struct mnl_socket;

uint32_t mnl_seqnum_alloc(nft_context_t *nft_ctx);
void mnl_genid_get(nft_context_t *nft_ctx);

struct mnl_err {
	struct list_head	head;
	int			err;
	uint32_t		seqnum;
};

void mnl_err_list_free(struct mnl_err *err);

void mnl_batch_init(nft_context_t *nft_ctx);
bool mnl_batch_ready(nft_context_t *nft_ctx);
void mnl_batch_reset(nft_context_t *nft_ctx);
uint32_t mnl_batch_begin(nft_context_t *nft_ctx);
void mnl_batch_end(nft_context_t *nft_ctx);
int mnl_batch_talk(nft_context_t *nft_ctx, struct list_head *err_list);
int mnl_nft_rule_batch_add(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
			   unsigned int flags, uint32_t seqnum);
int mnl_nft_rule_batch_del(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
			   unsigned int flags, uint32_t seqnum);
int mnl_nft_rule_batch_replace(nft_context_t *nft_ctx, struct nftnl_rule *nlr,
			       unsigned int flags, uint32_t seqnum);

int mnl_nft_rule_add(nft_context_t *nft_ctx, struct nftnl_rule *r,
		     unsigned int flags);
int mnl_nft_rule_delete(nft_context_t *nft_ctx, struct nftnl_rule *r,
			unsigned int flags);
struct nftnl_rule_list *mnl_nft_rule_dump(nft_context_t *nft_ctx,
					int family);

int mnl_nft_chain_add(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
		      unsigned int flags);
int mnl_nft_chain_batch_add(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
			    unsigned int flags, uint32_t seq);
int mnl_nft_chain_delete(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
                         unsigned int flags);
int mnl_nft_chain_batch_del(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
			    unsigned int flags, uint32_t seq);
struct nftnl_chain_list *mnl_nft_chain_dump(nft_context_t *nft_ctx,
					  int family);
int mnl_nft_chain_get(nft_context_t *nft_ctx, struct nftnl_chain *nlc,
		      unsigned int flags);

int mnl_nft_table_add(nft_context_t *nft_ctx, struct nftnl_table *nlt,
		      unsigned int flags);
int mnl_nft_table_batch_add(nft_context_t *nft_ctx, struct nftnl_table *nlt,
			    unsigned int flags, uint32_t seq);
int mnl_nft_table_delete(nft_context_t *nft_ctx, struct nftnl_table *nlt,
			 unsigned int flags);
int mnl_nft_table_batch_del(nft_context_t *nft_ctx, struct nftnl_table *nlt,
			    unsigned int flags, uint32_t seq);
struct nftnl_table_list *mnl_nft_table_dump(nft_context_t *nft_ctx,
					  int family);
int mnl_nft_table_get(nft_context_t *nft_ctx, struct nftnl_table *nlt,
		      unsigned int flags);

int mnl_nft_set_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
		    unsigned int flags);
int mnl_nft_set_batch_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
			  unsigned int flags, uint32_t seq);
int mnl_nft_set_delete(nft_context_t *nft_ctx, struct nftnl_set *nls,
		       unsigned int flags);
int mnl_nft_set_batch_del(nft_context_t *nft_ctx, struct nftnl_set *nls,
			  unsigned int flags, uint32_t seq);
struct nftnl_set_list *mnl_nft_set_dump(nft_context_t *nft_ctx, int family,
				      const char *table);
int mnl_nft_set_get(nft_context_t *nft_ctx, struct nftnl_set *nls);

int mnl_nft_setelem_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
			unsigned int flags);
int mnl_nft_setelem_batch_add(nft_context_t *nft_ctx, struct nftnl_set *nls,
			      unsigned int flags, uint32_t seq);
int mnl_nft_setelem_delete(nft_context_t *nft_ctx, struct nftnl_set *nls,
			   unsigned int flags);
int mnl_nft_setelem_batch_del(nft_context_t *nft_ctx, struct nftnl_set *nls,
			      unsigned int flags, uint32_t seq);
int mnl_nft_setelem_get(nft_context_t *nft_ctx, struct nftnl_set *nls);

struct nftnl_ruleset *mnl_nft_ruleset_dump(nft_context_t *nft_ctx,
					 uint32_t family);
int mnl_nft_event_listener(struct mnl_socket *nf_sock,
			   int (*cb)(const struct nlmsghdr *nlh, void *data),
			   void *cb_data);

bool mnl_batch_supported(nft_context_t *nft_ctx);

#endif /* _NFTABLES_MNL_H_ */
