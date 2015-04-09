#ifndef _NFTABLES_IFACE_H_
#define _NFTABLES_IFACE_H_

#include <net/if.h>

struct iface {
	struct list_head	list;
	char			name[IFNAMSIZ];
	uint32_t		ifindex;
};

unsigned int nft_if_nametoindex(const char *name);
char *nft_if_indextoname(unsigned int ifindex, char *name);

void iface_cache_update(void);
void iface_cache_release(void);

#endif
