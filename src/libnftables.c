/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

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
