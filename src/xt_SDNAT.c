/*
 * (C) 2017 Mathew Heard <mheard@x4b.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include "libxt_SDNAT.h"

static void xt_nat_convert_range(struct nf_nat_range *dst,
				 const struct nf_nat_ipv4_range *src)
{
	memset(&dst->min_addr, 0, sizeof(dst->min_addr));
	memset(&dst->max_addr, 0, sizeof(dst->max_addr));

	dst->flags	 = src->flags;
	dst->min_addr.ip = src->min_ip;
	dst->max_addr.ip = src->max_ip;
	dst->min_proto	 = src->min;
	dst->max_proto	 = src->max;
}

static unsigned int
xt_sdnat_target_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_sdnat_info *info = par->targinfo;
	struct nf_nat_range snat_range, dnat_range;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	u_int32_t newmark;


	ct = nf_ct_get(skb, &ctinfo);
	NF_CT_ASSERT(ct != NULL &&
		     (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));

	xt_nat_convert_range(&snat_range, info.src.range[0]);
	xt_nat_convert_range(&dnat_range, info.dst->range[0]);


	newmark = (ct->mark & ~info->ctmask) ^ info->ctmark;

	if (ct->mark != newmark) {
		ct->mark = newmark;
		nf_conntrack_event_cache(IPCT_MARK, ct);
	}
	
	nf_nat_setup_info(ct, &snat_range, NF_NAT_MANIP_SRC);
	return nf_nat_setup_info(ct, &dnat_range, NF_NAT_MANIP_DST);
}

static struct xt_target xt_nat_target_reg[] __read_mostly = {
	{
		.name		= "SDNAT",
		.revision	= 1,
		.target		= xt_sdnat_target_v1,
		.targetsize	= sizeof(struct xt_sdnat_info),
		.table		= "nat",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_LOCAL_OUT),
		.me		= THIS_MODULE,
	}
};

static int __init xt_nat_init(void)
{
	return xt_register_targets(xt_nat_target_reg,
				   ARRAY_SIZE(xt_nat_target_reg));
}

static void __exit xt_nat_exit(void)
{
	xt_unregister_targets(xt_nat_target_reg, ARRAY_SIZE(xt_nat_target_reg));
}

module_init(xt_nat_init);
module_exit(xt_nat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mathew Heard <mheard@x4b.net>");
MODULE_ALIAS("ipt_SDNAT");;
MODULE_ALIAS("ip6t_SDNAT");