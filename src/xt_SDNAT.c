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
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat_core.h>

static int xt_nat_checkentry(const struct xt_tgchk_param *par)
{
	return nf_ct_netns_get(par->net, par->family);
}

static void xt_nat_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

static unsigned int
xt_dnat_target_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct nf_nat_range *range = par->targinfo;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	NF_CT_ASSERT(ct != NULL &&
		     (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));

	nf_nat_setup_info(ct, range, NF_NAT_MANIP_SRC);
	return nf_nat_setup_info(ct, range + 1, NF_NAT_MANIP_DST);
}

static struct xt_target xt_nat_target_reg[] __read_mostly = {
	{
		.name		= "SDNAT",
		.revision	= 1,
		.checkentry	= xt_nat_checkentry,
		.destroy	= xt_nat_destroy,
		.target		= xt_sdnat_target_v1,
		.targetsize	= sizeof(struct nf_nat_range)*2,
		.table		= "nat",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
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