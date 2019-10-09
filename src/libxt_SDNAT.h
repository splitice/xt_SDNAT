#include <net/netfilter/nf_nat_core.h>
#include <linux/netfilter_ipv4/ip_tables.h>

struct xt_sdnat_info {
	struct nf_nat_ipv4_multi_range_compat src;
	struct nf_nat_ipv4_multi_range_compat dst;
	u_int32_t ctmark;
	u_int32_t ctmask;
};