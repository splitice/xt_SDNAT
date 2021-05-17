#include <linux/netfilter_ipv4/ip_tables.h>

struct xt_sdnat_info {
	struct nf_nat_ipv4_multi_range_compat src;
	struct nf_nat_ipv4_multi_range_compat dst;
	int flags;
	u_int32_t ctmark;
	u_int32_t ctmask;
};

#define XT_SDNAT_FLAG_SNAT (1 << 0)
#define XT_SDNAT_FLAG_DNAT (1 << 1)
#define XT_SDNAT_FLAG_MASK (1 << 2)
#define XT_SDNAT_FLAG_SEQADJ (1 << 3)

#define NF_NAT_SET		(1 << 5)