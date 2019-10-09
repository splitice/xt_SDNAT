#include <net/netfilter/nf_nat_core.h>

struct xt_sdnat_info {
	nf_nat_ipv4_multi_range_compat src;
	nf_nat_ipv4_multi_range_compat dst;
	u_int32_t ctmark;
	u_int32_t ctmask;
}