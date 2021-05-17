#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter/nf_nat.h>
#include "xt_SDNAT.h"

enum {
	O_TO_DEST = 0,
	O_TO_SRC,
	O_RANDOM,
	O_RANDOM_FULLY,
	O_SEQADJ,
	O_X_TO_SRC,
	O_PERSISTENT,
	O_CTMASK,
	O_CTMARK,
	O_X_TO_DEST, /* hidden flag */
	F_TO_DEST   = 1 << O_TO_DEST,
	F_TO_SRC       = 1 << O_TO_SRC,
	F_RANDOM    = 1 << O_RANDOM,
	F_X_TO_DEST = 1 << O_X_TO_DEST,
	F_RANDOM_FULLY = 1 << O_RANDOM_FULLY,
	F_X_TO_SRC     = 1 << O_X_TO_SRC,
};

/* Dest NAT data consists of a multi-range, indicating where to map
   to. */
struct ipt_natinfo
{
	struct xt_entry_target t;
	struct xt_sdnat_info info;
};

static void SDNAT_help(void)
{
	printf(
"SDNAT target options:\n"
" --to-destination [<ipaddr>[-<ipaddr>]][:port[-port]]\n"
"				Address to map destination to.\n"
" --to-source [<ipaddr>[-<ipaddr>]][:port[-port]]\n"
"				Address to map source to.\n"
" --ctmark [mark]\n"
"				Conntrack mark to set.\n"
" --ctmask [mask]\n"
"				Conntrack mask to set.\n"
"[--random] [--persistent] [--also-seqadj]\n");
}

static const struct xt_option_entry SDNAT_opts[] = {
	{.name = "to-destination", .id = O_TO_DEST, .type = XTTYPE_STRING},
	{.name = "to-source", .id = O_TO_SRC, .type = XTTYPE_STRING},
	{.name = "random", .id = O_RANDOM, .type = XTTYPE_NONE},
	{.name = "random-fully", .id = O_RANDOM_FULLY, .type = XTTYPE_NONE},
	{.name = "persistent", .id = O_PERSISTENT, .type = XTTYPE_NONE},
	{.name = "ctmark", .id = O_CTMARK, .type = XTTYPE_UINT32, .flags = XTOPT_PUT,
	 XTOPT_POINTER(struct xt_sdnat_info, ctmark)},
	{.name = "ctmask", .id = O_CTMASK, .type = XTTYPE_UINT32, .flags = XTOPT_PUT,
	 XTOPT_POINTER(struct xt_sdnat_info, ctmask)},
	{.name = "also-seqadj", .id = O_SEQADJ, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static struct ipt_natinfo *
append_range(struct ipt_natinfo *info, const struct nf_nat_ipv4_range *range, struct nf_nat_ipv4_multi_range_compat* target)
{
	int size;

	/* One rangesize already in struct ipt_natinfo */
	target->rangesize++;
	
	size = (info->info.src.rangesize + info->info.src.rangesize - 2) * sizeof(*range);
	if(size < 0) size = 0;
	size = XT_ALIGN(sizeof(*info) + size);
	
	
	info = realloc(info, size);
	if (!info)
		xtables_error(OTHER_PROBLEM, "Out of memory\n");

	info->t.u.target_size = (unsigned int)size;
	target->range[target->rangesize - 1] = *range;

	return info;
}

/* Ranges expected in network order. */
static struct xt_entry_target *
parse_to(const char *orig_arg, int portok, struct ipt_natinfo *info, struct nf_nat_ipv4_multi_range_compat* target)
{
	struct nf_nat_ipv4_range range;
	char *arg, *colon, *dash, *error;
	const struct in_addr *ip;

	arg = strdup(orig_arg);
	if (arg == NULL)
		xtables_error(RESOURCE_PROBLEM, "strdup");
	memset(&range, 0, sizeof(range));
	colon = strchr(arg, ':');

	range.flags |= NF_NAT_SET;
	if (colon) {
		int port;

		if (!portok)
			xtables_error(PARAMETER_PROBLEM,
				   "Need TCP, UDP, SCTP or DCCP with port specification");

		range.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;

		port = atoi(colon+1);
		if (port <= 0 || port > 65535)
			xtables_error(PARAMETER_PROBLEM,
				   "Port `%s' not valid\n", colon+1);

		error = strchr(colon+1, ':');
		if (error)
			xtables_error(PARAMETER_PROBLEM,
				   "Invalid port:port syntax - use dash\n");

		dash = strchr(colon, '-');
		if (!dash) {
			range.min.tcp.port
				= range.max.tcp.port
				= htons(port);
		} else {
			int maxport;

			maxport = atoi(dash + 1);
			if (maxport <= 0 || maxport > 65535)
				xtables_error(PARAMETER_PROBLEM,
					   "Port `%s' not valid\n", dash+1);
			if (maxport < port)
				/* People are stupid. */
				xtables_error(PARAMETER_PROBLEM,
					   "Port range `%s' funky\n", colon+1);
			range.min.tcp.port = htons(port);
			range.max.tcp.port = htons(maxport);
		}
		/* Starts with a colon? No IP info...*/
		if (colon == arg) {
			free(arg);
			return &(append_range(info, &range, target)->t);
		}
		*colon = '\0';
	}

	range.flags |= NF_NAT_RANGE_MAP_IPS;
	dash = strchr(arg, '-');
	if (colon && dash && dash > colon)
		dash = NULL;

	if (dash)
		*dash = '\0';

	ip = xtables_numeric_to_ipaddr(arg);
	if (!ip)
		xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
			   arg);
	range.min_ip = ip->s_addr;
	if (dash) {
		ip = xtables_numeric_to_ipaddr(dash+1);
		if (!ip)
			xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
				   dash+1);
		range.max_ip = ip->s_addr;
	} else
		range.max_ip = range.min_ip;

	free(arg);
	return &(append_range(info, &range, target)->t);
}

static void SDNAT_init(struct xt_entry_target *target){
	struct ipt_natinfo *t = (void *)target;
	t->info.ctmark = 0;
	t->info.ctmask = 0;
}

static void SDNAT_parse(struct xt_option_call *cb)
{
	const struct ipt_entry *entry = cb->xt_entry;
	struct ipt_natinfo *info = (void *)(*cb->target);
	int portok;

	if (entry->ip.proto == IPPROTO_TCP
	    || entry->ip.proto == IPPROTO_UDP
	    || entry->ip.proto == IPPROTO_SCTP
	    || entry->ip.proto == IPPROTO_DCCP
	    || entry->ip.proto == IPPROTO_ICMP)
		portok = 1;
	else
		portok = 0;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO_DEST:
		if (cb->xflags & F_X_TO_DEST) {
				xtables_error(PARAMETER_PROBLEM,
					   "DNAT: Multiple --to-destination not supported");
		}
		*cb->target = parse_to(cb->arg, portok, info, &(info->info.dst));
		info->info.flags |= XT_SDNAT_FLAG_DNAT;
		cb->xflags |= F_X_TO_DEST;
		break;
	case O_TO_SRC:
		if (cb->xflags & F_X_TO_SRC) {
				xtables_error(PARAMETER_PROBLEM,
					   "SNAT: Multiple --to-source not supported");
		}
		*cb->target = parse_to(cb->arg, portok, info, &(info->info.src));
		info->info.flags |= XT_SDNAT_FLAG_SNAT;
		cb->xflags |= F_X_TO_SRC;
		break;
	case O_PERSISTENT:
		info->info.src.range[0].flags |= NF_NAT_RANGE_PERSISTENT;
		break;
	case O_CTMASK:
		info->info.flags |= XT_SDNAT_FLAG_MASK;
		break;
	case O_SEQADJ:
		info->info.flags |= XT_SDNAT_FLAG_SEQADJ;
		break;
	}
}

static void print_range(const struct nf_nat_ipv4_range *r)
{
	if(!(r->flags & NF_NAT_SET)){
		return;
	}
	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		struct in_addr a;

		a.s_addr = r->min_ip;
		printf("%s", xtables_ipaddr_to_numeric(&a));
		if (r->max_ip != r->min_ip) {
			a.s_addr = r->max_ip;
			printf("-%s", xtables_ipaddr_to_numeric(&a));
		}
	}
	if (r->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(":");
		printf("%hu", ntohs(r->min.tcp.port));
		if (r->max.tcp.port != r->min.tcp.port)
			printf("-%hu", ntohs(r->max.tcp.port));
	}
}

static void SDNAT_print(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
	const struct ipt_natinfo *t = (const void *)target;
	unsigned int i = 0;

	printf(" from:");
	for (i = 0; i < t->info.src.rangesize; i++) {
		print_range(&t->info.src.range[i]);
		if (t->info.src.range[i].flags & NF_NAT_RANGE_PROTO_RANDOM)
			printf(" random");
		if (t->info.src.range[i].flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)
			printf(" random-fully");
		if (t->info.src.range[i].flags & NF_NAT_RANGE_PERSISTENT)
			printf(" persistent");
	}
	printf(" to:");
	for (i = 0; i < t->info.dst.rangesize; i++) {
		print_range(&t->info.dst.range[i]);
		if (t->info.dst.range[i].flags & NF_NAT_RANGE_PROTO_RANDOM)
			printf(" random");
		if (t->info.dst.range[i].flags & NF_NAT_RANGE_PERSISTENT)
			printf(" persistent");
	}
}

static void SDNAT_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_natinfo *t = (const void *)target;
	unsigned int i = 0;

	if(t->info.flags & XT_SDNAT_FLAG_SNAT) {
		for (i = 0; i < t->info.src.rangesize; i++) {	
			if(!(t->info.src.range[i].flags & NF_NAT_SET)){
				continue;
			}

			printf(" --to-source ");
			print_range(&t->info.src.range[i]);
			
			if (t->info.src.range[i].flags & NF_NAT_RANGE_PROTO_RANDOM)
				printf(" --random");
			if (t->info.src.range[i].flags & NF_NAT_RANGE_PERSISTENT)
				printf(" --persistent");
		}
	}
	
	if(t->info.flags & XT_SDNAT_FLAG_DNAT) {
		for (i = 0; i < t->info.dst.rangesize; i++) {
			printf(" --to-destination ");
			print_range(&t->info.dst.range[i]);
		}
	}
	if((t->info.flags & XT_SDNAT_FLAG_MASK) && t->info.ctmark != 0){
		printf(" --ctmark %u", t->info.ctmark);
		printf(" --ctmask %u", t->info.ctmask);
	}

	if(t->info.flags & XT_SDNAT_FLAG_SEQADJ){
		printf(" --also-seqadj");
	}
}

static struct xtables_target sdnat_tg_reg = {
	.name		= "SDNAT",
    .revision      = 1,
	.version       = XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct xt_sdnat_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_sdnat_info)),
	.init       = SDNAT_init,
	.help		= SDNAT_help,
	.x6_parse	= SDNAT_parse,
	.print		= SDNAT_print,
	.save		= SDNAT_save,
	.x6_options	= SDNAT_opts,
};

void _init(void)
{
	xtables_register_target(&sdnat_tg_reg);
}