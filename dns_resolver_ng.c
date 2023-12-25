#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <ifaddrs.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "dnsproto.h"
#include "tx_debug.h"
#include "subnet_api.h"

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#define closesocket close
#endif

static char addrbuf[256];
#define ntop6(addr) inet_ntop(AF_INET6, &addr, addrbuf, sizeof(addrbuf))
#define ntop6p(addr) inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf))

struct dns_resource _predefine_resource_record[] = {
	{
		.type = NSTYPE_SOA,
		.klass = NSCLASS_INET,
		.ttl = 86400,
		.len = 4,
		.flags = 0,
		.domain = "_dummy",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_NS,
		.klass = NSCLASS_INET,
		.ttl = 86400,
		.len = 8,
		.flags = 0,
		.domain = "_dummy",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_AAAA,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "ipv4only.arpa",
		.value = {110, 42, 145, 164}},
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))
const char _nat64_prefix[] = "2002:1769:c6bd:ffff::8.8.8.8";

int fetch_predefine_resource_record(struct dns_parser *parser)
{
	int found = 0;
	struct dns_resource *res;
	struct dns_question *que = &parser->question[0];
	size_t domain_plen = strlen(que->domain);

	for (int i = 0; i < ARRAY_SIZE(_predefine_resource_record); i++) {

		if (MAX_RECORD_COUNT <= parser->head.answer) {
			break;
		}

		res = &_predefine_resource_record[i];
		if ((res->type == que->type) && strcasecmp(res->domain, que->domain) == 0) {
			int index = parser->head.answer++;
			parser->answer[index].type = res->type;
			parser->answer[index].klass = res->klass;
			parser->answer[index].flags = res->flags;
			parser->answer[index].ttl   = res->ttl;
			memcpy(parser->answer[index].value, res->value, sizeof(res->value));
			parser->answer[index].domain = add_domain(parser, que->domain);
		}

		if (/* res->type == NSTYPE_ANY &&*/ strcasecmp(que->domain, res->domain) == 0) {
			found = 1;
		}
	}

	return (parser->head.answer > 0) || (found == 1);
}

struct dns_cname {
	const char *alias;
};

#define NSCLASS_INET 0x01
#define NSFLAG_RD    0x0100

struct dns_context {
	int outfd;
	int sockfd;

	socklen_t dnslen;
	struct sockaddr_in6 *dnslocal;

	socklen_t dnslen1;
	struct sockaddr_in6 *dnsremote;
};

#define FLAG_REMOTE 0x1
#define FLAG_LOCAL  0x2
#define FLAG_ALL    0x3
#define FLAG_BLOCK_IPV4 0x4
#define FLAG_ZERO_IDENT 0x8

struct dns_incoming {
	uint16_t index;
	uint8_t flags;
	uint8_t length;
	uint8_t  body[96];
};

#if 0
struct dns_outgoing {
};
#endif

struct dns_switcher {
   char *domain;
   uint8_t near_out_A, near_got_A;
   uint8_t pure_out_A, pure_got_A;
   uint8_t near_out_AAAA, near_got_AAAA;
   uint8_t pure_out_AAAA, pure_got_AAAA;

   struct dns_incoming incomings[4];
};

struct dns_query_context {
	int flags;
	int updated;
	int preference;
	int score_board_id;

	int nat64_pref;
	uint8_t oil_addr[16];

	struct sockaddr_in6 from;
	struct dns_parser parser;
};

static struct dns_query_context _orig_list[0x1000];

#define PREFERENCE_LOCAL_NAT64  100
#define PREFERENCE_REMOTE_NAT64 4
#define PREFERENCE_NON_LOCAL_NAT64  6
#define PREFERENCE_NON_REMOTE_NAT64 6

#define PREFERENCE_LOCAL_IPV4  1
#define PREFERENCE_LOCAL_IPV6  20

#define PREFERENCE_REMOTE_IPV6 5
#define PREFERENCE_REMOTE_IPV4 4

#define PREFERENCE_NON_LOCAL_IPV4  5
#define PREFERENCE_NON_LOCAL_IPV6  50
#define PREFERENCE_NON_REMOTE_IPV6 50
#define PREFERENCE_NON_REMOTE_IPV4 50

struct dns_score_board {
	int checking;
	uint16_t ipv6_offset;
	uint16_t ipv4_offset;

	time_t ipv4_atime;
	time_t ipv6_atime;

	int updated;
	int preference;
};

static struct dns_score_board _hash_src[0x10000];

static int dns_parser_copy(struct dns_parser *dst, const struct dns_parser *src)
{
    static uint8_t _qc_hold[2048];
    size_t len  = dns_build(src, _qc_hold, sizeof(_qc_hold));
    return dns_parse(dst, _qc_hold, len) == NULL;
}

static int dns_sendto(int outfd, struct dns_parser *parser, const struct sockaddr *to, size_t tolen)
{
	ssize_t len;
	uint8_t _hold[2048];

	len = dns_build(parser, _hold, sizeof(_hold));

	const struct sockaddr_in6 *inp = (const struct sockaddr_in6 *)to;
	if (len != -1)
		len = sendto(outfd, _hold, len, 0, to, tolen);
	else
		LOG_DEBUG("dns_build %d", len);

	LOG_DEBUG("dns_build bytes %d %d %d %s", len, inp->sin6_family, htons(inp->sin6_port), ntop6(inp->sin6_addr));
	return len;
}

struct subnet_info {
	uint16_t tag; // 0x0008
	uint16_t len;
	uint16_t family;
	uint8_t source_netmask;
	uint8_t scope_netmask;
	uint8_t addr[16];
};

#define NS_IPV6 2
#define NS_IPV4 1

// china mobile 117.143.102.0/24
const static struct subnet_info subnet4_data = {
	0x08, sizeof(subnet4_data), NS_IPV4, 24, 0, {117, 143, 102, 0}
};

static int add_client_subnet(struct dns_parser *p0, uint8_t *optbuf, const struct subnet_info *info)
{
#ifndef DISABLE_SUBNET

	int have_edns = 0;
	struct dns_resource *res = NULL;
	struct subnet_info info0 = *info;

	int prefixlen = info->source_netmask;//+ info->scope_netmask;
	size_t subnet_len = 8 + ((7 + prefixlen) >> 3);

	info0.tag = htons(info->tag);
	info0.family = htons(info->family);
	info0.len    = htons(4 + ((7 + prefixlen) >> 3));

	for (int i = 0; i < p0->head.addon; i++) {
		res = &p0->addon[i];
		if (res->type != NSTYPE_OPT) {
			continue;
		}

		if (res->domain == NULL || *res->domain == 0) {
			size_t len = res->len;
			const uint8_t * valp = *(const uint8_t **)res->value;
			struct tagheader {uint16_t tag; uint16_t len; } tag0;

			while (len > sizeof(tag0)) {
				memcpy(&tag0, valp, sizeof(tag0));
				if (len < sizeof(tag0) + htons(tag0.len)) break;
				const uint8_t *hold = valp;
				valp += sizeof(tag0) + htons(tag0.len);
				len -= (sizeof(tag0) + htons(tag0.len));
				if (tag0.tag == htons(0x0008)) {
					const uint8_t * valp0 = *(const uint8_t **)res->value;
					memcpy(optbuf, valp0, (hold - valp0));
					memcpy(optbuf + (hold - valp0), valp, len);

					memcpy(optbuf + (hold - valp0) + len, &info0, subnet_len);
					*(void **)res->value = optbuf;
					res->len = len + (hold - valp0) + subnet_len;
					have_edns = 1;
					break;
				}
			}

			if (have_edns == 0) {
				const uint8_t * valp = *(const uint8_t **)res->value;

				memcpy(optbuf, &info0, subnet_len);
				memcpy(optbuf + subnet_len, valp, res->len);

				*(void **)res->value = optbuf;
				res->len += subnet_len;
				have_edns = 1;
			}
		}
	}

	if (p0->head.addon < MAX_RECORD_COUNT && have_edns == 0) {
		res = &p0->addon[p0->head.addon++];

		res->domain = "";
		res->klass = 0x1000;
		res->type = NSTYPE_OPT;
		res->ttl  = 0;
		res->len  = subnet_len;
		memcpy(optbuf, &info0, subnet_len);
		*(const void **)res->value = optbuf; 
	}
#endif

	return 0;
}

static uint16_t dns_hash(const void *up, const char *domain)
{
	int i;
	uint32_t total = 0;
	const uint16_t *ptr = (const uint16_t *)up;

	for (i = 0; i < 8; i ++) {
		total += ptr[i];
	}

	ptr = (const uint16_t *)domain;
	while ((*ptr & 0xff00) && (*ptr & 0xff)) {
		total += *ptr++;
	}

	if (*ptr & htons(0xff00)) {
		total += *ptr++;
	}

	total = (total & 0xffff) + (total >> 16);
	return (total & 0xffff) + (total >> 16);
}

int do_dns_forward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
	struct dns_parser p0;
	struct dns_parser *pp;

	pp = dns_parse(&p0, buf, count);
	if (pp == NULL) {
		LOG_DEBUG("do_dns_forward parse failure");
		return 0;
	}

	if (p0.head.flags & 0x8000) {
		LOG_DEBUG("FROM: %s this is not query", "nothing");
		return -1;
	}
	
	if (fetch_predefine_resource_record(&p0)) {
		LOG_DEBUG("prefetch: %s", p0.question[0].domain);
		p0.head.flags |= NSFLAG_QR;
		dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
		return 0;
	}
	
	int retval = 0;
	int offset = (p0.head.ident & 0xfff);

	struct dns_parser *p1 = NULL;
	struct dns_query_context *qc = &_orig_list[offset];

	p1 = &qc->parser;
	if (memcmp(from, &qc->from, sizeof(from)) ||
			(qc->flags & FLAG_ALL) == FLAG_ALL||
			(qc->preference == MIN(PREFERENCE_LOCAL_IPV4, PREFERENCE_LOCAL_IPV6)) ||
			memcmp(&p1->head, &p0.head, sizeof(p0.head)) ||
			strcmp(p0.question[0].domain, p1->question[0].domain) ||
			p0.question[0].type != p1->question[0].type) {
		memset(qc, 0, sizeof(*qc));
		qc->from = *from;
		qc->preference = 100;
		qc->nat64_pref = 100;
		qc->score_board_id = -1;

		dns_parser_copy(&qc->parser, &p0);
	}

	p0.head.flags |= NSFLAG_RD;

	char optbuf[124];
	struct dns_parser u1 = {};
	dns_parser_copy(&u1, &p0);
	add_client_subnet(&u1, optbuf, &subnet4_data);

	retval = dns_sendto(ctx->outfd, &u1, ctx->dnslocal, ctx->dnslen1);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnslocal);
		return 0;
	}

	if (ctx->dnsremote == NULL) {
		return 0;
	}

	retval = sendto(ctx->outfd, buf, count, 0, ctx->dnsremote, ctx->dnslen);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnsremote);
		return 0;
	}

	if (p0.question[0].type != NSTYPE_AAAA && p0.question[0].type != NSTYPE_A) {
		LOG_DEBUG("skip dns type: %s type:%d", p0.question[0].domain, p0.question[0].type);
		return 0;
	}

	int hashid = dns_hash(&from->sin6_addr, p0.question[0].domain);
	LOG_DEBUG("FROM %s:%d QUERY: %s type:%d hashid:%04x ident:%04x",
			ntop6(from->sin6_addr), htons(from->sin6_port),
			p0.question[0].domain, p0.question[0].type, hashid, p0.head.ident);

	struct dns_score_board *sb = &_hash_src[hashid];

	if (p0.question[0].type == NSTYPE_A) {
		sb->ipv4_offset = p0.head.ident;
		sb->ipv4_atime  = time(NULL);
	} else if (p0.question[0].type == NSTYPE_AAAA) {
		sb->ipv6_offset = p0.head.ident;
		sb->ipv6_atime  = time(NULL);
	}

	int i;
	struct dns_parser *pp4, *pp6;
	struct dns_query_context *qc6, *qc4;

	qc4 = &_orig_list[sb->ipv4_offset & 0xfff];
	qc6 = &_orig_list[sb->ipv6_offset & 0xfff];

	pp4 = &qc4->parser;
	pp6 = &qc6->parser;
	if (sb->ipv4_atime + 2 < time(NULL) || sb->ipv6_atime + 2 < time(NULL) ||
			memcmp(&qc4->from.sin6_addr, &qc6->from.sin6_addr, sizeof(from->sin6_addr))) {
		LOG_DEBUG("time expire detected: %s", p0.question[0].domain);
		sb->preference = 100;
		sb->checking = 0;
	} else {
		assert(pp4->head.question > 0 && pp6->head.question > 0);
		if (strcasecmp(pp4->question[0].domain, pp6->question[0].domain) ||
				pp4->question[0].type != NSTYPE_A || pp6->question[0].type != NSTYPE_AAAA) {
			LOG_DEBUG("getaddrinfo failure domain: %s %s", pp4->question[0].domain, pp6->question[0].domain);
			sb->preference = 100;
			sb->checking = 0;
		} else {
			LOG_DEBUG("getaddrinfo detected: %s", pp4->question[0].domain);
			qc4->score_board_id = hashid;
			qc6->score_board_id = hashid;
			sb->checking = 1;
			update_preference(sb, qc4, qc4->preference);
			update_preference(sb, qc6, qc6->preference);

			struct dns_resource *res;
			pp4 = &qc4->parser;
			if (qc4->nat64_pref < qc6->preference &&
					!strcmp(pp4->question[0].domain, pp6->question[0].domain)) {
				update_preference(sb, qc6, qc4->nat64_pref);
				dns_parser_copy(pp6, pp4);
				pp6->head.ident = sb->ipv6_offset;
				pp6->question[0].type = NSTYPE_AAAA;
	
				uint32_t ipv4 = 0;
				for (i = 0; i < pp6->head.answer; i++) {
					res = &pp6->answer[i];
					if (res->type == NSTYPE_A) {
						res->type = NSTYPE_AAAA;
						memcpy(&ipv4, res->value, 4);
						inet_pton(AF_INET6, getenv("NAT64_PREFIX"), res->value);
						memcpy(pp6->answer[i].value + 12, &ipv4, 4);
					}
				}
			}
		}
	}

	return 0;
}

struct dns_soa {
	const char *nameserver;
	const char *email;
};

static int dump_resource(const char *title, struct dns_resource *res)
{
	
	       if (res->type == NSTYPE_TXT) {
			LOG_DEBUG("%s %s TXT", title, res->domain);
	} else if (res->type == NSTYPE_A) {
			LOG_DEBUG("%s %s A %s", title, res->domain, inet_ntoa(*(struct in_addr *)res->value));
	} else if (res->type == NSTYPE_NS) {
			LOG_DEBUG("%s %s NS %s", title, res->domain, *(const char **)res->value);
	} else if (res->type == NSTYPE_SRV) {
			LOG_DEBUG("%s %s SRV %p", title, res->domain, *(const char **)res->value);
	} else if (res->type == NSTYPE_SOA) {
			LOG_DEBUG("%s %s SOA %s", title, res->domain, *(const char **)res->value);
	} else if (res->type == NSTYPE_AAAA) {
			LOG_DEBUG("%s %s AAAA %s", title, res->domain, ntop6(res->value));
	} else if (res->type == NSTYPE_CNAME) {
			LOG_DEBUG("%s %s CNAME %s", title, res->domain, *(const char **)res->value);
	} else {
			LOG_DEBUG("%s %s UNKOWN %d", title, res->domain, res->type);
	}

	return 0;
}


static int setup_route(const void* ip, int family)
{
	uint64_t val = 0;
	subnet_t *subnet = NULL;
	char sTarget[128], sNetwork[128];


	inet_ntop(family, ip, sTarget, sizeof(sTarget));
	if (family == AF_INET6) {
		val = htonll(*(uint64_t *)ip);
		subnet = lookupRoute6(val);
	} else if (family == AF_INET) {
		val = htonll(*(uint64_t *)ip) & 0xffffffff00000000ull;
		subnet = lookupRoute4(val);
	}

	if (subnet != 0 && subnet->flags == 0) {
		char sCmd[1024];
		uint64_t network = htonll(subnet->network);

		inet_ntop(family, &network, sNetwork, sizeof(sNetwork));
		fprintf(stderr, "ACTIVE network: %s/%d by %s\n", sNetwork, subnet->prefixlen, sTarget);
		subnet->flags = 1;

		if (family == AF_INET) {
			sprintf(sCmd, "ipset add ipsec %s/%d", sNetwork, subnet->prefixlen);
			fprintf(stderr, "CMD=%s\n", sCmd);
			system(sCmd);
		} else {
			sprintf(sCmd, "ip -6 route add %s/%d dev tun0 mtu 1400 table 100", sNetwork, subnet->prefixlen);
			fprintf(stderr, "CMD=%s\n", sCmd);
			system(sCmd);
		}

		return 0;
	}

	return 0;
}

int update_preference(struct dns_score_board *sb, struct dns_query_context *qc, int preference)
{
	assert(qc);
	assert(preference > 0);

	if (preference <= qc->preference) {
		qc->preference = preference;
		qc->updated = 1;
	}

	if (sb == NULL)
		return 0;

	if (preference <= sb->preference) {
		sb->preference = preference;
		sb->updated = 1;
	}

    assert(qc->preference >= sb->preference);
	return 0;
}

int do_dns_backward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
	struct dns_parser p0;
	struct dns_parser *pp;
	struct dns_resource *res;

	pp = dns_parse(&p0, buf, count);
	if (pp == NULL || p0.head.question == 0) {
		LOG_DEBUG("do_dns_backward parse failure: %s", ntop6(from->sin6_addr));
		return 0;
	}

	if (~p0.head.flags & 0x8000) {
		LOG_DEBUG("FROM: %s this is not response", ntop6(from->sin6_addr));
		return -1;
	}

	int i, found = 0, nat64_pref = 100;
	int offset = (p0.head.ident & 0xfff);
	struct dns_query_context *qc = &_orig_list[offset];

	pp = &qc->parser;

	LOG_DEBUG("record: %s %d %s %x", ntop6(from->sin6_addr), p0.head.answer, p0.question[0].domain, p0.question[0].type);

	const char *suffixes = strstr(p0.question[0].domain, ".oil.cootail.com");

    size_t domainlen = strlen(pp->question[0].domain);
	if (strncmp(p0.question[0].domain, pp->question[0].domain, domainlen)) {
		LOG_DEBUG("reponse out of day: %s %s type=%d %s", ntop6(qc->from), pp->question[0].domain, p0.question[0].type, p0.question[0].domain);
		return 0;
	}

	if (p0.question[0].type != NSTYPE_AAAA && p0.question[0].type != NSTYPE_A) {
		LOG_DEBUG("skip domain: %s %s type=%d", ntop6(qc->from), pp->question[0].domain, p0.question[0].type);
		dns_sendto(ctx->sockfd, &p0, &qc->from, sizeof(qc->from));
		return 0;
	}

	if (suffixes == NULL && strcmp(pp->question[0].domain, p0.question[0].domain)) {
		LOG_DEBUG("skip domain: %s %s %s type=%d", ntop6(qc->from), pp->question[0].domain, p0.question[0].domain, p0.question[0].type);
		return 0;
	}

	struct dns_score_board *sb = NULL;
	if (qc->score_board_id != -1) {
		sb = &_hash_src[qc->score_board_id];

		struct dns_query_context *qc4, *qc6;
		qc4 = &_orig_list[sb->ipv4_offset & 0xfff];
		qc6 = &_orig_list[sb->ipv6_offset & 0xfff];

		sb->updated = 0;
		if (sb->ipv4_offset != p0.head.ident
				&& sb->ipv6_offset != p0.head.ident) {
			sb = NULL;
		} else if (!sb->checking || qc4->score_board_id != qc6->score_board_id) {
			LOG_DEBUG("checking %d qc4_score_board_id %x qc6_score_board_id %x",
					sb->checking, qc4->score_board_id, qc6->score_board_id);
			sb = NULL;
		} else {
			int type = p0.question[0].type;
			int ipv4 = sb->ipv4_offset == p0.head.ident && type == NSTYPE_A;
			int ipv6 = sb->ipv6_offset == p0.head.ident && type == NSTYPE_AAAA;
			assert(ipv4 || ipv6 || suffixes);
		}

	}

	qc->updated = 0;
	if (suffixes && strcmp(suffixes, ".oil.cootail.com") == 0) {
		if (!strcmp(p0.question[0].domain, pp->question[0].domain)) {
			LOG_DEBUG("skip fake domain: %s %s", ntop6(qc->from), pp->question[0].domain);
			dns_sendto(ctx->sockfd, &p0, &qc->from, sizeof(qc->from));
			return 0;
		}

		if (pp->head.answer < 0) {
			LOG_DEBUG("something wrong: %s", ntop6(qc->from), pp->question[0].domain);
			assert(0);
			return 0;
		}

		char buf[256];
		uint32_t type = 0;
		for (i = 0; i < p0.head.answer; i++) {
			res = &p0.answer[i];
			if (res->type == NSTYPE_A) {
				memcpy(&type, res->value, 4);
				break;
			}
		}

		dns_parser_copy(&p0, pp);
		memcpy(p0.answer[0].value, qc->oil_addr, 16);
		p0.answer[0].domain = p0.question[0].domain;
		p0.answer[0].type  = p0.question[0].type;
		p0.answer[0].klass = NSCLASS_INET;
		p0.answer[0].ttl = 3600;
		p0.head.answer = 0;

		if (type == 0x7f7f7f7f) {
			p0.head.answer = 1;
		} else {
			qc->flags |= FLAG_BLOCK_IPV4;
		}

		from->sin6_addr =  ctx->dnslocal->sin6_addr;
		LOG_DEBUG("oil detect finish: %x %s\n", type, pp->question[0].domain);
	} else if (ctx->dnsremote != NULL && p0.head.answer == 1 &&
			IN6_ARE_ADDR_EQUAL(&from->sin6_addr, &ctx->dnslocal->sin6_addr)) {
		uint64_t val;
		subnet_t *subnet = NULL;
		int preference = 100;
		char temp[256];

		res = &p0.answer[0];
		val = htonll(*(uint64_t *)res->value);
		memcpy(qc->oil_addr, res->value, 16);

		if (res->type == NSTYPE_A) {
			subnet = lookupRoute4(val);
			preference =  subnet? PREFERENCE_NON_LOCAL_IPV4: PREFERENCE_LOCAL_IPV4;
			nat64_pref =  subnet? PREFERENCE_NON_LOCAL_NAT64: PREFERENCE_LOCAL_NAT64;
		} else if (res->type == NSTYPE_AAAA) {
			subnet = lookupRoute6(val);
			preference =  subnet? PREFERENCE_NON_LOCAL_IPV6: PREFERENCE_LOCAL_IPV6;
		}

		preference = MIN(preference, nat64_pref);
		if ((sb && preference <= sb->preference) || (!sb && preference <= qc->preference)) {
			snprintf(temp, sizeof(temp), "%s.oil.cootail.com", p0.question[0].domain);
			LOG_DEBUG("start oil detect %s %x %x %x %s", temp, p0.head.ident, pp->head.ident, p0.head.flags, temp);
			memset(&p0, 0, sizeof(p0));

			p0.head.flags |= NSFLAG_RD;
			p0.head.ident  = pp->head.ident;
			p0.head.question  = 1;
			p0.question[0].domain = add_domain(&p0, temp);
			p0.question[0].klass = NSCLASS_INET;
			p0.question[0].type = NSTYPE_A;

			dns_sendto(ctx->outfd, &p0, ctx->dnslocal, ctx->dnslen1);
			return 0;
		}

		LOG_DEBUG("ignore oil detect %s %x %x %x", p0.question[0].domain, p0.head.ident, pp->head.ident, p0.head.flags);
		p0.head.answer  = 0;
		nat64_pref = 100;
	}

	if (IN6_ARE_ADDR_EQUAL(&from->sin6_addr, &ctx->dnslocal->sin6_addr) && ctx->dnsremote) {
		uint64_t val;
		subnet_t *subnet = 0;

		for (i = 0; i < p0.head.answer; i++) {
			res = &p0.answer[i];

			val = htonll(*(uint64_t *)res->value);
			if (res->type == NSTYPE_A) {
				subnet = lookupRoute4(val);
				update_preference(sb, qc, subnet? PREFERENCE_NON_LOCAL_IPV4: PREFERENCE_LOCAL_IPV4);
				nat64_pref = subnet? PREFERENCE_NON_LOCAL_NAT64: PREFERENCE_LOCAL_NAT64;
			} else if (res->type == NSTYPE_AAAA) {
				subnet = lookupRoute6(val);
				update_preference(sb, qc, subnet? PREFERENCE_NON_LOCAL_IPV6: PREFERENCE_LOCAL_IPV6);
			}
		}

		qc->flags |= FLAG_LOCAL;
	}

	if (ctx->dnsremote && IN6_ARE_ADDR_EQUAL(&from->sin6_addr, &ctx->dnsremote->sin6_addr)) {
		uint64_t val;
		subnet_t *subnet = 0;

		for (i = 0; i < p0.head.answer; i++) {
			res = &p0.answer[i];

			val = htonll(*(uint64_t *)res->value);
			if (res->type == NSTYPE_A) {
				subnet = lookupRoute4(val);
				update_preference(sb, qc, subnet? PREFERENCE_REMOTE_IPV4: PREFERENCE_NON_REMOTE_IPV4);
				nat64_pref = subnet? PREFERENCE_REMOTE_NAT64: PREFERENCE_NON_REMOTE_NAT64;
			} else if (res->type == NSTYPE_AAAA) {
				subnet = lookupRoute6(val);
				update_preference(sb, qc, subnet? PREFERENCE_REMOTE_IPV6: PREFERENCE_NON_LOCAL_IPV6);
			}
		}

		qc->flags |= FLAG_REMOTE;
	}

check_finish:

	if (sb != NULL && !sb->updated) {
		LOG_DEBUG("ignore this response %s type:%d answer:%d", p0.question[0].domain, p0.question[0].type, p0.head.answer);
	}

	if (sb != NULL) {
		struct dns_parser *pp4, *pp6;
		struct dns_query_context *qc4, *qc6;
		qc4 = &_orig_list[sb->ipv4_offset & 0xfff];
		qc6 = &_orig_list[sb->ipv6_offset & 0xfff];

		pp6 = &qc6->parser;
		pp4 = &qc4->parser;
        assert(qc4->score_board_id == qc6->score_board_id);
		assert(suffixes || !strcasecmp(pp4->question[0].domain, pp6->question[0].domain));

		assert(sb->updated <= qc->updated);
		if (qc->updated) {
			assert(!sb || sb->preference <= qc->preference);  
			dns_parser_copy(pp, &p0);
		}

		if (nat64_pref < qc6->preference) {
			pp6 = &qc6->parser;
			pp4 = &qc4->parser;
			for (i = 0; i < p0.head.answer; i++) {
				pp6->answer[i] = p0.answer[i];
				if (p0.question[0].domain == p0.answer[i].domain) {
					pp6->answer[i].domain = pp6->question[0].domain;
				} else {
					pp6->answer[i].domain = add_domain(pp6, p0.answer[i].domain);
				}

				struct dns_cname *cname = pp6->answer[i].value;
				if (pp6->answer[i].type == NSTYPE_CNAME) {
					cname->alias = add_domain(pp6, cname->alias);
				} else {
					pp6->answer[i].type = NSTYPE_AAAA;
					inet_pton(AF_INET6, getenv("NAT64_PREFIX"), cname);
					memcpy(pp6->answer[i].value + 12, p0.answer[i].value, 4);
				}
			}
			LOG_DEBUG("update %s nat64 answer: %d pref64:%d", p0.question[0].domain, p0.head.answer, nat64_pref);
			pp6->head.answer = p0.head.answer;
			update_preference(sb, qc6, nat64_pref);
		}

		LOG_DEBUG("pref:%d flags4:%x flags6:%x pref4:%d pref6:%d ", sb->preference, qc4->flags, qc6->flags, qc4->preference, qc6->preference);
		if (sb->preference == MIN(PREFERENCE_LOCAL_IPV4, PREFERENCE_LOCAL_IPV6) ||
				((qc4->flags & FLAG_ALL) == FLAG_ALL && (qc6->flags & FLAG_ALL) == FLAG_ALL)) {

			if (qc4->preference == sb->preference || (qc4->flags & FLAG_ALL) == FLAG_ALL) {
				pp = &qc4->parser;
				pp->head.flags |= NSFLAG_QR;
				pp->head.answer = (!(qc4->flags & FLAG_BLOCK_IPV4) && (qc4->preference <= sb->preference))? pp->head.answer: 0;
				LOG_DEBUG("ipv4: d=%s n=%d", pp->question[0].domain, pp->head.answer);
				dns_sendto(ctx->sockfd, pp, &qc4->from, sizeof(qc4->from));
			}

			if (qc6->preference == sb->preference || (qc6->flags & FLAG_ALL) == FLAG_ALL) {
				pp = &qc6->parser;
				pp->head.flags |= NSFLAG_QR;
				pp->head.answer = (qc6->preference <= sb->preference)? pp->head.answer: 0;
				LOG_DEBUG("ipv6: d=%s n=%d", pp->question[0].domain, pp->head.answer);
				dns_sendto(ctx->sockfd, pp, &qc6->from, sizeof(qc6->from));
			}
		}

		return 0;
	}

	pp = &qc->parser;
	if (qc->updated) {
		pp = &p0;
	}

	if ((qc->flags & FLAG_ALL) == FLAG_ALL || (qc->preference == MIN(PREFERENCE_LOCAL_IPV4, PREFERENCE_LOCAL_IPV6))) {
		LOG_DEBUG("dns_sendto %s %s:%d d=%s n=%d type:%d pref:%d", pp->question[0].type==NSTYPE_AAAA?"ipv6":"ipv4", ntop6(qc->from.sin6_addr),
				htons(qc->from.sin6_port), pp->question[0].domain, pp->head.answer, pp->question[0].type, qc->preference);
		pp->head.flags |= NSFLAG_QR;

		int save = pp->head.answer;
		if (qc->flags & FLAG_BLOCK_IPV4 && pp->question[0].type == NSTYPE_A)
			pp->head.answer = 0;

		dns_sendto(ctx->sockfd, pp, &qc->from, sizeof(qc->from));
		pp->head.answer = save;
		pp = NULL;
	}

	if ((nat64_pref <= qc->nat64_pref) && (qc->updated || pp == NULL)) {
		dns_parser_copy(&qc->parser, &p0);
		qc->nat64_pref = nat64_pref;
	} else if (qc->updated) {
		dns_parser_copy(&qc->parser, &p0);
	} else {
		assert(nat64_pref >= qc->nat64_pref);
		assert(!qc->updated || pp == NULL);
	}

	return 0;
}

#define get_score_id(ifname) if_nametoindex(ifname)

int main(int argc, char *argv[])
{
	int retval;
	int outfd, sockfd;
	struct sockaddr_in6 myaddr;
	struct sockaddr * paddr = (struct sockaddr *)&myaddr;

	struct sockaddr_in6 myaddr6;
	struct sockaddr * paddr6 = (struct sockaddr *)&myaddr6;

	outfd = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(outfd != -1);

	myaddr.sin6_family = AF_INET6;
	myaddr.sin6_port   = 0;
	myaddr.sin6_addr   = in6addr_any;
	retval = bind(outfd, paddr, sizeof(myaddr));
	assert(retval != -1);

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(sockfd != -1);

	myaddr6.sin6_family = AF_INET6;
	myaddr6.sin6_port   = htons(53);
	myaddr6.sin6_addr   = in6addr_loopback;
#if 0
	myaddr6.sin6_addr   = in6addr_any;
#endif
	setenv("NAT64_PREFIX", _nat64_prefix, 0);
	setenv("BINDLOCAL", "::ffff:127.0.0.111", 0);

	char _dummy[256], *ifp;
	strcpy(_dummy, getenv("BINDLOCAL"));
	if (NULL != (ifp = strchr(_dummy, '%'))) {
		*ifp ++ = 0;
		myaddr6.sin6_scope_id = get_score_id(ifp);
		inet_pton(AF_INET6, _dummy, &myaddr6.sin6_addr);
	} else {
		myaddr6.sin6_scope_id = 0;
		inet_pton(AF_INET6, _dummy, &myaddr6.sin6_addr);
	}

	retval = bind(sockfd, paddr6, sizeof(myaddr6));
	assert(retval != -1);

	int count;
	char buf[2048];
	fd_set readfds = {};
	socklen_t addrl = 0;
	struct sockaddr_in6 dnslocal;
	struct sockaddr_in6 dnsremote;

	struct dns_context c0 = {
		.outfd = outfd,
		.sockfd = sockfd,
		.dnslen  = sizeof(dnslocal),
		.dnslen1  = sizeof(dnsremote),
	};

	setenv("NAMESERVER", "::ffff:8.8.8.8", 0);

	dnslocal.sin6_family = AF_INET6;
	dnslocal.sin6_port   = htons(53);
	inet_pton(AF_INET6, getenv("NAMESERVER"), &dnslocal.sin6_addr);
	c0.dnslocal = (struct sockaddr *)&dnslocal;

	dnsremote.sin6_family = AF_INET6;
	dnsremote.sin6_port   = htons(53);

	c0.dnsremote = NULL;
	if (getenv("REMOTESERVER") != NULL) {
	    inet_pton(AF_INET6, getenv("REMOTESERVER"), &dnsremote.sin6_addr);
	    if (!IN6_ARE_ADDR_EQUAL(&dnsremote.sin6_addr, &dnslocal.sin6_addr))
		c0.dnsremote = (struct sockaddr *)&dnsremote;
	}

	const struct sockaddr_in6 *inp = (const struct sockaddr_in6 *)&dnslocal;
	LOG_DEBUG("dns_build bytes %d %d %d %s", 0, inp->sin6_family, htons(inp->sin6_port), ntop6(inp->sin6_addr));

	const char *ipv4only = "ipv4only.arpa";
	for (int i = 0; i < ARRAY_SIZE(_predefine_resource_record); i++) {

		struct dns_resource * res = &_predefine_resource_record[i];
		if ((res->type == NSTYPE_AAAA) && strcasecmp(res->domain, ipv4only) == 0) {
			inet_pton(AF_INET6, getenv("NAT64_PREFIX"), res->value);
			break;
		}
	}

	do {
		FD_ZERO(&readfds);
		FD_SET(outfd, &readfds);
		FD_SET(sockfd, &readfds);

		retval = select(sockfd + 1, &readfds, 0, 0, 0);
		if (retval == -1) {
			LOG_DEBUG("select failure: %s", strerror(errno));
			break;
		}

		if (FD_ISSET(sockfd, &readfds)) {
			addrl = sizeof(myaddr6);
			count = recvfrom(sockfd, buf, sizeof(buf), 0, paddr6, &addrl);
			count > 0 || LOG_DEBUG("sockfd is readable");
			assert(count > 0);
			do_dns_forward(&c0, buf, count, &myaddr6);
			continue;
		}

		if (FD_ISSET(outfd, &readfds)) {
			addrl = sizeof(myaddr);
			count = recvfrom(outfd, buf, sizeof(buf), 0, paddr, &addrl);
			count > 0 || LOG_DEBUG("outfd is readable");
			assert(count > 0);
			do_dns_backward(&c0, buf, count, &myaddr);
		}

	} while (retval >= 0);

	close(sockfd);
	close(outfd);

	return 0;
}
