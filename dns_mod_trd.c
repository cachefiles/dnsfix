#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "dnsproto.h"
#include "subnet_api.h"

#define LOG_DEBUG(fmt, args...) fprintf(stderr, fmt"\n", ##args)

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
		.ttl = 360,
		.len = 4,
		.flags = 0,
		.domain = "cdn.855899.xyz",
		.value = {54, 192, 17, 115}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 360,
		.len = 4,
		.flags = 0,
		.domain = "cdn.855899.xyz",
		.value = {172, 67, 165, 145}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "mtalk.oogleg.moc.cootail.com",
		.value = {10, 0, 3, 1}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "mtalk.google.com",
		.value = {10, 0, 3, 1}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt1-mtalk.google.com",
		.value = {110, 42, 145, 164}},
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

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


#define NSCLASS_INET 0x01
#define NSFLAG_RD    0x0100

struct dns_context {
	int outfd;
	int sockfd;

	socklen_t dnslen;
	struct sockaddr_in6 *dnsaddr;
};

struct dns_query_context {
	struct sockaddr_in6 from;
	struct dns_parser parser;
};

static struct dns_query_context _orig_list[0xfff + 1];
static struct dns_query_context _orig_list_ipv4[0xfff + 1];
static struct dns_query_context _orig_list_ipv6[0xfff + 1];

static int dns_parser_copy(struct dns_parser *dst, struct dns_parser *src)
{
    static uint8_t _qc_hold[2048];
    size_t len  = dns_build(src, _qc_hold, sizeof(_qc_hold));
    return dns_parse(dst, _qc_hold, len) == NULL;
}

static int dns_contains(const char *domain)
{
	int i;
	const char *_tld1[] = {
		"ten.", "ude.", "oc.", "gro.", "moc.", "vog.", NULL
	};
	const char *_tld0[] = {
		"net.", "edu.", "co.", "org.", "com.", "gov.", NULL
	};

	for (i = 0; _tld0[i]; i++) {
		if (strncasecmp(domain, _tld0[i], 4) == 0) {
			return 1;
		}
	}

	if (strncasecmp(domain, "co.", 3) == 0) {
		return 1;
	}

	return 0;
}

static int dns_rewrap(struct dns_parser *p1)
{
	int num = p1->head.question;
	const char *domain = NULL;
	struct dns_question *que, *que1;

	que = &p1->question[0];
	que1 = &p1->question[1];

	int ndot = 0;
	char *limit, *optp;
	char *dots[8] = {}, title[256];

	LOG_DEBUG("suffixes: %s %d", que->domain, que->type);

	*que1 = *que;

	optp = title;
	dots[ndot & 0x7] = title;
	for (domain = que->domain; *domain; domain++) {
		switch(*domain) {
			case '.':
				if (optp > dots[ndot & 0x7]) ndot++;
				*optp++ = *domain;
				dots[ndot & 0x7] = optp;
				break;

			default:
				*optp++ = *domain;
				break;
		}
	}

	*optp = 0;
	if (optp > dots[ndot & 0x7]) ndot++;

	if (ndot < 2) {
		return 0;
	}

	assert(ndot >= 2);
	if (!strcasecmp(dots[(ndot - 2) & 0x7], "cootail.com")) {
		return 0;
	}

	strcat(optp, ".cootail.com");

	limit = optp - 1;
	ndot--;
	optp = dots[ndot & 0x7];

	if (ndot < 1) {
		LOG_DEBUG("dns_unwrap warning %s XX", title);
		que1->domain = add_domain(p1, title);
		return 0;
	}

	int cc = 0;
	if (optp + 1 == limit) {
		limit = dots[ndot & 0x7] -2;
		ndot--;
		optp = dots[ndot & 0x7];
		cc = 1;
	}

	if (cc == 0 || dns_contains(optp)) {
		for (; *optp && optp < limit; optp++) {
			char t = *optp;
			*optp = *limit;
			*limit-- = t;
		}

		if (ndot < 1) {
			LOG_DEBUG("dns_unwrap ork %s", title);
			que1->domain = add_domain(p1, title);
			return 0;
		}

		limit = dots[ndot & 0x7] -2;
		ndot--;
		optp = dots[ndot & 0x7];
	}

#if 0
	if (ndot < 1) {
		LOG_DEBUG("dns_unwrap warning %s", title);
		que1->domain = add_domain(p1, title);
		return 0;
	}
#endif

	char t = *optp;
	memmove(optp, optp + 1, limit - optp);
	*limit = t;

	LOG_DEBUG("dns_unwrap title=%s cc=%d", title, cc);
	if (que1->type == NSTYPE_PTR) {
		que1->domain = add_domain(p1, que->domain);
		return 0;
	}

	que1->domain = add_domain(p1, title);
	return 0;
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
		dns_sendto(ctx->sockfd, &p0, (struct sockaddr *)from, sizeof(*from));
		return 0;
	}
	
	int retval = 0;
	int offset = (p0.head.ident & 0xfff);

	struct dns_parser *p1 = NULL;
	struct dns_query_context *qc = &_orig_list[offset];
	if (p0.question[0].type == NSTYPE_AAAA) {
		qc = &_orig_list_ipv6[offset];
	} else if (p0.question[0].type == NSTYPE_A) {
		qc = &_orig_list_ipv4[offset];
	}

	memset(qc, 0, sizeof(*qc));
	qc->from = *from;

	dns_parser_copy(&qc->parser, &p0);
	p1 = &qc->parser;

	if (p0.question[0].type == NSTYPE_A
			&& !!getenv("REFUSED_IPV4")) {
		p0.head.flags |= NSFLAG_QR;
		p0.head.flags &= ~NSFLAG_RCODE;
		p0.head.flags |= RCODE_NOTAUTH;
		dns_sendto(ctx->sockfd, &p0, (struct sockaddr *)from, sizeof(*from));
		return -1;
	}

	if (getenv("FORWARD")) {
		p1->question[1] = p1->question[0];
		p0.question[0] = p1->question[1];
	} else if (dns_rewrap(p1) == -1) {
		LOG_DEBUG("FROM: %s this is not good", p1->question[0].domain);
		return -1;
	}

	if (p0.question[0].type != NSTYPE_PTR) {
		p0.question[0] = p1->question[1];
	}

	p0.head.flags |= NSFLAG_RD;
	retval = dns_sendto(ctx->outfd, &p0, (struct sockaddr *)ctx->dnsaddr, ctx->dnslen);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure: %s target %p", strerror(errno), ctx->dnsaddr);
		return 0;
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

int do_dns_backward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
	struct dns_parser p0;
	struct dns_parser *pp;
	struct dns_resource *res;

	pp = dns_parse(&p0, buf, count);
	if (pp == NULL) {
		LOG_DEBUG("do_dns_backward parse failure");
		return 0;
	}

	if (~p0.head.flags & 0x8000) {
		LOG_DEBUG("FROM: %s this is not response", ntop6(from->sin6_addr));
		return -1;
	}
	
	int i, found = 0;
	int offset = (p0.head.ident & 0xfff);
	struct dns_query_context *qc = &_orig_list[offset];
	if (p0.question[0].type == NSTYPE_AAAA) {
		qc = &_orig_list_ipv6[offset];
	} else if (p0.question[0].type == NSTYPE_A) {
		qc = &_orig_list_ipv4[offset];
	}

	pp = &qc->parser;
	int test = (p0.question[0].type != NSTYPE_PTR);
	if (strcmp(p0.question[0].domain, pp->question[test].domain) || p0.question[0].type != pp->question[0].type) {
		LOG_DEBUG("drop since name no expected: %s:%d %s:%d", p0.question[0].domain, p0.question[0].type, pp->question[test].domain, pp->question[0].type);
		return 0;
	}
	p0.question[0] = pp->question[0];

	for (i = 0; i < p0.head.answer; i++) {
		res = &p0.answer[i];
		if (res->type == NSTYPE_CNAME) {
			const char *alias = *(const char **)res->value;
			LOG_DEBUG("domain %s %s %s %s", res->domain, pp->question[0].domain, pp->question[1].domain, alias);
			if (strcasecmp(res->domain, pp->question[1].domain) == 0 &&
					strcasecmp(alias, pp->question[0].domain) == 0) {
				memmove(p0.answer + i, p0.answer + i + 1, sizeof(p0.answer[0]) * (p0.head.answer - i -1));
				p0.head.answer = p0.head.answer - 1;
				found = 1;
				break;
			}
		} else {
			if (strcasecmp(res->domain, pp->question[1].domain) == 0) {
				res->domain = pp->question[0].domain;
			}
		}
	}

#if 0
	if (found == 0) {
		memmove(p0.answer + 1, p0.answer, sizeof(p0.answer[0]) * p0.head.answer);
		res = &p0.answer[0];
		res->domain = add_domain(&p0, qc->parser.question[0].domain);
		res->type   = NSTYPE_CNAME;
		res->klass  = NSCLASS_INET;
		res->ttl    = 3600;
		*(const char **)res->value  = add_domain(&p0, qc->parser.question[1].domain);
		p0.head.answer++;
	}
#endif

#if 0
	for (i = 0; i < p0.head.answer; i++) {
		res = &p0.answer[i];
		if (res->type == NSTYPE_A) {
			setup_route(res->value, AF_INET);
		} else if (res->type == NSTYPE_AAAA) {
			setup_route(res->value, AF_INET6);
		}
	}
#endif

	// p0.head.addon = 0;
	char buf0[256];
	p0.head.ident = qc->parser.head.ident;
	LOG_DEBUG("dns_sendto %s:%d", inet_ntop(AF_INET6, &qc->from.sin6_addr, buf0, sizeof(buf0)), htons(qc->from.sin6_port));
	dns_sendto(ctx->sockfd, &p0, (struct sockaddr *)&qc->from, sizeof(qc->from));

	return 0;
}

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
	setenv("BINDLOCAL", "::ffff:127.0.0.111", 0);
	inet_pton(AF_INET6, getenv("BINDLOCAL"), &myaddr6.sin6_addr);
	retval = bind(sockfd, paddr6, sizeof(myaddr6));
	assert(retval != -1);

	int count;
	char buf[2048];
	fd_set readfds = {};
	socklen_t addrl = 0;
	struct sockaddr_in6 dnsaddr;

	struct dns_context c0 = {
		.outfd = outfd,
		.sockfd = sockfd,
		.dnslen  = sizeof(dnsaddr),
	};

	setenv("NAMESERVER", "::ffff:8.8.8.8", 0);

	dnsaddr.sin6_family = AF_INET6;
	dnsaddr.sin6_port   = htons(53);
	inet_pton(AF_INET6, getenv("NAMESERVER"), &dnsaddr.sin6_addr);
	// dnsaddr.sin_addr.s_addr = inet_addr("223.5.5.5");

	c0.dnsaddr = (struct sockaddr_in6 *)&dnsaddr;
	LOG_DEBUG("nsaddr %p pointer %p %d", c0.dnsaddr, &dnsaddr, htons(dnsaddr.sin6_port));

	const struct sockaddr_in6 *inp = (const struct sockaddr_in6 *)&dnsaddr;
	LOG_DEBUG("dns_build bytes %d %d %d %s", 0, inp->sin6_family, htons(inp->sin6_port), ntop6(inp->sin6_addr));

	do {
		FD_ZERO(&readfds);
		FD_SET(outfd, &readfds);
		FD_SET(sockfd, &readfds);

		retval = select(sockfd + 1, &readfds, 0, 0, 0);
		if (retval == -1) {
			LOG_DEBUG("select failure: %s", strerror(errno));
			break;
		}

		if (FD_ISSET(outfd, &readfds)) {
			addrl = sizeof(myaddr);
			count = recvfrom(outfd, buf, sizeof(buf), 0, paddr, &addrl);
			count > 0 || LOG_DEBUG("outfd is readable");
			assert(count > 0);
			do_dns_backward(&c0, buf, count, &myaddr);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			addrl = sizeof(myaddr6);
			count = recvfrom(sockfd, buf, sizeof(buf), 0, paddr6, &addrl);
			count > 0 || LOG_DEBUG("sockfd is readable");
			assert(count > 0);
			do_dns_forward(&c0, buf, count, &myaddr6);
		}

	} while (retval >= 0);

	close(sockfd);
	close(outfd);

	return 0;
}
