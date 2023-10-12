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

#define NSCLASS_INET 0x01
#define NSFLAG_RD    0x0100

struct dns_context {
	int outfd;
	int sockfd;

	socklen_t dnslen;
	struct sockaddr *dnsaddr;
};

struct dns_query_context {
	int is_china_domain;
	int is_nonchina_domain;
	struct sockaddr_in6 from;
	struct dns_parser parser;
};

static struct dns_query_context _orig_list[0xfff];

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
		if (strncmp(domain, _tld0[i], 4) == 0) {
			return 1;
		}
	}

	if (strncmp(domain, "oc.", 3) == 0) {
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
			*optp++ = *limit;
			*limit-- = t;
		}

		if (ndot < 1) {
			LOG_DEBUG("dns_unwrap ork %s", title);
			que1->domain = add_domain(p1, title);
			return 0;
		}

		LOG_DEBUG("xx dns_unwrap %s %d", title, cc);
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
	LOG_DEBUG("zz dns_unwrap %s %c %s", title, t, optp);
	memmove(optp, optp + 1, limit - optp);
	*limit = t;

	LOG_DEBUG("zz dns_unwrap title=%s cc=%d", title, cc);
	que1->domain = add_domain(p1, title);
	return 0;
}

static int dns_sendto(int outfd, struct dns_parser *parser, const struct sockaddr *to, size_t tolen)
{
	ssize_t len;
	uint8_t _hold[2048];

	len = dns_build(parser, _hold, sizeof(_hold));

	const struct sockaddr_in *inp = (const struct sockaddr_in *)to;
	LOG_DEBUG("dns_build bytes %d %d %d %s", len, inp->sin_family, htons(inp->sin_port), inet_ntoa(inp->sin_addr));
	if (len != -1)
		len = sendto(outfd, _hold, len, 0, to, tolen);
	else
		LOG_DEBUG("dns_build %d", len);

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
	
	int retval = 0;
	int offset = (p0.head.ident & 0xfff);

	struct dns_parser *p1 = NULL;
	struct dns_query_context *qc = &_orig_list[offset];
	memset(qc, 0, sizeof(*qc));
	qc->from = *from;

	dns_parser_copy(&qc->parser, &p0);
	p1 = &qc->parser;
	if (dns_rewrap(p1) == -1) {
		LOG_DEBUG("FROM: %s this is not good", p1->question[0].domain);
		return -1;
	}
	p0.question[0] = p1->question[1];

	int save_opt = p0.head.addon;
	p0.head.addon = 0;
	p0.head.flags |= NSFLAG_RD;
	retval = dns_sendto(ctx->outfd, &p0, ctx->dnsaddr, ctx->dnslen);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnsaddr);
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
	
	char inet6[256];
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
			LOG_DEBUG("%s %s AAAA %s", title, res->domain, inet_ntop(AF_INET6, res->value, inet6, sizeof(inet6)));
	} else if (res->type == NSTYPE_CNAME) {
			LOG_DEBUG("%s %s CNAME %s", title, res->domain, *(const char **)res->value);
	} else {
			LOG_DEBUG("%s %s UNKOWN %d", title, res->domain, res->type);
	}

	return 0;
}


static int setup_route(uint32_t ipv4)
{
	char sTarget[128], sNetwork[128];
	uint32_t target = htonl(ipv4);
	subnet_t *subnet = lookupRoute(target);

	inet_ntop(AF_INET, &ipv4, sTarget, sizeof(sTarget));

	if (subnet != 0 && subnet->flags == 0) {
		unsigned network = htonl(subnet->network);

		inet_ntop(AF_INET, &network, sNetwork, sizeof(sNetwork));
		fprintf(stderr, "ACTIVE network: %s/%d by %s\n", sNetwork, subnet->prefixlen, sTarget);
		subnet->flags = 1;

		char sCmd[1024];
		sprintf(sCmd, "ipset add ipsec %s/%d", sNetwork, subnet->prefixlen);
		fprintf(stderr, "CMD=%s\n", sCmd);
		system(sCmd);
		sprintf(sCmd, "ip route add %s/%d dev tunnel1 mtu 1400 table 20", sNetwork, subnet->prefixlen);
		fprintf(stderr, "CMD=%s\n", sCmd);
		system(sCmd);
		return 0;
	}

	return 0;
}

int do_dns_backward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in *from)
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
		LOG_DEBUG("FROM: %s this is not response", inet_ntoa(from->sin_addr));
		return -1;
	}
	
	int i, found = 0;
	int offset = (p0.head.ident & 0xfff);
	struct dns_query_context *qc = &_orig_list[offset];

	pp = &qc->parser;
	p0.question[0] = pp->question[0];

	for (i = 0; i < p0.head.answer; i++) {
		res = &p0.answer[i];
		if (res->type != NSTYPE_CNAME) {
			continue;
		}

		const char *alias = *(const char **)res->value;
		LOG_DEBUG("domain %s %s %s", res->domain, pp->question[0].domain, pp->question[1].domain);
		if (strcasecmp(res->domain, pp->question[1].domain) == 0 &&
				strcasecmp(alias, pp->question[0].domain) == 0) {
			memmove(p0.answer, p0.answer + 1, sizeof(p0.answer[0]) * (p0.head.answer - i -1));
			p0.head.answer = p0.head.answer - i - 1;
			found = 1;
			break;
		}
	}

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

	for (i = 0; i < p0.head.answer; i++) {
		res = &p0.answer[i];
		if (res->type != NSTYPE_A) {
			continue;
		}
		uint32_t *v4addrp = (uint32_t *)res->value;
		setup_route(htonl(*v4addrp));
	}

	p0.head.addon = 0;
	p0.head.ident = qc->parser.head.ident;
	dns_sendto(ctx->sockfd, &p0, (struct sockaddr *)&qc->from, sizeof(qc->from));

	return 0;
}

int main(int argc, char *argv[])
{
	int retval;
	int outfd, sockfd;
	struct sockaddr_in myaddr;
	struct sockaddr * paddr = (struct sockaddr *)&myaddr;

	struct sockaddr_in6 myaddr6;
	struct sockaddr * paddr6 = (struct sockaddr *)&myaddr6;

	outfd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(outfd != -1);

	myaddr.sin_family = AF_INET;
	myaddr.sin_port   = 0;
	myaddr.sin_addr.s_addr = INADDR_ANY;
	retval = bind(outfd, paddr, sizeof(myaddr));
	assert(retval != -1);

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(sockfd != -1);

	myaddr6.sin6_family = AF_INET6;
	myaddr6.sin6_port   = htons(53);
	myaddr6.sin6_addr   = in6addr_any;
	myaddr6.sin6_addr   = in6addr_loopback;
	inet_pton(AF_INET6, "2409:8a1e:9464:1160:8639:beff:fe67:d576", &myaddr6.sin6_addr);
	retval = bind(sockfd, paddr6, sizeof(myaddr6));
	assert(retval != -1);

	int count;
	char buf[2048];
	fd_set readfds = {};
	socklen_t addrl = 0;
	struct sockaddr_in dnsaddr;

	struct dns_context c0 = {
		.outfd = outfd,
		.sockfd = sockfd,
		.dnslen  = sizeof(dnsaddr),
	};

	setenv("NAMESERVER", "8.8.8.8", 0);

	dnsaddr.sin_family = AF_INET;
	dnsaddr.sin_port   = htons(53);
	dnsaddr.sin_addr.s_addr = inet_addr(getenv("NAMESERVER"));
	// dnsaddr.sin_addr.s_addr = inet_addr("223.5.5.5");

	c0.dnsaddr = (struct sockaddr *)&dnsaddr;
	LOG_DEBUG("nsaddr %p pointer %p %d", c0.dnsaddr, &dnsaddr, htons(dnsaddr.sin_port));

	const struct sockaddr_in *inp = (const struct sockaddr_in *)&dnsaddr;
	LOG_DEBUG("dns_build bytes %d %d %d %s", 0, inp->sin_family, htons(inp->sin_port), inet_ntoa(inp->sin_addr));

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
			LOG_DEBUG("outfd is readable");
			addrl = sizeof(myaddr);
			count = recvfrom(outfd, buf, sizeof(buf), 0, paddr, &addrl);
			assert(count > 0);
			do_dns_backward(&c0, buf, count, &myaddr);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			LOG_DEBUG("sockfd is readable");
			addrl = sizeof(myaddr6);
			count = recvfrom(sockfd, buf, sizeof(buf), 0, paddr6, &addrl);
			assert(count > 0);
			do_dns_forward(&c0, buf, count, &myaddr6);
		}

	} while (retval >= 0);

	close(sockfd);
	close(outfd);

	return 0;
}
