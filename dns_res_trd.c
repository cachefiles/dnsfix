#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <endian.h>
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

struct dns_context {
	int outfd;
	int sockfd;

	socklen_t dnslen;
	struct sockaddr *dnsaddr;
	struct sockaddr *ecsaddr;
};

struct zip_parser {
	char buf[1500];
	int len;
};

struct dns_query_context {
	int is_china_domain;
	int is_nonchina_domain;
	struct sockaddr_in6 from;
	struct zip_parser parser, ecs_parser, def_parser;
};

static struct dns_query_context _orig_list[0x1000];

static int dns_parser_copy(struct dns_parser *dst, struct dns_parser *src)
{
    static uint8_t _qc_hold[2048];
    size_t len  = dns_build(src, _qc_hold, sizeof(_qc_hold));
    return dns_parse(dst, _qc_hold, len) == NULL;
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

// vn he-ipv6 prefix 2001:470:35:639::/56
const static struct subnet_info subnet6_data = {
	0x08, sizeof(subnet6_data), NS_IPV6, 56, 53, {0x20, 0x01, 0x04, 0x70, 0x00, 0x35, 0x06, 0x39}
};

static int contains_subnet(struct dns_parser *p0)
{
	struct dns_resource *res = NULL;
	struct subnet_info *info = NULL;

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
					info = (struct subnet_info *)hold;
					LOG_DEBUG("taglen=%d family=%d", htons(tag0.len), htons(info->family));
					return htons(info->family) == NS_IPV4;
				}
			}
		}
	}

	return 0;
}

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

static int dns_contains(const char *domain)
{
	int i;
	const char *_tld0[] = {
		"ten.", "ude.", "oc.", "gro.", "moc.", "vog.", NULL
	};
	const char *_tld1[] = {
		"net.", "edu.", "co.", "org.", "com.", "gov.", NULL
	};

	(void)_tld1;
	for (i = 0; _tld0[i]; i++) {
		if (strncasecmp(domain, _tld0[i], 4) == 0) {
			return 1;
		}
	}

	if (strncasecmp(domain, "oc.", 3) == 0) {
		return 1;
	}

	if (strncmp(domain, "co.", 3) == 0) {
		return 1;
	}

	return 0;
}

static int dns_unwrap(struct dns_parser *p1)
{
	char *domain = NULL;
	struct dns_question *que, *que1;

	que = &p1->question[0];
	que1 = &p1->question[1];
	*que1 = *que;

	int ndot = 0;
	char *limit, *optp;
	char *dots[8], title[256];

	LOG_DEBUG("suffixes: %s", que->domain);
	if (que->domain == NULL) {
		return -1;
	}

	title[sizeof(title) -1] = 0;
	strncpy(title, que->domain, sizeof(title) -1);

	dots[ndot++] = title;
	for (domain = title; *domain; domain++)
		if (*domain == '.') dots[ndot++&0x7] = domain + 1;

	// mail.oogleg.moc.cooltail.com
	if (ndot < 3) {
		LOG_DEBUG("dns_unwrap failure");
		return -1;
	}

	ndot -= 2;
	dots[ndot & 0x7][-1] = 0;
	LOG_DEBUG("suffixes: %s %s", dots[ndot & 0x7], title);

	assert(ndot > 0);
	limit = dots[ndot & 0x7] -2;
	ndot--;
	optp = dots[ndot & 0x7];

	int cc = 0;
	if (ndot < 1) {
		LOG_DEBUG("dns_unwrap warning %s", title);
		que1->domain = add_domain(p1, title);
		p1->head.question++;
		return 0;
	}

	if (optp + 1 == limit) {
		limit = dots[ndot & 0x7] -2;
		ndot--;
		optp = dots[ndot & 0x7];
		cc = 1;
	}

	if (cc == 0 || dns_contains(optp)) {
		LOG_DEBUG("o %s %s %s", title, optp, limit);
		for (; *optp && optp < limit; optp++) {
			char t = *optp;
			*optp = *limit;
			*limit-- = t;
		}

		LOG_DEBUG("o %s", title);
		if (ndot < 1) {
			LOG_DEBUG("dns_unwrap ork %s", title);
			que1->domain = add_domain(p1, title);
			p1->head.question++;
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
		p1->head.question++;
		return 0;
	}
#endif

	char t = *limit;
	LOG_DEBUG("zz dns_unwrap %s %c %s", title, t, optp);
	memmove(optp + 1, optp, limit - optp);
	*optp = t;

	LOG_DEBUG("zz dns_unwrap %s %d", title, cc);
	que1->domain = add_domain(p1, title);
	p1->head.question++;
	return 0;
}

static int dns_sendto(int outfd, struct dns_parser *parser, const struct sockaddr *to, size_t tolen)
{
	ssize_t len;
	uint8_t _hold[2048];

	len = dns_build(parser, _hold, sizeof(_hold));

	const struct sockaddr_in6 *inp = (const struct sockaddr_in6 *)to;
	LOG_DEBUG("dns_build bytes %ld %d %d %s", len, inp->sin6_family, htons(inp->sin6_port), ntop6(inp->sin6_addr));
	if (len != -1)
		len = sendto(outfd, _hold, len, 0, to, tolen);
	else
		LOG_DEBUG("dns_build %ld", len);

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
	struct dns_parser parser = {};
	struct dns_query_context *qc = &_orig_list[offset];
	memset(qc, 0, sizeof(*qc));
	qc->from = *from;

	dns_parser_copy(&parser, &p0);
	p1 = &parser;
	if (dns_unwrap(p1) == -1) {
        LOG_DEBUG("FROM: %s this is not good", p1->question[0].domain);
		return -1;
	}
	p0.question[0] = p1->question[1];
	qc->parser.len = dns_build(&parser, qc->parser.buf, sizeof(qc->parser.buf));
	assert(qc->parser.len > 0);

	uint8_t optbuf[256];
	add_client_subnet(&p0, optbuf, &subnet4_data);
	
	p0.head.flags |= NSFLAG_RD;
	retval = dns_sendto(ctx->outfd, &p0, ctx->ecsaddr, ctx->dnslen);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure");
		return 0;
	}

	if (p0.head.addon > 0
			&& p0.addon[0].len > 0 
			&& p0.addon[0].type == NSTYPE_OPT)
		p0.addon[0].len = 0;
#if 0
	if (p0.question[0].type == NSTYPE_AAAA)
		add_client_subnet(&p0, optbuf, &subnet6_data);
#endif

	p0.head.ident += 0x1000;
	retval = dns_sendto(ctx->outfd, &p0, ctx->dnsaddr, ctx->dnslen);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnsaddr);
		return 0;
	}

	if (strchr(p1->question[1].domain, '_') != NULL) {
		LOG_DEBUG("dns_sendto contains _");
		qc->is_nonchina_domain = 1;
		return 0;
	}

	char _domain[256];
	snprintf(_domain, sizeof(_domain), "_.%s", p1->question[1].domain);
	p0.question[0].domain = add_domain(&p0, _domain);
	p0.question[0].type   = NSTYPE_TXT;
	p0.head.addon  = 0;
	p0.head.answer = 0;
	p0.head.author = 0;
	p0.head.question = 1;

	p0.head.ident += 0x1000;
	retval = dns_sendto(ctx->outfd, &p0, ctx->dnsaddr, ctx->dnslen);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure");
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

int dns_answer_diff(struct dns_parser *p1, struct dns_parser *p2)
{
	int i, j = 0, d = 0;
	int type = NSTYPE_CNAME;
	struct dns_resource *f, *t;

	int ncname = 0;
	for (i = 0; i < p1->head.answer && d == 0; i++) {
		f = &p1->answer[i];
		if (f->type != type) {
			continue;
		}

		while (j < p2->head.answer &&
				p2->answer[j].type != type) {
			j++;
		}

		if (j >= p2->head.answer) {
			return 1;
		}

		t = &p2->answer[j++];
		d = !!strcasecmp(*(const char **)f->value, *(const char **)t->value);
		LOG_DEBUG("alias: %s %s %d %d", *(const char **)f->value, *(const char **)t->value, ncname, d);
		ncname ++;
	}

	while (j < p2->head.answer && d == 0) {
		t = &p2->answer[j++];
		if (t->type == type) return 1;
		j++;
	}
	
	return d || ncname < 2;
}

static const char * get_suffix(const char *domain, int ndot)
{
	assert (ndot < 256);
	
	int offset = 0;
	const char *dots[256] = {};

    dots[offset] = domain;
    for (; *domain; domain++) {
        switch(*domain) {
            case '.':
                if (domain > dots[offset]) offset++;
                dots[offset] = domain + 1;
                break;

			default:
				break;
        }
    }

	if (domain > dots[offset]) offset++;

	if (offset > ndot) {
	    LOG_DEBUG("offset = %d ndot=%d %s", offset, ndot, dots[offset - ndot]);
		return dots[offset - ndot];
	}
 
	return 0;
}

static subnet_t *lookupRoute(const void *block, int type)
{
	uint64_t network;

	memcpy(&network, block, sizeof(network));
	if (type == NSTYPE_AAAA) {
		return lookupRoute6(htonll(network)); 
	}

	if (type == NSTYPE_A) {
		return lookupRoute4(htonll(network));
	}

	return NULL;
}

int cdn_is_akamai(const char *domain)
{
	// www.apple.com.edgekey.net.globalredir.akadns.net. 3388 IN CNAME	e6858.dscx.akamaiedge.net.
	// e6858.dscx.akamaiedge.net. 20	IN	A	23.59.247.25

	const char *suffixies = strstr(domain, "akamaiedge.net");
	if (suffixies && strcmp(suffixies, "akamaiedge.net") == 0) {
		return 1;
	}

	suffixies = strstr(domain, "akadns.net");
	if (suffixies && strcmp(suffixies, "akadns.net") == 0) {
		return 1;
	}

	suffixies = strstr(domain, "akamai.net");
	if (suffixies && strcmp(suffixies, "akamai.net") == 0) {
		return 1;
	}

	return 0;
}

int do_dns_backward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
	struct dns_parser p0;
	struct dns_parser *pp;
	struct dns_resource *res;

	LOG_DEBUG("count %d", count);
	pp = dns_parse(&p0, buf, count);
	if (pp == NULL) {
		LOG_DEBUG("do_dns_backward parse failure");
		return 0;
	}

    if (~p0.head.flags & 0x8000) {
        LOG_DEBUG("FROM: %s this is not response", ntop6(from->sin6_addr));
        return -1;
    }
	
	int i;
	int offset = (p0.head.ident & 0xfff);
	struct dns_query_context *qc = &_orig_list[offset];
	struct dns_parser parser, def_parser, ecs_parser;

	if (p0.question[0].type == NSTYPE_PTR) {
		p0.head.flags &= ~NSFLAG_RCODE;
		qc->is_china_domain = 1;
	}

	assert (p0.question[0].domain);
	dns_parse(&parser, qc->parser.buf, qc->parser.len);
	if (strcasecmp(parser.question[1].domain, p0.question[0].domain)) {
		struct dns_parser p1 = {};
		const char *domain = p0.question[0].domain;
		LOG_DEBUG("query soa: %s %s ", parser.question[1].domain, p0.question[0].domain);

		for (i = 0; i < p0.head.answer; i++) {
			res = &p0.answer[i];
			dump_resource("answer ", res);
		}

		for (i = 0; i < p0.head.author; i++) {
			res = &p0.author[i];
			dump_resource("author ", res);
		}

		for (i = 0; i < p0.head.addon; i++) {
			res = &p0.addon[i];
			dump_resource("addon ", res);
		}

		if (*domain == '_' && domain[1] == '.') {
			const char *soa_nameserver = NULL;
			for (i = 0; i < p0.head.author; i++) {
				res = &p0.author[i];
				if (res->type == NSTYPE_SOA) {
					soa_nameserver = *(const char **)res->value;
					if (cdn_is_akamai(soa_nameserver))
						qc->is_china_domain = 1;
					break;
				}
			}
			p1.head.ident    = p0.head.ident;
			p1.head.flags    = NSFLAG_RD;
			p1.head.question = 1;
			p1.question[0].type   = NSTYPE_A;
			p1.question[0].klass  = NSCLASS_INET;

			if (soa_nameserver && strcasecmp(soa_nameserver, parser.question[1].domain)) {
				p1.head.ident += 0x1000;
				p1.question[0].domain = add_domain(&p1, soa_nameserver);
				dns_sendto(ctx->outfd, &p1, ctx->dnsaddr, ctx->dnslen);
				p1.question[0].type   = NSTYPE_AAAA;
				dns_sendto(ctx->outfd, &p1, ctx->dnsaddr, ctx->dnslen);
				return 0;
			}
		}

		for (i = 0; i < p0.head.answer; i++) {
			res = &p0.answer[i];
			if (res->type == NSTYPE_CNAME && (cdn_is_akamai(res->domain)
						||  cdn_is_akamai(*(const char **)res->value))) {
				qc->is_china_domain = 1;
				break;
			}

			if (res->type == NSTYPE_A || res->type == NSTYPE_AAAA) {
				if (NULL == lookupRoute(res->value, res->type)) {
					qc->is_china_domain = 1;
					break;
				} else {
					qc->is_nonchina_domain = 1;
				}
			}
		}

		if (qc->is_china_domain == 0 && p0.head.answer > 0) {
			qc->is_nonchina_domain = 1;
		}

		dns_parse(&def_parser, qc->def_parser.buf, qc->def_parser.len);
		dns_parse(&ecs_parser, qc->ecs_parser.buf, qc->ecs_parser.len);
		goto check_flush;
	}

	if (contains_subnet(&p0)) {
		dns_parser_copy(&ecs_parser, &p0);
		dns_parse(&def_parser, qc->def_parser.buf, qc->def_parser.len);
	} else {
		dns_parse(&ecs_parser, qc->ecs_parser.buf, qc->ecs_parser.len);
		dns_parser_copy(&def_parser, &p0);
	}

	for (i = 0; i < p0.head.answer; i++) {
		res = &p0.answer[i];
		if (res->type == NSTYPE_CNAME && (cdn_is_akamai(res->domain)
					||  cdn_is_akamai(*(const char **)res->value))) {
			// qc->is_china_domain = 1;
			break;
		}

		if ((res->type == NSTYPE_A || res->type == NSTYPE_AAAA)
				&& NULL == lookupRoute(res->value, res->type)) {
			dns_parser_copy(&ecs_parser, &p0);
			// qc->is_china_domain = 1;
			break;
		}
	}

	qc->ecs_parser.len = dns_build(&ecs_parser, qc->ecs_parser.buf, sizeof(qc->ecs_parser.buf));
	qc->def_parser.len = dns_build(&def_parser, qc->def_parser.buf, sizeof(qc->def_parser.buf));

check_flush:
	if (qc->is_china_domain && ecs_parser.head.question) {
		dns_parser_copy(&p0, &ecs_parser);

		p0.question[0] = parser.question[0];
		memmove(p0.answer + 1, p0.answer, sizeof(p0.answer[0]) * p0.head.answer);

		res = &p0.answer[0];
		res->domain = add_domain(&p0, parser.question[0].domain);
		res->type   = NSTYPE_CNAME;
		res->klass  = NSCLASS_INET;
		res->ttl    = 3600;
		*(const char **)res->value  = add_domain(&p0, parser.question[1].domain);
		p0.head.answer++;

		const char *ptr = get_suffix(parser.question[0].domain, 3);
		
		for (i = 0; i < p0.head.author && ptr; i++) {
			res = &p0.author[i];
			if (res->type == NSTYPE_SOA) {
				res->domain = add_domain(&p0, ptr);
				res->ttl = 7200;
			}
		}

		p0.head.addon = 0;
		p0.head.ident = parser.head.ident;
		p0.head.flags |= NSFLAG_AA;
		dns_sendto(ctx->sockfd, &p0, (struct sockaddr *)&qc->from, sizeof(qc->from));
		LOG_DEBUG("RETURN: china domain: %s type=%d answer=%d", p0.question[0].domain, p0.question[0].type, p0.head.answer);
	}

	if (qc->is_nonchina_domain && def_parser.head.question && ecs_parser.head.question) {
		struct dns_question *que;
		dns_parser_copy(&p0, &def_parser);

		que = &p0.question[0];
		p0.question[0] = parser.question[0];

		if (dns_answer_diff(&def_parser, &ecs_parser) == 0 && 0) {
			for (i = 0; i < p0.head.answer; i++) {
				res = &p0.answer[i];
				if (strcasecmp(res->domain, parser.question[1].domain) == 0) {
					res->domain = add_domain(&p0, parser.question[0].domain);
				}
			}
			LOG_DEBUG("ecs is ko, will return cname");
		} else {
			int nanswer = 0;
			for (i = 0; i < p0.head.answer; i++) {
				res = &p0.answer[i];
				if (que->type == res->type) {
					res->domain = que->domain;
					p0.answer[nanswer++] = *res;
				}
			}
			LOG_DEBUG("RETURN: ecs is ok, do not return %s cname: %d type=%d originally: %d/%d/%d",
					p0.question[0].domain, nanswer, p0.question[0].type, def_parser.head.answer, ecs_parser.head.answer, p0.head.answer);
			p0.head.answer = nanswer;
		}

		const char *ptr = get_suffix(parser.question[0].domain, 3);
		
		for (i = 0; i < p0.head.author && ptr; i++) {
			res = &p0.author[i];
			if (res->type == NSTYPE_SOA) {
				res->domain = add_domain(&p0, ptr);
				res->ttl = 7200;
			}
		}

		p0.head.ident = parser.head.ident;
		p0.head.flags |= NSFLAG_AA;
		dns_sendto(ctx->sockfd, &p0, (struct sockaddr *)&qc->from, sizeof(qc->from));
	}

	LOG_DEBUG("%s is_nonchina_domain %d is_china_domain %d question ecs=%d def=%d",
			parser.question[1].domain,
			qc->is_nonchina_domain, qc->is_china_domain, 
			ecs_parser.head.question, def_parser.head.question);
	// dns_build(&ecs_parser, qc->ecs_parser.buf, qc->ecs_parser.len);
	// dns_build(&def_parser, qc->def_parser.buf, qc->def_parser.len);
	// dns_build(&parser, qc->parser.buf, qc->parser.len);
	return 0;
}

// #define get_score_id(ifname) if_nametoindex(ifname)
#define get_score_id(ifname) 0

int main(int argc, char *argv[])
{
	int retval;
	int outfd, sockfd;
	struct sockaddr_in6 myaddr;
	struct sockaddr * paddr = (struct sockaddr *)&myaddr;

	struct sockaddr_in6 myaddr6;
	struct sockaddr * paddr6 = (struct sockaddr *)&myaddr6;
	setenv("BINDLOCAL", "::ffff:127.0.0.111", 0);
	LOG_DEBUG("memory: %d %d %d\n", sizeof(_orig_list), sizeof(_orig_list[0]), sizeof(_orig_list[0].parser));

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
	myaddr6.sin6_addr   = in6addr_any;

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
	struct sockaddr_in6 dnsaddr;
	struct sockaddr_in6 ecsaddr;

	struct dns_context c0 = {
		.outfd = outfd,
		.sockfd = sockfd,
		.dnslen  = sizeof(dnsaddr),
	};

	setenv("NAMESERVER", "::ffff:8.8.8.8", 0);
	setenv("ECS_SERVER", "::ffff:8.8.8.8", 0);

	dnsaddr.sin6_family = AF_INET6;
	dnsaddr.sin6_port   = htons(53);
	inet_pton(AF_INET6, getenv("NAMESERVER"), &dnsaddr.sin6_addr);

	ecsaddr.sin6_family = AF_INET6;
	ecsaddr.sin6_port   = htons(53);
	inet_pton(AF_INET6, getenv("ECS_SERVER"), &ecsaddr.sin6_addr);

	c0.dnsaddr = (struct sockaddr *)&dnsaddr;
	c0.ecsaddr = (struct sockaddr *)&ecsaddr;
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
			assert(count > 0);
			count > 0 || LOG_DEBUG("outfd is readable");
			do_dns_backward(&c0, buf, count, &myaddr);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			addrl = sizeof(myaddr6);
			count = recvfrom(sockfd, buf, sizeof(buf), 0, paddr6, &addrl);
			assert(count > 0);
			count > 0 || LOG_DEBUG("sockfd is readable");
			do_dns_forward(&c0, buf, count, &myaddr6);
		}

	} while (retval >= 0);

	close(sockfd);
	close(outfd);

	return 0;
}
