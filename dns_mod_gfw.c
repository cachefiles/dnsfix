#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "tx_debug.h"
#include "dnsproto.h"
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

struct dns_soa {
        const char *name_server;
        const char *admin_email;
        uint32_t serial;
        uint32_t day2;
        uint32_t day3;
        uint32_t day4;
        uint32_t day5;
};

static struct dns_soa _rr_soa = {
        .name_server = "ns2.603030.xyz",
        .admin_email = "admin.603030.xyz",
        .serial = 20231523,
        .day2 = 7200,
        .day3 = 1800,
        .day4 = 1209600,
        .day5 = 1600
};

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
		.domain = "mtalk.oogleg.moc.603030.xyz",
		.value = {10, 0, 3, 1}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "example.com",
		.value = {93, 184, 215, 14}},
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

struct dns_context {
	int outfd;
	int sockfd;
	int echofd;

	socklen_t dnslen;
	struct sockaddr_in6 *dnsaddr;
};

struct dns_query_context {
	uint32_t digest;
	int server_status;
	char cname[256];
	struct sockaddr_in6 from;
	struct dns_parser parser;
};

static struct dns_query_context _orig_list[0x1000];

static struct sockaddr_in6 _ain6 = {};
static struct sockaddr_in6 _cin6 = {};

static int dns_parser_copy(struct dns_parser *dst, struct dns_parser *src)
{
    static uint8_t _qc_hold[2048];
    size_t len  = dns_build(src, _qc_hold, sizeof(_qc_hold));
	assert(len > 0);
    int isok = dns_parse(dst, _qc_hold, len) == NULL;
	assert(isok == 0);
	return isok;
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

	(void)_tld1;
	for (i = 0; _tld0[i]; i++) {
		if (strncasecmp(domain, _tld0[i], 4) == 0) {
			return 1;
		}
	}

	if (strncasecmp(domain, "oc.", 3) == 0) {
		return 1;
	}

	return 0;
}

static int dns_rewrap(struct dns_parser *p1)
{
	const char *domain = NULL;
	struct dns_question *que, *que1;

	que = &p1->question[0];
	que1 = &p1->question[1];

	int ndot = 0;
	char *optp, *limit;
	char *dots[8] = {}, title[256];

	// LOG_DEBUG("suffixes: %s %d", que->domain, que->type);
	if (p1->head.question != 1 || que->domain == NULL) {
		return -1;
	}

	optp = title;
	limit = title + sizeof(title);
	dots[ndot & 0x7] = title;
	for (domain = que->domain; *domain; domain++) {
		switch(*domain) {
			case '.':
				if (optp > dots[ndot & 0x7]) ndot++;
				assert(optp < limit);
				*optp++ = *domain;
				dots[ndot & 0x7] = optp;
				break;

			default:
				assert(optp < limit);
				*optp++ = *domain;
				break;
		}
	}

	*optp = 0;
	if (optp > dots[ndot & 0x7]) ndot++;

	if (ndot <= 3) {
		return -1;
	}

	if (ndot > 3 && !strcasecmp(dots[(ndot - 3) & 0x7], "oil.603030.xyz")) {
		*que1 = *que;
		p1->addon[0].domain = add_domain(p1, "oil.603030.xyz");
		p1->addon[0].klass = NSCLASS_INET;
		p1->addon[0].type = NSTYPE_A;
		p1->addon[0].ttl = 3600;
		dots[(ndot - 3) & 0x7][-1] = 0;
		que1->domain = add_domain(p1, title);
		assert(que1->domain);
		p1->head.question = 2;
		return 0;
	}

	return -1;
}

static int dns_sendto(int outfd, struct dns_parser *parser, const struct sockaddr_in6 *inp, size_t tolen)
{
	ssize_t len;
	uint8_t _hold[2048];
	const struct sockaddr *to = (const struct sockaddr *)inp;

	len = dns_build(parser, _hold, sizeof(_hold));
	assert(len > 0);

	if (len != -1)
		len = sendto(outfd, _hold, len, 0, to, tolen);

	LOG_DEBUG("dns_sendto %d af=%d %d %s %s", len,
			inp->sin6_family, htons(inp->sin6_port), ntop6(inp->sin6_addr), parser->question[0].domain);

	return len;
}

int off_primary = 0;
static char cache_primary[1024 * 1024] = {};

int off_secondary = 0;
static char cache_secondary[1024 * 1024] = {};

enum {STATUS_ALLOW, STATUS_REJECT};
static char * cache_current = cache_primary;

static int cache_get(const char *host)
{
    int off = 0;

    for (off = 0; off < off_primary; off++) {
        int length = cache_primary[off] & 0xff;

        if (strncasecmp(cache_primary + off + 1, host, length) == 0) {
            int type = cache_primary[off + length];
            LOG_DEBUG("get cache host: %s type %d", host, type);
            return type | 0x80;
        }

        off += length;
    }

    for (off = 0; off < off_secondary; off++) {
        int length = cache_secondary[off] & 0xff;

        if (strncasecmp(cache_secondary + off + 1, host, length) == 0) {
            int type = cache_secondary[off + length];
            LOG_DEBUG("get cache host: %s type %d", host, type);
            return type | 0x80;
        }

        off += length;
    }

    return 0;
}


static int cache_add(const char *host, int atype)
{
    int off = 0;

    if (cache_get(host))
        return 0;

    int hostlen = strlen(host);

    if (atype == STATUS_ALLOW)
        hostlen++;

    assert(hostlen < 256);
    int *off_current = 0;
    if (cache_current == cache_primary) {
        off_current = &off_primary;
        if (off_primary + hostlen >= sizeof(cache_primary)) {
            cache_current = cache_secondary;
            off_current = &off_secondary;
            off_secondary = 0;
        }
    } else if (cache_current == cache_secondary) {
        off_current = &off_secondary;
        if (off_secondary + hostlen >= sizeof(cache_secondary)) {
            cache_current = cache_primary;
            off_current = &off_primary;
            off_primary = 0;
        }
    }

    assert(off_current);

    off = *off_current;

    cache_current[off++] = hostlen;
    memcpy(cache_current + off, host, hostlen);
    off += hostlen;

    *off_current = off;

    LOG_DEBUG("cache_add %s %d", host, atype);
    return 0;
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

    if (p0.head.question && p0.question[0].type == NSTYPE_A
	    && !strcmp(p0.question[0].domain, "example.com")) {
        LOG_DEBUG("FROM: %s keepalive %s", ntop6p(&from->sin6_addr), p0.question[0].domain);
        // memcpy(ctx->dnsaddr, from, sizeof(*from));
	// ctx->dnslen = sizeof(*from);
	// ctx->echofd = ctx->sockfd;
    }

    if (p0.head.question && fetch_predefine_resource_record(&p0)) {
        LOG_DEBUG("prefetch: %s", p0.question[0].domain);
        p0.head.flags |= NSFLAG_QR;
        dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
        return 0;
    }

    int type = cache_get(p0.question[0].domain);
    if (type && (p0.question[0].type == NSTYPE_A || p0.question[0].type == NSTYPE_AAAA)) {
        LOG_DEBUG("cache_get: %s %d", p0.question[0].domain, type);
        p0.head.flags |= NSFLAG_QR;
        if (p0.head.flags & NSFLAG_RD) p0.head.flags |= NSFLAG_RA;
        p0.head.flags |= NSFLAG_AA;
        p0.head.flags &= ~NSFLAG_ZERO;

        p0.head.answer = 1;
        p0.head.addon = 0;
        p0.answer[0].domain = p0.question[0].domain;
        p0.answer[0].type = p0.question[0].type;
        p0.answer[0].ttl  = 7200;
        p0.answer[0].klass = p0.question[0].klass;

        if (type & 0x7f) {
            uint32_t fakeip = rand();
            if (fakeip == 0x7f7f7f7f) fakeip = 0x1010101;
            uint32_t list[4] = {fakeip, fakeip, fakeip, fakeip};
            memcpy(p0.answer[0].value, list, 16);
        } else if (p0.question[0].type == NSTYPE_AAAA) {
            memset(p0.answer[0].value, 0xfe, 16);
        } else {
            memset(p0.answer[0].value, 127, 16);
        }

        dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
        return 0;
    }

    if (p0.head.question == 0) {
        p0.head.flags |= RCODE_REFUSED;
        p0.head.flags |= NSFLAG_QR;
        dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
        return 0;
    }

    const char *myzone = strcasestr(p0.question[0].domain, "oil.603030.xyz");
    if (myzone == NULL || strcasecmp(myzone, "oil.603030.xyz") || p0.question[0].type == NSTYPE_CNAME) {
        // p0.head.flags |= RCODE_NXDOMAIN;
        p0.head.flags |= RCODE_REFUSED;
        p0.head.flags |= NSFLAG_QR;
        dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
        return 0;
    }

    int retval = 0;
    int offset = (p0.head.ident & 0xfff);

    struct dns_parser *p1 = NULL;
    struct dns_query_context qc0 = {};
    struct dns_query_context *qc = &qc0;
    struct dns_query_context *qc1 = &_orig_list[offset];

    memset(qc, 0, sizeof(qc0));
    qc->from = *from;

    dns_parser_copy(&qc->parser, &p0);
    p1 = &qc->parser;

    if (dns_rewrap(p1) == -1) {
        p0.head.flags |= RCODE_REFUSED;
        p0.head.flags |= NSFLAG_QR;
        dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
        LOG_DEBUG("FROM: %s this is not good %d", p0.question[0].domain, p0.question[0].type);
        return -1;
    }

    const char *zone = p1->addon[0].domain;
    LOG_DEBUG("%04x: FROM: %s to %s, zone %s", p1->head.ident, p1->question[0].domain, p1->question[1].domain, zone);
    if (zone != NULL && *p0.question[0].domain == '_') {
        struct dns_resource *res;
        p0.head.flags |= (RCODE_NXDOMAIN| NSFLAG_AA);
        p0.head.flags |= (NSFLAG_RA| NSFLAG_QR);

        res = &p0.author[0];
        res->domain = add_domain(&p0, zone);
        res->type = NSTYPE_SOA;
        res->klass = NSCLASS_INET;
        res->ttl = 7200;
        memcpy(res->value , &_rr_soa, sizeof(_rr_soa));
        p0.head.author = 1;

        retval = dns_sendto(ctx->sockfd, &p0, &qc->from, ctx->dnslen);
        if (retval == -1) {
            LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnsaddr);
            return 0;
        }
        return 0;
    }

    if (zone != NULL && strcasecmp(zone, "oil.603030.xyz") == 0 && (p0.question[0].type == NSTYPE_AAAA || p0.question[0].type == NSTYPE_A)) {
        p0.question[0] = p1->question[1];
        p0.head.flags &= ~NSFLAG_QR;
        p0.head.flags &= ~NSFLAG_RD;
        p0.head.flags &= ~NSFLAG_RCODE;
        p0.head.question = 1;
        p0.head.answer = 0;
        p0.head.author = 0;

        p0.addon[0].domain = "";
        p0.addon[0].ttl = 0;
        p0.addon[0].klass = 1320;
        p0.addon[0].type = NSTYPE_OPT;
        p0.addon[0].len = 0;
        p0.head.addon = 1;

	int outfd = ctx->echofd == -1? ctx->outfd: ctx->echofd;
        retval = dns_sendto(outfd, &p0, ctx->dnsaddr, ctx->dnslen);
        if (retval == -1) {
            LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnsaddr);
            return 0;
        }

        retval = dns_sendto(ctx->outfd, &p0, &_ain6, sizeof(_ain6));
        if (retval == -1) {
            LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnsaddr);
            return 0;
        }

        p0.head.flags |= NSFLAG_RD;
        retval = dns_sendto(ctx->outfd, &p0, &_cin6, sizeof(_cin6));
        if (retval == -1) {
            LOG_DEBUG("dns_sendto failure: %s %p", strerror(errno), ctx->dnsaddr);
            return 0;
        }

        *qc1 = qc0;
        qc1->digest = 0;
        dns_parser_copy(&qc1->parser, &qc0.parser);
    } else {
	    p0.head.flags |= RCODE_REFUSED;
	    p0.head.flags |= NSFLAG_QR;
	    dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
	    LOG_DEBUG("refused FROM: %s this is not good %d", p0.question[0].domain, p0.question[0].type);
    }

    return 0;
}

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
			LOG_DEBUG("%s %s AAAA %s", title, res->domain, ntop6p(res->value));
	} else if (res->type == NSTYPE_CNAME) {
			LOG_DEBUG("%s %s CNAME %s", title, res->domain, *(const char **)res->value);
	} else {
			LOG_DEBUG("%s %s UNKOWN %d", title, res->domain, res->type);
	}

	return 0;
}

static uint32_t get_check_sum(void *buf, size_t count)
{
	uint32_t cksum = 0;
	uint32_t *dataptr = (uint32_t*)buf;
	uint32_t flags = *dataptr;

#define NSFLAG_AA    0x0400
#define NSFLAG_RD    0x0100
#define NSFLAG_RA    0x0080

	flags &= ~htonl(NSFLAG_AA|NSFLAG_RD|NSFLAG_RA);

	LOG_DEBUG("flags=%08x %08x", flags, *dataptr);
	while (count >= 4) {
		cksum += flags;
		count -= 4;
		flags  = *++dataptr;
	}
	
	return cksum;
}

struct dns_alias {
    char *name;
};

#define SS_CHINA 1
#define SS_ONEED  2
#define SS_REJECTED  8

int do_dns_backward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
    int i;
    struct dns_parser p0;
    struct dns_parser *pp;
    struct dns_resource *res;

    pp = dns_parse(&p0, buf, count);
    if (pp == NULL) {
        LOG_DEBUG("do_dns_backward parse failure");
        return 0;
    }

#if 0
    if (~p0.head.flags & 0x8000) {
        LOG_DEBUG("FROM: %s this is not response", inet_ntoa(from->sin_addr));
        return -1;
    }
#endif
    if (~p0.head.flags & 0x8000) {
	if (p0.head.question && p0.question[0].type == NSTYPE_A
		&& !strcmp(p0.question[0].domain, "example.com")) {
	    LOG_DEBUG("FROM: %s keepalive %s", ntop6p(&from->sin6_addr), p0.question[0].domain);
	    memcpy(ctx->dnsaddr, from, sizeof(*from));
	    ctx->dnslen = sizeof(*from);
	    ctx->echofd = ctx->outfd;
	}

	if (p0.head.question && fetch_predefine_resource_record(&p0)) {
	    LOG_DEBUG("prefetch: %s", p0.question[0].domain);
	    p0.head.flags |= NSFLAG_QR;
	    dns_sendto(ctx->outfd, &p0, from, sizeof(*from));
	    return 0;
	}
    }

    int offset = (p0.head.ident & 0xfff);
    struct dns_query_context *qc = &_orig_list[offset];

    pp = &qc->parser;
    if (pp->head.ident != p0.head.ident || pp->head.question != 2) {
        LOG_DEBUG("FROM: %s XX unexpected response: %d", ntop6(from->sin6_addr), pp->head.question);
        return -1;
    }

    if (IN6_ARE_ADDR_EQUAL(&_cin6.sin6_addr, &from->sin6_addr)) {
	for (i = 0; i < p0.head.answer; i++) {
            res = &p0.answer[i];
            if (res->type == NSTYPE_CNAME) {
		struct dns_alias * alias = (struct dns_alias *)res->value;
		strcpy(qc->cname, alias->name);
                break;
	    }
	}

	qc->server_status |= SS_ONEED;
	LOG_DEBUG("oneed server_status: %x :%s\n", qc->server_status, qc->cname);
	if (qc->server_status == SS_ONEED) return 0;

	p0.question[0] = pp->question[0];

	p0.head.flags |= NSFLAG_QR;
	p0.head.flags |= NSFLAG_RA;
	p0.head.flags |= NSFLAG_RD;
	p0.head.flags &= ~NSFLAG_RCODE;
	p0.answer[0].klass = NSCLASS_INET;

        p0.head.answer = 1;
        p0.head.addon = 0;
        p0.answer[0].domain = p0.question[0].domain;
        p0.answer[0].type = p0.question[0].type;
        p0.answer[0].ttl  = 7200;
        p0.answer[0].klass = p0.question[0].klass;

	if (p0.answer[0].type != NSTYPE_AAAA &&
           p0.answer[0].type != NSTYPE_A) {
           p0.head.answer = 0;
        } else if (qc->server_status & SS_REJECTED) {
            uint32_t fakeip = rand();
            if (fakeip == 0x7f7f7f7f) fakeip = 0x1010101;
            uint32_t list[4] = {fakeip, fakeip, fakeip, fakeip};
            memcpy(p0.answer[0].value, list, 16);
	} else if (*qc->cname) {
	    int type;
	    char buf[356];
	    snprintf(buf, sizeof(buf), "%s.oil.603030.xyz", qc->cname);
	    type = cache_get(buf);
	    if (type == 0) {
		p0.answer[0].type = NSTYPE_CNAME;
		struct dns_alias *alias = (struct dns_alias *)p0.answer[0].value;
		alias->name = add_domain(&p0, buf);
	    } else if (type & 0x7f) {
		uint32_t fakeip = rand();
		if (fakeip == 0x7f7f7f7f) fakeip = 0x1010101;
		uint32_t list[4] = {fakeip, fakeip, fakeip, fakeip};
		memcpy(p0.answer[0].value, list, 16);
                cache_add(p0.question[0].domain, STATUS_REJECT);
	    } else if (p0.question[0].type == NSTYPE_AAAA) {
                cache_add(p0.question[0].domain, STATUS_ALLOW);
		memset(p0.answer[0].value, 0xfe, 16);
	    } else {
                cache_add(p0.question[0].domain, STATUS_ALLOW);
		memset(p0.answer[0].value, 127, 16);
	    }
	} else {
	    if (p0.question[0].type == NSTYPE_AAAA) {
		memset(p0.answer[0].value, 0xfe, 16);
	    } else {
		memset(p0.answer[0].value, 127, 16);
	    }
	    cache_add(p0.question[0].domain, STATUS_ALLOW);
	}

	dns_sendto(ctx->sockfd, &p0, &qc->from, sizeof(qc->from));
	return 0;
    } else if (IN6_ARE_ADDR_EQUAL(&_ain6.sin6_addr, &from->sin6_addr)) {
        int found = 0;
        uint64_t val = 0;

        for (i = 0; 3 != found && i < p0.head.addon; i++) {
            res = &p0.addon[i];
            if (res->type == NSTYPE_AAAA) {
                val = htonll(*(uint64_t *)res->value);
                found = 2 + !lookupRoute6(val);
            } else if (res->type == NSTYPE_A) {
                val = htonll(*(uint64_t *)res->value) & 0xffffffff00000000ull;
                found = 2 + !lookupRoute4(val);
            }
        }

        LOG_DEBUG("found=%d %s", found, ntop6(from->sin6_addr));
        if (found != 3) {
            p0.question[0] = pp->question[0];
            p0.head.answer = 0;
            p0.head.author = 0;
            p0.head.addon = 0;

            p0.head.flags |= NSFLAG_QR;
            p0.head.flags &= ~NSFLAG_RCODE;
            p0.head.flags |= RCODE_REFUSED;

            if (NULL != getenv("REFUSED")) 
                dns_sendto(ctx->sockfd, &p0, &qc->from, sizeof(qc->from));

            return -1;
        }
	qc->server_status = (SS_ONEED| SS_CHINA);
        qc->cname[0] = 0;
    } else {
	qc->server_status |= SS_CHINA;
    }

    uint32_t digest = get_check_sum(buf, 6 * 2);
    if (digest != qc->digest && qc->digest != 0) {
        LOG_DEBUG("FROM: %s digest %08x %08x %d", ntop6(from->sin6_addr), digest, qc->digest, count);
        return -1;
    }

    qc->digest = digest;
    if (p0.head.author != 0 && p0.head.answer > 0) {
        LOG_DEBUG("FROM: %s %d/%d/%d unexpected response", ntop6(from->sin6_addr), p0.head.author, p0.head.answer, p0.head.addon);
        return -1;
    }

    if (pp->head.answer > p0.head.answer) {
        LOG_DEBUG("FROM: %s should not overwrite response", ntop6(from->sin6_addr));
        return -1;
    }

    if (strcasecmp(pp->question[1].domain, p0.question[0].domain)) {
        LOG_DEBUG("FROM: %s should not overwrite response since question not ok", ntop6(from->sin6_addr));
        LOG_DEBUG("FROM: domain %s %s", pp->question[1].domain, p0.question[0].domain);
        return -1;
    }

    LOG_DEBUG("%04x do_dns_backward parse copy: %d/%d/%d/%d",
            p0.head.ident, p0.head.question, p0.head.answer, p0.head.author, p0.head.addon);

    p0.question[0] = pp->question[0];

    p0.head.flags |= NSFLAG_QR;
    p0.head.flags |= NSFLAG_RA;
    p0.head.flags |= NSFLAG_RD;
    p0.head.flags &= ~NSFLAG_RCODE;
    p0.answer[0].klass = NSCLASS_INET;

    if (p0.head.answer > 0) {
        p0.answer[0].domain = p0.question[0].domain;
        int allow_mask = 0;
        for (i = 0; i < p0.head.answer; i++) {
            p0.answer[i].ttl = 7200;
            if (p0.head.addon) {
                allow_mask = 1;
                if (p0.answer[i].type == NSTYPE_A)
                    memset(p0.answer[i].value, 127, 4);
                if (p0.answer[i].type == NSTYPE_AAAA)
                    memset(p0.answer[i].value, 0xfe, 16);
                if (p0.answer[i].type == NSTYPE_CNAME)
                    *(char **)p0.answer[i].value = "chinazone.603030.xyz";
            }
        }
	if (*qc->cname && allow_mask) {
	    char buf[356];
	    p0.answer[0].type = NSTYPE_CNAME;
	    snprintf(buf, sizeof(buf), "%s.oil.603030.xyz", qc->cname);
	    struct dns_alias *alias = (struct dns_alias *)p0.answer[0].value;
	    alias->name = add_domain(&p0, buf);
	    p0.head.answer = 1;
	}

        if (p0.head.flags & NSFLAG_RD) p0.head.flags |= NSFLAG_RA;
        p0.head.flags |= NSFLAG_AA;
        p0.head.flags &= ~NSFLAG_ZERO;

	if (!allow_mask) {
	    qc->server_status |= SS_REJECTED;
	    // cache_add(p0.question[0].domain, allow_mask? STATUS_ALLOW: STATUS_REJECT);
	    cache_add(p0.question[0].domain, STATUS_REJECT);
	}
    } else if (p0.question[0].type == NSTYPE_AAAA
            || p0.question[0].type == NSTYPE_A) {
        p0.answer[0].domain = p0.question[0].domain;
        p0.answer[0].type = p0.question[0].type;
        p0.answer[0].ttl = 7200;
        if (p0.question[0].type == NSTYPE_A)
            memset(p0.answer[0].value, 127, 4);
        if (p0.question[0].type == NSTYPE_AAAA)
            memset(p0.answer[0].value, 0xfe, 16);

	if (*qc->cname) {
	    char buf[356];
	    p0.answer[0].type = NSTYPE_CNAME;
	    snprintf(buf, sizeof(buf), "%s.oil.603030.xyz", qc->cname);
	    struct dns_alias *alias = (struct dns_alias *)p0.answer[0].value;
	    alias->name = add_domain(&p0, buf);
	}

        // cache_add(p0.question[0].domain, STATUS_ALLOW);

        if (p0.head.flags & NSFLAG_RD) p0.head.flags |= NSFLAG_RA;
        p0.head.flags |= NSFLAG_AA;
        p0.head.flags &= ~NSFLAG_ZERO;
        p0.head.answer = 1;
    }

    for (i = 0; i < p0.head.author; i++) {
        if (p0.author[i].type == NSTYPE_SOA) {
            p0.author[i].domain = "oil.603030.xyz";
            p0.author[i].ttl = 7200;
        }
    }

    p0.head.addon = 0;
    p0.head.author = 0;

    int all_flasgs = (SS_ONEED| SS_CHINA);
    LOG_DEBUG("server_status: %x :%s\n", qc->server_status, qc->cname);
    if ((qc->server_status & all_flasgs) == all_flasgs) {
	dns_sendto(ctx->sockfd, &p0, &qc->from, sizeof(qc->from));
	if ((~qc->server_status & SS_REJECTED) && 0 == *qc->cname)
	    cache_add(p0.question[0].domain, STATUS_ALLOW);
    }

    return 0;
}

int main(int argc, char *argv[])
{
	int retval;
	int outfd, sockfd;
	struct sockaddr_in6 myaddr;
	struct sockaddr * paddr = (struct sockaddr *)&myaddr;

	struct sockaddr_in6 myaddr6;
	struct sockaddr * paddr1 = (struct sockaddr *)&myaddr6;

	setenv("NAMESERVER", "2408:4009:501::2", 0);
	setenv("LOCALADDR6", "2001:470:66:22a::2", 0);
	setenv("ROOTSERVER", "::ffff:192.41.162.30", 0);
	setenv("FOURONE", "::ffff:101:101", 0);

	_ain6.sin6_family = AF_INET6;
	_ain6.sin6_port   = htons(53);
	inet_pton(AF_INET6, getenv("ROOTSERVER"), &_ain6.sin6_addr); 

	_cin6.sin6_family = AF_INET6;
	_cin6.sin6_port   = htons(53);
	inet_pton(AF_INET6, getenv("FOURONE"), &_cin6.sin6_addr); 

	outfd = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(outfd != -1);

	myaddr.sin6_family = AF_INET6;
	myaddr.sin6_port   = htons(51623);
	myaddr.sin6_addr   = in6addr_any;
	retval = bind(outfd, paddr, sizeof(myaddr));
	assert(retval != -1);

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(sockfd != -1);

	myaddr6.sin6_family = AF_INET6;
	myaddr6.sin6_port   = htons(53);
	// myaddr6.sin6_addr.s_addr   = INADDR_ANY;
	inet_pton(AF_INET6, getenv("LOCALADDR6"), &myaddr6.sin6_addr);
	retval = bind(sockfd, paddr1, sizeof(myaddr6));
	assert(retval != -1);

	int count;
	char buf[2048];
	fd_set readfds = {};
	socklen_t addrl = 0;
	struct sockaddr_in6 dnsaddr;

	struct dns_context c0 = {
		.outfd = outfd,
		.sockfd = sockfd,
		.echofd = -1,
		.dnslen  = sizeof(dnsaddr),
	};

	dnsaddr.sin6_family = AF_INET6;
	dnsaddr.sin6_port   = htons(53);
	inet_pton(AF_INET6, getenv("NAMESERVER"), &dnsaddr.sin6_addr);

	c0.dnsaddr = &dnsaddr;
	LOG_DEBUG("nsaddr %p pointer %p %d", c0.dnsaddr, &dnsaddr, htons(dnsaddr.sin6_port));

	const struct sockaddr_in6 *inp = &dnsaddr;
	LOG_DEBUG("dns_build af=%d port=%d %s", inp->sin6_family, htons(inp->sin6_port), inet_ntop(AF_INET6, &inp->sin6_addr, buf, sizeof(buf)));

	_predefine_resource_record[0].domain = "oil.603030.xyz";
	_predefine_resource_record[0].type   = NSTYPE_NS;
	*(char **)_predefine_resource_record[0].value  = "ns2.603030.xyz";

	do {
		FD_ZERO(&readfds);
		FD_SET(outfd, &readfds);
		FD_SET(sockfd, &readfds);

		retval = select(sockfd + 2, &readfds, 0, 0, 0);
		if (retval == -1) {
			LOG_DEBUG("select failure: %s", strerror(errno));
			break;
		}

		if (FD_ISSET(outfd, &readfds)) {
			addrl = sizeof(myaddr);
			count = recvfrom(outfd, buf, sizeof(buf), 0, paddr, &addrl);
			count > 0 || LOG_DEBUG("outfd is readable count=%d", count);
			if (count > 0) do_dns_backward(&c0, buf, count, &myaddr);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			addrl = sizeof(myaddr6);
			count = recvfrom(sockfd, buf, sizeof(buf), 0, paddr1, &addrl);
			count > 0 || LOG_DEBUG("sockfd is readable: %d", count);
			if (count > 0) do_dns_forward(&c0, buf, count, &myaddr6);
		}

	} while (retval >= 0);

	close(sockfd);
	close(outfd);

	return 0;
}
