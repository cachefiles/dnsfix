#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#define closesocket close
#endif

#include "txall.h"
#include "txdnsxy.h"
#include "dnsproto.h"
#include "subnet_api.h"

#include <txall.h>
#include "txconfig.h"

struct uptick_task {
	int ticks;
	tx_task_t task;
	unsigned int last_ticks;
};

static void update_tick(void *up)
{
	struct uptick_task *uptick;
	unsigned int ticks = tx_ticks;

	uptick = (struct uptick_task *)up;

	if (ticks != uptick->last_ticks) {
		//fprintf(stderr, "tx_getticks: %u %d\n", ticks, uptick->ticks);
		uptick->last_ticks = ticks;
	}

	if (uptick->ticks < 100) {
		tx_task_active(&uptick->task, "update_tick");
		uptick->ticks++;
		return;
	}

	fprintf(stderr, "all update_tick finish\n");
#if 0
	tx_loop_stop(tx_loop_get(&uptick->task));
	fprintf(stderr, "stop the loop\n");
#endif
	return;
}

struct timer_task {
	tx_task_t task;
	tx_timer_t timer;
};

static void update_timer(void *up)
{
	struct timer_task *ttp;
	ttp = (struct timer_task*)up;

	tx_timer_reset(&ttp->timer, 50000);
	//fprintf(stderr, "update_timer %d\n", tx_ticks);
	return;
}

struct dns_udp_context_t {
    int sockfd;
    tx_aiocb file;

    int outfd;
    tx_aiocb outgoing;
    tx_task_t mark_detect;
    tx_timer_t reset_detect;

    struct tcpip_info forward;

    tx_task_t task;
};

typedef void (*callback_t)(void *);

void query_finish(void *context)
{

}

struct root_server {
    char domain[32];
    int ttl;
    char ipv4[32];
};

static struct root_server _root_servers[]= {
    {"a.root-servers.net", 518400, "198.41.0.4"},
    {"b.root-servers.net", 518400, "199.9.14.201"},
    {"c.root-servers.net", 518400, "192.33.4.12"},
    {"d.root-servers.net", 518400, "199.7.91.13"},
    {"e.root-servers.net", 518400, "192.203.230.10"},
    {"f.root-servers.net", 518400, "192.5.5.241"},
    {"g.root-servers.net", 518400, "192.112.36.4"},
    {"h.root-servers.net", 518400, "198.97.190.53"},
    {"i.root-servers.net", 518400, "192.36.148.17"},
    {"j.root-servers.net", 518400, "192.58.128.30"},
    {"k.root-servers.net", 518400, "193.0.14.129"},
    {"l.root-servers.net", 518400, "199.7.83.42"},
    {"m.root-servers.net", 518400, "202.12.27.33"},
};

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#define NSCLASS_INET 1

static struct dns_resource _tpl0 =  {
	.type = NSTYPE_A,
	.klass = NSCLASS_INET,
	.ttl = 518400,
	.len = 4,
	.flags = 0,
	.domain = "dummy",
	.value = {}
};

static int nanswer = 0;
static struct dns_resource answsers[1024] = {};

static int answer_cache_lookup(const char *domain, int type, struct dns_resource results[], size_t size)
{
    int count = 0;
	struct dns_resource *res = NULL;

    for (int j = 0; j < nanswer; j++) {
        res = &answsers[j];
        if (res->type == type && !strcasecmp(domain, res->domain)) {
            results[count] = *res;
            count++;
        }
    }

	for (int j = 0; j < ARRAY_SIZE(_root_servers); j++) {
		struct root_server *rs = &_root_servers[j];
		if (type == NSTYPE_A && !strcasecmp(domain, rs->domain)) {
			results[count] = _tpl0;
			results[count].domain = rs->domain;
			in_addr_t target = inet_addr(rs->ipv4);
			memcpy(results[count].value, &target, sizeof(target)); 
            count++;
		}
	}

    if (count > 0) {
        fprintf(stderr, "answer_cache_lookup %s type %d\n", domain, type);
        return count;
    }

	int oldcount = 0;
	const char *trace = domain;

	do {
		oldcount = count;
		for (int j = 0; j < nanswer; j++) {
			res = &answsers[j];
			if (res->type == NSTYPE_CNAME && !strcasecmp(trace, res->domain)) {
				const char *newtrace = *(char **)res->value;

				if (0 == strcasecmp(newtrace, trace)) {
						LOG_DEBUG("bad cname: %s", newtrace);
						return 0;
				}

				for (int i = 0; i <  count; i++) {
					if (strcasecmp(newtrace, results[i].domain) == 0) {
						LOG_DEBUG("bad cname %s %s", newtrace, results[i].domain);
						return 0;
					}
				}

				trace = newtrace;
				results[count] = *res;
				count++;
			}
		}
	} while (oldcount != count);

	if (count > 0 && strcasecmp(trace, domain)) {
		int plus = answer_cache_lookup(trace, type, results + count, size - count);
		count += plus;
	}

	return count;
}

static int hold_to_answer(struct dns_resource *res, size_t count, int is_china_domain)
{
    int i, j;
    struct dns_resource *f, *t;

    move_to_cache(res, count);

	void *lastptr[256] = {};
    for (i = 0; i < count; i++) {
        f = res + i;

        int found = 0;
        for (j = 0; j < nanswer; j++) {
            t = &answsers[j];
            if (strcasecmp(t->domain, f->domain) == 0 && t->type == f->type && (lastptr[t->type] < t)) {
				lastptr[t->type] = t;
                *t = *f;
                found = 1;
                break;
            }
        }

        if (found == 0) {
            answsers[nanswer] = *f;
            nanswer++;
        }
    }

    return 0;
}


static int nauthor;
static struct dns_resource authors[1024];

struct query_context_t {
	int refcnt;
	int is_china_domain;
	struct sockaddr_in from;
	struct dns_question que;
	struct dns_parser parser;

	int nworker, iworker;
	struct dns_resource worker[260];
	void *assioc_uptr;
};

static int _qc_next = 0;
static uint8_t _qc_hold[2048];
static struct query_context_t _query_list[0xfff];

int dns_parser_copy(struct dns_parser *dst, struct dns_parser *src)
{
    size_t len  = dns_build(src, _qc_hold, 2048);
    return dns_parse(dst, _qc_hold, len) == NULL;
}

static int do_lookup_nameserver(dns_udp_context_t *up, struct query_context_t *qc, const char * domain);

static int author_cache_lookup(const char *domain, struct dns_resource results[], size_t size)
{
	struct dns_resource *res = NULL;
	struct dns_resource *kes = NULL;

	int ndot = 0;
	const char *dots[256] = {};

	for (int j = 0; domain[j]; j++) {
		assert(ndot < 256);
		if (domain[j] == '.') {
			dots[ndot] = domain + j;
			ndot++;
		}
	}

	if (ndot == 0) {
		return 0;
	}

    int count = 0;
	for (int j = 0; j < ARRAY_SIZE(_root_servers); j++) {
		struct root_server *rs = &_root_servers[j];
		const char *domain = rs->domain;

		results[count] = _tpl0;
		results[count].domain = "";
		results[count].type = NSTYPE_NS;

		memcpy(results[count].value, &domain, sizeof(domain));
		count++;
	}

	for (int i = ndot - 1; i >= 0; i--) {
		const char *dotname = dots[i] + 1;

		int newcount = 0;
		for (int j = 0; j < nauthor; j++) {
			res = &authors[j];
			if (res->type == NSTYPE_NS && !strcasecmp(dotname, res->domain)) {
				results[newcount] = *res;
				newcount++;
			}
		}

		if (newcount > 0) {
			count = newcount;
		}
	}

	int nscount = count;

	for (int i = 0; i < nscount; i++) {
		res = &results[i];
		if (res->type != NSTYPE_NS) {
			res->ttl = 0;
			continue;
		}

		const char * nsname = *(const char **)res->value;

		for (int j = 0; j < nanswer; j++) {
			kes = &answsers[j];
			if (kes->type == NSTYPE_A && !strcasecmp(kes->domain, nsname)) {
				results[count] = *kes;
				res->ttl = 0;
				count++;
			}
		}

		if (res->ttl == 0) {
			continue;
		}

		for (int j = 0; j < nauthor; j++) {
			kes = &authors[j];
			if (kes->type == NSTYPE_A && !strcasecmp(nsname, kes->domain)) {
				results[count] = *kes;
				res->ttl = 0;
				count++;
			}
		}

		if (res->ttl == 0) {
			continue;
		}

		for (int j = 0; j < ARRAY_SIZE(_root_servers); j++) {
			struct root_server *rs = &_root_servers[j];
			if (!strcasecmp(nsname, rs->domain)) {
				results[count] = _tpl0;
				results[count].domain = rs->domain;
				in_addr_t target = inet_addr(rs->ipv4);
				memcpy(results[count].value, &target, sizeof(target)); 
				res->ttl = 0;
				count++;
			}
		}
	}

	return count;
}

static int hold_to_author(struct dns_resource *res, size_t count)
{
    int i, j;
    struct dns_resource *f, *t;

    move_to_cache(res, count);

	void *lastptr[256] = {};
    for (i = 0; i < count; i++) {
        f = res + i;

        int found = 0;
        for (j = 0; j < nauthor; j++) {
            t = &authors[j];
            if (t->domain == f->domain && t->type == f->type && (lastptr[f->type] < t)) {
				lastptr[t->type] = t;
                *t = *f;
                found = 1;
                break;
            }
        }

        if (found == 0 && NSTYPE_NS == f->type) {
			LOG_DEBUG("cache NS %s %s", f->domain, *(char **)f->value);
            authors[nauthor] = *f;
            nauthor++;
        }

        if (found == 0 && NSTYPE_A == f->type) {
			LOG_DEBUG("cache A %s", f->domain);
            authors[nauthor] = *f;
            nauthor++;
        }
    }

	return 0;
}

static int do_fetch_resource(dns_udp_context_t *up, int ident, struct dns_question *que, struct in_addr *server, const char *server_name)
{
	uint8_t buf[2048];
	struct dns_parser p0 = {};
	struct sockaddr_in target = {};

	p0.head.question = 1;
	p0.head.ident  = ident;
	p0.question[0] = *que;

	p0.head.addon = 1;
	p0.addon[0].domain = "";
	p0.addon[0].type   = NSTYPE_OPT;
	p0.addon[0].ttl    = 0;
	p0.addon[0].klass  = 1230;
	p0.addon[0].len    = 0;

	size_t len = dns_build(&p0, buf, sizeof(buf));

	target.sin_family = AF_INET;
	target.sin_port   = htons(53);
	target.sin_addr   = *server;

	size_t slen = sendto(up->outfd, buf, len, 0, (struct sockaddr *)&target, sizeof(target));
	LOG_DEBUG("do_fetch_resource sendto %s/%s data %d %d %s %d", server_name, inet_ntoa(*server), len, slen, que->domain, que->type);
}

static int dns_query_append(struct query_context_t *qc, struct dns_resource *answer, size_t count)
{
	int i, is_china_domain = 0;
	struct dns_resource *res;

	for (i = 0; i < count; i++) {
		res = answer + i;
		if (res->type != NSTYPE_A) continue;

        int target = *(int *)res->value;
        if (res->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
            LOG_DEBUG("china domain detect");
			is_china_domain = 1;
        }

		qc->worker[qc->nworker++] = *res;
		qc->iworker = qc->nworker - 1;
	}

	qc->is_china_domain |= is_china_domain;

	return 0;
}

static int do_query_response(dns_udp_context_t *up, struct query_context_t *qc, struct dns_resource *answer, size_t count, int author)
{
	int i, len, slen;
	uint8_t buf[2048];
	struct dns_parser *p = &qc->parser;

	p->head.flags |= 0x8000;

	p->head.answer = 0;
	p->head.author = 0;

	const char *lastdn = NULL;
	if (p->head.question > 1) {

		for (i = 1; i < p->head.question; i++) {
			struct dns_resource *res = &p->answer[p->head.answer++];
			struct dns_question *que0 = &p->question[i -1];
			struct dns_question *que1 = &p->question[i];

			res->domain = add_domain(p, que0->domain);
			res->type   = NSTYPE_CNAME;
			res->klass  = NSCLASS_INET;
			res->ttl    = 600;

			*(const char **)res->value = lastdn = add_domain(p, que1->domain);
		}

		p->head.question = 1;
	}

	if (p->head.answer > 0 && !qc->is_china_domain) {
		p->head.answer = 0;
	} else {
		lastdn = NULL;
	}

	if (author == 0) {
			struct dns_resource *res;
		for (i = 0; i < count; i++) {
			res = &p->answer[p->head.answer];
			p->answer[p->head.answer++] = answer[i];
			if (lastdn && strcasecmp(res->domain, lastdn) == 0) {
				res->domain = p->question[0].domain;
			}
		}
	} else {
			struct dns_resource *res;
		for (i = 0; i < count; i++) {
			res = &p->author[p->head.author];
			p->author[p->head.author++] = answer[i];
			if (lastdn && strcasecmp(res->domain, lastdn) == 0) {
				res->domain = p->question[0].domain;
			}
		}
	}

#if 0
	if (qc->is_china_domain) {
		p->head.addon = 1;
		struct dns_resource *res = &p->addon[0];

		res->domain = add_domain(p, "ischina.cn");
		res->type   = NSTYPE_CNAME;
		res->klass  = NSCLASS_INET;
		res->ttl    = 600;

		*(const char **)res->value = add_domain(p, "yes.com");
	}
#endif


	len = dns_build(p, buf, sizeof(buf));
	if (len == -1) 
		LOG_DEBUG("dns_build failure");
	
	slen = sendto(up->sockfd, buf, len, 0, (struct sockaddr *)&qc->from, sizeof(qc->from));
	LOG_DEBUG("do_query_resource sendto %d %s %s", slen, inet_ntoa(qc->from.sin_addr), p->question[0].domain);
	return 0;
}

static int do_query_resource(dns_udp_context_t *up, struct query_context_t *qc, struct dns_question *que);
static int dns_query_continue(dns_udp_context_t *up, struct query_context_t *qc, struct dns_question *que);

static int do_lookup_update(dns_udp_context_t *up, struct query_context_t *qc, const char *alias)
{
	struct dns_parser *p = &qc->parser;
	int offset = p->head.question++;
	struct dns_question *que = &p->question[offset];

	p->question[offset].domain = add_domain(p, alias);
	p->question[offset].type  = p->question[0].type;
	p->question[offset].klass = NSCLASS_INET;
	LOG_DEBUG("do_lookup_update: %d cname %s -> %s", offset, p->question[offset -1].domain, alias);

	qc->iworker = 0; 
	qc->nworker = 0; 
	do_query_resource(up, qc, que);
	return 0;
}

static int dns_query_continue(dns_udp_context_t *up, struct query_context_t *qc, struct dns_question *que)
{
	struct dns_resource *res = NULL;
	struct dns_resource *kes = NULL;
	struct dns_resource answer[256];

	int count = answer_cache_lookup(que->domain, que->type, answer, 256);
	if (count > 0 || qc->is_china_domain) {
		struct query_context_t *c = (struct query_context_t *)qc->assioc_uptr;
		LOG_DEBUG("answer_cache_lookup: result %d %p %p", count, qc, c);
		struct dns_question *que = &qc->parser.question[qc->parser.head.question -1];

		int found = 0;
		const char *alias = NULL;

		for (int i = 0; i < count; i++) {
			res = answer + i;
			if (que->type == res->type) {
				found = 1;
			}

			if (res->type == NSTYPE_CNAME) {
				alias = *(char **)res->value;
				LOG_DEBUG("%s %s", res->domain, alias);
			}
		}

		if (alias != NULL && found == 0) {
			do_lookup_update(up, qc, alias);
			return 0;
		}

		if (qc->assioc_uptr == NULL) {
			do_query_response(up, qc, answer, count, 0);
		} else if (qc != qc->assioc_uptr) {
			qc->refcnt --;
			dns_query_append(c, answer, count);
			if (qc->is_china_domain) c->is_china_domain = 1;
			dns_query_continue(up, c, &c->parser.question[c->parser.head.question -1]);
		}
		return count;
	}

	size_t maxns = 0;

	LOG_DEBUG("continue: %s %d", que->domain, que->type);
	for (int i = 0; i < qc->nworker; i++) {
		res = &qc->worker[i];
		if (res->type == NSTYPE_NS &&
				strlen(res->domain) > maxns) {
			LOG_DEBUG("maxns: %s", res->domain);
			maxns = strlen(res->domain);
		}
	}

	LOG_DEBUG("maxns is: %d %s", maxns, que->domain);
	
	int newns = 0;
	for (int i = 0; i < nauthor; i++) {
		res = &authors[i];
		if (res->type != NSTYPE_NS) continue;

		if (strlen(res->domain) > maxns && 
				strstr(que->domain, res->domain)) {
		    LOG_DEBUG("add ns %s %s %d", res->domain, que->domain, maxns);
			qc->worker[newns++] = *res;
		}
	}

	if (newns > 0) {
		qc->iworker = qc->nworker = newns - 1;
		qc->nworker ++;
	}

	int nscount = qc->nworker;
	for (int i = 0; i < nscount; i++) {
		res = &qc->worker[i];
		if (res->type != NSTYPE_NS) {
			continue;
		}

		char *nsname = *(char **)res->value;
		for (int j = 0; j < nanswer; j++) {
			kes = &answer[j];
			if (kes->type == NSTYPE_A && strcasecmp(nsname, kes->domain) == 0) {
		        LOG_DEBUG("add v4 %s %s", res->domain, kes->domain);

				int target = *(int *)kes->value;
				if (kes->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
					LOG_DEBUG("china domain detect");
					qc->is_china_domain = 1;
				}

				qc->worker[qc->nworker] = *kes;
				qc->iworker = qc->nworker;
				qc->nworker ++;
				res->ttl = 0;
			}
		}

		if (res->ttl == 0) {
			continue;
		}

		for (int j = 0; j < nauthor; j++) {
			kes = &authors[j];
			if (kes->type == NSTYPE_A && strcasecmp(nsname, kes->domain) == 0) {
		        LOG_DEBUG("add v4 %s %s", res->domain, kes->domain);

				int target = *(int *)kes->value;
				if (kes->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
					LOG_DEBUG("china domain detect");
					qc->is_china_domain = 1;
				}

				qc->worker[qc->nworker] = *kes;
				qc->iworker = qc->nworker;
				qc->nworker ++;
				res->ttl = 0;
			}
		}
	}

	if (qc->is_china_domain) {
		dns_query_continue(up, qc, que);
		return 0;
	}

	while (qc->iworker >= 0) {
		res = &qc->worker[qc->iworker];
		qc->iworker--;
		if (res->ttl == 0)
			continue;

		switch (res->type) {
			case NSTYPE_A:
				do_fetch_resource(up, qc->parser.head.ident, que, (struct in_addr *)res->value, res->domain);
				LOG_DEBUG("NSTYPE_A: %s %s\n", res->domain, inet_ntoa(*(struct in_addr*)res->value));
				res->ttl = 0;
				return 0;

			case NSTYPE_NS:
				LOG_DEBUG("NSTYPE_NS: %s %s\n", res->domain, *(char **)res->value);
				do_lookup_nameserver(up, qc, *(char **)res->value);
				qc->refcnt ++;
				res->ttl = 0;
				return 0;

			default:
				assert(0);
				break;
		}
	}

	if (qc->iworker == 0 && qc->refcnt == 0) {
		LOG_DEBUG("no server response");
	}

	return 0;
}

static int do_query_resource(dns_udp_context_t *up, struct query_context_t *qc, struct dns_question *que)
{
	int count;
	struct dns_resource *res = NULL;
	struct dns_resource answer[2560];

	count = answer_cache_lookup(que->domain, que->type, answer, 260);
	if (count > 0 || qc->is_china_domain) {
		struct query_context_t *c = (struct query_context_t *)qc->assioc_uptr;
		LOG_DEBUG("answer_cache_lookup: result %d %p %p", count, qc, c);
		struct dns_question *que = &qc->parser.question[qc->parser.head.question -1];

		int found = 0;
		const char *alias = NULL;

		for (int i = 0; i < count; i++) {
			res = answer + i;
			if (que->type == res->type) {
				found = 1;
			}

			if (res->type == NSTYPE_CNAME) {
				alias = *(char **)res->value;
			}
		}

		if (alias != NULL && found == 0) {
			do_lookup_update(up, qc, alias);
			return 0;
		}

		if (qc->assioc_uptr == NULL) {
			do_query_response(up, qc, answer, count, 0);
		} else if (qc != qc->assioc_uptr) {
			c->refcnt --;
			c->is_china_domain |= qc->is_china_domain;
			dns_query_append(c, answer, count);
			dns_query_continue(up, c, &c->parser.question[c->parser.head.question -1]);
		}
		return count;
	}

	count = author_cache_lookup(que->domain, qc->worker, 260);
	if (count == 0) {
		LOG_DEBUG("author_cache_lookup: %d", count);
		return count;
	}

	if (qc->is_china_domain == 0) {
		for (int i = 0; i < count; i++) {
			res = &qc->worker[i];

			int target = *(int *)res->value;
			if (res->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
				qc->is_china_domain = 1;
	            dns_query_continue(up, qc, que);
				return 0;
			}
		}
	}


	qc->nworker = count;
	qc->iworker = count - 1;
	while (qc->iworker >= 0) {
		res = &qc->worker[qc->iworker];
		qc->iworker--;
		if (res->ttl == 0)
			continue;

		switch (res->type) {
			case NSTYPE_A:
				do_fetch_resource(up, qc->parser.head.ident, que, (struct in_addr *)res->value, res->domain);
				LOG_DEBUG("NSTYPE_A: (0) %s %s\n", res->domain, inet_ntoa(*(struct in_addr*)res->value));
				res->ttl = 0;
				return 0;

			case NSTYPE_NS:
				do_lookup_nameserver(up, qc, *(char **)res->value);
				qc->refcnt ++;
				res->ttl = 0;
				return 0;

			default:
				assert(0);
				break;
		}
	}

	if (qc->iworker == 0 && qc->refcnt == 0) {
		LOG_DEBUG("no server response");
	}

	return 0;
}

static int do_lookup_nameserver(dns_udp_context_t *up, struct query_context_t *qc, const char * domain)
{
	struct query_context_t *outqc = &_query_list[(_qc_next++ & 0xfff)];
	struct dns_parser *p = &outqc->parser;

	memset(outqc, 0, sizeof(*outqc));
	p->head.ident = (_qc_next - 1);
	p->question[0].domain = add_domain(p, domain);
	p->question[0].type = NSTYPE_A;
	p->question[0].klass = NSCLASS_INET;
	p->head.question = 1;
	outqc->assioc_uptr = qc;
	
	outqc->refcnt = 0;
	outqc->iworker = outqc->nworker = 0;
	LOG_DEBUG("query nameserver: %s", domain);
	do_query_resource(up, outqc, &p->question[0]);
	return 0;
}

int dns_forward(dns_udp_context_t *up, char *buf, size_t count, struct sockaddr_in *in_addr1, socklen_t namlen, int fakeresp)
{
    int len;
    int err = 0;

    struct dns_question *que;
    struct dns_parser parser, *pparse;
    static union { struct sockaddr sa; struct sockaddr_in in0; } dns;

    pparse = dns_parse(&parser, (uint8_t *)buf, count);
    if (pparse == NULL || parser.head.question == 0) {
        LOG_DEBUG("FROM: %s dns_forward dns_parse failure %p", inet_ntoa(in_addr1->sin_addr), pparse);
        return -1;
    }

	if (parser.head.flags & 0x8000) {
        LOG_DEBUG("FROM: %s this is not query", inet_ntoa(in_addr1->sin_addr));
		return -1;
	}

	struct query_context_t *qc = &_query_list[parser.head.ident & 0xfff];
	memset(qc, 0, sizeof(*qc));
	dns_parser_copy(&qc->parser, &parser);

	qc->from = *in_addr1;
	qc->iworker = qc->nworker = 0;
	qc->assioc_uptr = 0;
	qc->refcnt = 0;

	assert (qc->parser.head.question == 1);
	// for (int i = 0;  i < qc->parser.head.question; i++) {
		que = &qc->parser.question[0];
		LOG_DEBUG("Q [%d] %s %d", 0, que->domain, que->type);
		const char *domain = que->domain;
		size_t dolen = strlen(domain);
		const char SUFFIXIES[] = ".z.855899.xyz";

		LOG_DEBUG("domain %s %s %d %d", domain, domain + dolen + 1 - sizeof(SUFFIXIES), dolen, sizeof(SUFFIXIES));
		if (dolen > sizeof(SUFFIXIES) &&
				!strcasecmp(SUFFIXIES, domain + dolen + 1 - sizeof(SUFFIXIES))) {
			char _domain[128];
			_domain[sizeof(_domain) -1] = 0;
			strncpy(_domain, que->domain, sizeof(_domain) -1);

			qc->parser.question[1] = qc->parser.question[0];
			qc->parser.head.question++;
			que = &qc->parser.question[1];
			_domain[dolen + 1 - sizeof(SUFFIXIES)] = 0;
			LOG_DEBUG("_domain %s", _domain);
			que->domain = add_domain(&qc->parser, _domain);
		}

		do_query_resource(up, qc, que);
	// }

	return 0;
}

int dns_backward(dns_udp_context_t *up, char *buf, size_t count, struct sockaddr_in *in_addr1, socklen_t namlen, int fakeresp)
{
	int i, is_china_domain = 0;
	struct dns_parser *p;
	struct dns_parser p0 = {};
	struct dns_question *que;
	struct dns_resource *res;

	is_china_domain = NULL == lookupRoute(htonl(in_addr1->sin_addr.s_addr));

	p = dns_parse(&p0, (uint8_t *)buf, count);
    if (p == NULL || p0.head.question == 0) {
        LOG_DEBUG("FROM: %s dns_backward dns_parse failure %p", inet_ntoa(in_addr1->sin_addr), p);
        return -1;
    }

	if (~p->head.flags & 0x8000) {
        LOG_DEBUG("FROM: %s this is not answer", inet_ntoa(in_addr1->sin_addr));
		return -1;
	}

	for (i = 0; i < p->head.answer; i++) {
		res = &p->answer[i];
		if (res->type == NSTYPE_NS) {
			LOG_DEBUG("NS: %s - %s", res->domain, *(char **)(res->value));
		} else if (res->type == NSTYPE_A) {
			LOG_DEBUG("V4: %s - %s", res->domain, inet_ntoa(*(struct in_addr *)res->value));
		} else if (res->type == NSTYPE_CNAME) {
			LOG_DEBUG("CNAME: %s - %s", res->domain, *(char **)(res->value));
		}

        int target = *(int *)res->value;
        if (res->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
            LOG_DEBUG("china domain detect");
			is_china_domain = 1;
        }
	}

	int found_soa = 0;
	for (i = 0; i < p->head.author; i++) {
		res = &p->author[i];
		if (res->type == NSTYPE_NS) {
			LOG_DEBUG("NS: %s - %s", res->domain, *(char **)(res->value));
		} else if (res->type == NSTYPE_A) {
			LOG_DEBUG("V4: %s - %s", res->domain, inet_ntoa(*(struct in_addr *)res->value));
		} else if (res->type == NSTYPE_SOA) {
			LOG_DEBUG("V4: %s - %s", res->domain, inet_ntoa(*(struct in_addr *)res->value));
			found_soa = 1;
		} else if (res->type == NSTYPE_CNAME) {
			LOG_DEBUG("CNAME: %s - %s", res->domain, *(char **)(res->value));
		}
	}

	for (i = 0; i < p->head.addon; i++) {
		res = &p->addon[i];
		if (res->type == NSTYPE_NS) {
			LOG_DEBUG("NS: %s - %s", res->domain, *(char **)(res->value));
		} else if (res->type == NSTYPE_A) {
			LOG_DEBUG("V4: %s - %s", res->domain, inet_ntoa(*(struct in_addr *)res->value));
		} else if (res->type == NSTYPE_CNAME) {
			LOG_DEBUG("CNAME: %s - %s", res->domain, *(char **)(res->value));
		}

        int target = *(int *)res->value;
        if (res->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
            LOG_DEBUG("china domain detect");
			is_china_domain = 1;
        }
	}

	if (is_china_domain == 0)
		hold_to_answer(p0.answer, p0.head.answer, is_china_domain);
	hold_to_author(p0.author, p0.head.author);
	hold_to_author(p0.addon, p0.head.addon);

	struct query_context_t *qc = &_query_list[p->head.ident & 0xfff];

	int offset = qc->parser.head.question;
	que = &qc->parser.question[offset - 1];

	if (found_soa && p->head.answer == 0) {
		LOG_DEBUG("question should finish since SOA");
		if (qc->assioc_uptr != NULL) {
			qc = (struct query_context_t *)qc->assioc_uptr;
			qc->refcnt --;
			LOG_DEBUG("bad namesever found since SOA");
		} else {
			do_query_response(up, qc, p->author, p->head.author, 1);
		}
		return 0;
	}

	qc->is_china_domain |= is_china_domain;
	dns_query_continue(up, qc, que);
	return 0;
}

static void do_dns_udp_recv(void *upp)
{
	int count;
	socklen_t in_len1;
	char buf[2048];
	struct sockaddr_in in_addr1;
	dns_udp_context_t *up = (dns_udp_context_t *)upp;

	while (tx_readable(&up->file)) {
		in_len1 = sizeof(in_addr1);
		count = recvfrom(up->sockfd, buf, sizeof(buf), 0,
				(struct sockaddr *)&in_addr1, &in_len1);
		tx_aincb_update(&up->file, count);
		if (count < 12) {
			// LOG_DEBUG("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
			break;
		}

		dns_forward(up, buf, count, &in_addr1, in_len1, 0);
	}

	while (tx_readable(&up->outgoing)) {
		in_len1 = sizeof(in_addr1);
		count = recvfrom(up->outfd, buf, sizeof(buf), 0,
				(struct sockaddr *)&in_addr1, &in_len1);
		tx_aincb_update(&up->outgoing, count);
		if (count < 12) {
			// LOG_DEBUG("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
			break;
		}

		dns_backward(up, buf, count, &in_addr1, in_len1, 0);
	}

	tx_aincb_active(&up->outgoing, &up->task);
	tx_aincb_active(&up->file, &up->task);
	return ;
}

int txdns_create()
{
	int error;
	int outfd;
	int sockfd;
	int rcvbufsiz = 8192;
	tx_loop_t *loop;
	struct sockaddr_in in_addr1;
	dns_udp_context_t *up = NULL;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	TX_CHECK(sockfd != -1, "create dns socket failure");

	tx_setblockopt(sockfd, 0);
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbufsiz, sizeof(rcvbufsiz));

	in_addr1.sin_family = AF_INET;
	in_addr1.sin_port = htons(53);
	in_addr1.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(sockfd, (struct sockaddr *)&in_addr1, sizeof(in_addr1));
	TX_CHECK(error == 0, "bind dns socket failure");

	outfd = socket(AF_INET, SOCK_DGRAM, 0);
	TX_CHECK(outfd != -1, "create dns out socket failure");

	tx_setblockopt(outfd, 0);
	setsockopt(outfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbufsiz, sizeof(rcvbufsiz));

	in_addr1.sin_family = AF_INET;
	in_addr1.sin_port = 0;
	in_addr1.sin_addr.s_addr = 0;
	error = bind(outfd, (struct sockaddr *)&in_addr1, sizeof(in_addr1));
	TX_CHECK(error == 0, "bind dns out socket failure");

	up = new dns_udp_context_t();
	loop = tx_loop_default();

	up->outfd = outfd;
	tx_aiocb_init(&up->outgoing, loop, outfd);

	up->sockfd = sockfd;
	tx_aiocb_init(&up->file, loop, sockfd);
	tx_task_init(&up->task, loop, do_dns_udp_recv, up);

	tx_aincb_active(&up->file, &up->task);
	tx_aincb_active(&up->outgoing, &up->task);

	return 0;
}

int main(int argc, char *argv[])
{
	int err;
	struct timer_task tmtask;
	struct uptick_task uptick;

	struct tcpip_info relay_address = {0};
	struct tcpip_info listen_address = {0};

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	unsigned int last_tick = 0;
	tx_loop_t *loop = tx_loop_default();
	tx_poll_t *poll = tx_epoll_init(loop);
	tx_timer_ring *provider = tx_timer_ring_get(loop);

	uptick.ticks = 0;
	uptick.last_ticks = tx_getticks();
	tx_task_init(&uptick.task, loop, update_tick, &uptick);
	tx_task_active(&uptick.task, "main");

	tx_timer_init(&tmtask.timer, loop, &tmtask.task);
	tx_task_init(&tmtask.task, loop, update_timer, &tmtask);
	tx_timer_reset(&tmtask.timer, 500);

	txdns_create();
	tx_loop_main(loop);

	tx_timer_stop(&tmtask.timer);
	tx_loop_delete(loop);

	TX_UNUSED(last_tick);

	return 0;
}
