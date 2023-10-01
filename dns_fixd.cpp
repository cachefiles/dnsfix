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

    for (int j = 0; j < nanswer; j++) {
        res = &answsers[j];
        if (res->type == NSTYPE_CNAME && !strcasecmp(domain, res->domain)) {
            results[count] = *res;
            count++;
        }
    }

	return count;
}

static int hold_to_answer(struct dns_resource *res, size_t count)
{
    int i, j;
    struct dns_resource *f, *t;

    move_to_cache(res, count);

    for (i = 0; i < count; i++) {
        f = res + i;

#if 0
        int target = *(int *)f->value;
        if (f->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
            fprintf(stderr, "china domain detect\n");
            exit(0);
        }
#endif

        int found = 0;
        for (j = 0; j < nanswer; j++) {
            t = &answsers[j];
            if (t->domain == f->domain && t->type == f->type) {
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

static int nauthor = 0;
static struct dns_resource authors[1024] = {};

static int author_cache_lookup(const char *domain, struct dns_resource results[], size_t size)
{
    int count = 0;
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

		for (int j = 0; j < nauthor; j++) {
			res = &authors[j];
			if (res->type == NSTYPE_NS && !strcasecmp(dotname, res->domain)) {
				results[count] = *res;
				count++;
			}
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

    for (i = 0; i < count; i++) {
        f = res + i;

#if 0
        int target = *(int *)f->value;
        if (f->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
            fprintf(stderr, "china domain detect\n");
            exit(0);
        }
#endif

        int found = 0;
        for (j = 0; j < nanswer; j++) {
            t = &authors[j];
            if (t->domain == f->domain && t->type == f->type) {
                *t = *f;
                found = 1;
                break;
            }
        }

        if (found == 0 && NSTYPE_NS == f->type) {
            answsers[nanswer] = *f;
            nanswer++;
        }

        if (found == 0 && NSTYPE_A == f->type) {
            answsers[nanswer] = *f;
            nanswer++;
        }
    }

    return 0;
	return 0;
}

static int _nworker = 0;
static int _iworker = 0;
static struct dns_resource worker[2560];

static int _query_type = 0;
static char _query_domain[128];

static int do_fetch_resource(dns_udp_context_t *up, const char *domain, int type,
		struct in_addr *server, struct dns_resource p[], size_t start, size_t l, const char *server_name)
{
	uint8_t buf[2048];
	struct dns_parser p0 = {};
	struct dns_question *que;
	struct dns_resource *res;
	struct sockaddr_in target = {};

	p0.head.question = 1;
	p0.head.ident = random();
	que = &p0.question[0];
	que->domain = add_domain(&p0, domain);
	que->type   = type;
	que->klass  = NSCLASS_INET;

	size_t len = dns_build(&p0, buf, sizeof(buf));

	target.sin_family = AF_INET;
	target.sin_port   = htons(53);
	target.sin_addr   = *server;

	size_t slen = sendto(up->outfd, buf, len, 0, (struct sockaddr *)&target, sizeof(target));
	LOG_DEBUG("sendto %s/%s data %d %d", server_name, inet_ntoa(*server), len, slen);
}

static int dns_query_continue(dns_udp_context_t *up, const char *domain, int type)
{
	struct dns_resource *res = NULL;
	struct dns_resource answer[2560];

	int count = answer_cache_lookup(domain, type, answer, 2560);
	if (count > 0) {
		LOG_DEBUG("answer_cache_lookup: %d", count);
		return count;
	}

	for (int i = 0; i < _iworker; i++) {
		res = &worker[_iworker];
		if (res->ttl == 0) continue;
		if (res->type == NSTYPE_NS) {
		}
	}

	while (_iworker >= 0) {
		res = &worker[_iworker];
		if (res->ttl == 0)
			continue;

		_iworker--;
		switch (res->type) {
			case NSTYPE_A:
				do_fetch_resource(up, domain, type, (struct in_addr *)res->value, worker, _iworker, 2560, res->domain);
				res->ttl = 0;
				return 0;

			case NSTYPE_NS:
				LOG_DEBUG("NSTYPE_NS: %s %s\n", res->domain, *(char **)res->value);
				break;

			default:
				assert(0);
				break;
		}
	}

	return 0;
}

static int do_query_resource(dns_udp_context_t *up, const char *domain, int type, callback_t cb, void *context)
{
	int count;
	struct dns_resource *res = NULL;
	struct dns_resource answer[2560];

	count = answer_cache_lookup(domain, type, answer, 2560);
	if (count > 0) {
		LOG_DEBUG("answer_cache_lookup: %d", count);
		return count;
	}

	count = author_cache_lookup(domain, worker, 2560);
	if (count == 0) {
		LOG_DEBUG("author_cache_lookup: %d", count);
		return count;
	}

	_nworker = count;
	_iworker = count - 1;
	while (_iworker >= 0) {
		res = &worker[_iworker];
		if (res->ttl == 0)
			continue;
		res->ttl = 0;

		_iworker--;
		switch (res->type) {
			case NSTYPE_A:
				do_fetch_resource(up, domain, type, (struct in_addr *)res->value, worker, _iworker, 2560, res->domain);
				return 0;

			case NSTYPE_NS:
				LOG_DEBUG("NSTYPE_NS: %s %s\n", res->domain, *(char **)res->value);
				break;

			default:
				assert(0);
				break;
		}
	}

	if (domain != _query_domain)
		strcpy(_query_domain, domain);
	_query_type = type;
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
        LOG_DEBUG("FROM: %s dns_forward dns_parse failure", inet_ntoa(in_addr1->sin_addr));
        return -1;
    }

	if (parser.head.flags & 0x8000) {
        LOG_DEBUG("FROM: %s this is not query", inet_ntoa(in_addr1->sin_addr));
		return -1;
	}

	for (int i = 0;  i < parser.head.question; i++) {
		que = &parser.question[i];
		LOG_DEBUG("Q [%d] %s %d", i, que->domain, que->type);
		do_query_resource(up, que->domain, que->type, query_finish, NULL);
	}

	return 0;
}

int dns_backward(dns_udp_context_t *up, char *buf, size_t count, struct sockaddr_in *in_addr1, socklen_t namlen, int fakeresp)
{
	struct dns_parser *p;
	struct dns_parser p0 = {};
	struct dns_question *que;
	struct dns_resource *res;

	p = dns_parse(&p0, (uint8_t *)buf, count);
    if (p == NULL || p0.head.question == 0) {
        LOG_DEBUG("FROM: %s dns_backward dns_parse failure", inet_ntoa(in_addr1->sin_addr));
        return -1;
    }

	if (~p->head.flags & 0x8000) {
        LOG_DEBUG("FROM: %s this is not answer", inet_ntoa(in_addr1->sin_addr));
		return -1;
	}

	hold_to_answer(p0.answer, p0.head.answer);
	hold_to_author(p0.author, p0.head.author);
	hold_to_author(p0.addon, p0.head.addon);

	dns_query_continue(up, _query_domain, _query_type);
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
	in_addr1.sin_port = htons(53530);
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
