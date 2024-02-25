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
#include "dnsproto.h"
#include "subnet_api.h"

#include <txall.h>

struct timer_task {
    tx_task_t task; 
    tx_timer_t timer; 
};

struct udp_exchange_context {
    int sockfd;
    int port;
    int dport;
    tx_aiocb file;
    tx_task_t task;
};

#define HASH_MASK 0xFFFF

typedef struct _nat_conntrack_t {
    int sockfd;
    int mainfd;
    int hash_idx;
    time_t last_alive;
    struct sockaddr_in6 source;
    struct sockaddr_in6 target;

    int port;
    tx_aiocb file;
    tx_task_t task;
    LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

static nat_conntrack_t *_session_last[HASH_MASK + 1] = {};
static LIST_HEAD(nat_conntrack_q, _nat_conntrack_t) _session_header = LIST_HEAD_INITIALIZER(_session_header);

static inline unsigned int get_connection_match_hash(const void *src, const void *dst, uint16_t sport, uint16_t dport)
{
    uint32_t hash = 0, hashs[4];
    uint32_t *srcp = (uint32_t *)src;
    uint32_t *dstp = (uint32_t *)dst;

    hashs[0] = srcp[0] ^ dstp[0];
    hashs[1] = srcp[1] ^ dstp[1];
    hashs[2] = srcp[2] ^ dstp[2];
    hashs[3] = srcp[3] ^ dstp[3];

    hashs[0] = (hashs[0] ^ hashs[1]);
    hashs[2] = (hashs[2] ^ hashs[3]);

    hash = (hashs[0] ^ hashs[2]) ^ sport ^ dport;
    return ((hash >> 16)^ hash) & HASH_MASK;
}

static time_t _session_gc_time = 0;
static int conngc_session(time_t now, nat_conntrack_t *skip)
{
    int timeout = 30;
    if (now < _session_gc_time || now > _session_gc_time + 30) {
        nat_conntrack_t *item, *next;

        _session_gc_time = now;
        LIST_FOREACH_SAFE(item, &_session_header, entry, next) {
            if (item == skip) {
                continue;
            }

            if ((item->last_alive > now) ||
                    (item->last_alive + timeout < now)) {
                LOG_INFO("free datagram connection: %p, %d\n", skip, 0);
                int hash_idx = item->hash_idx;

                if (item == _session_last[hash_idx]) {
                    _session_last[hash_idx] = NULL;
                }

                tx_aiocb_fini(&item->file);
                tx_task_drop(&item->task);
                close(item->sockfd);

                LIST_REMOVE(item, entry);
                free(item);
            }
        }
    }

    return 0;
}

static nat_conntrack_t * lookup_session(struct sockaddr_in6 *from, uint16_t port)
{
    nat_conntrack_t *item;
    static uint32_t ZEROS[4] = {};

    int hash_idx0 = get_connection_match_hash(&from->sin6_addr, ZEROS, port, from->sin6_port);

    item = _session_last[hash_idx0];
    if (item != NULL) {
        if ((item->source.sin6_port == from->sin6_port) && port == item->port &&
                IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
            item->last_alive = time(NULL);
            return item;
        }
    }

    LIST_FOREACH(item, &_session_header, entry) {
        if ((item->source.sin6_port == from->sin6_port) && port == item->port &&
                IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
            item->last_alive = time(NULL);
            assert(hash_idx0 == item->hash_idx);
            _session_last[hash_idx0] = item;
            return item;
        }
    }

    return NULL;
}

static void update_timer(void *up)
{
    struct timer_task *ttp;
    ttp = (struct timer_task*)up;

    tx_timer_reset(&ttp->timer, 50000);
    LOG_INFO("update_timer %d\n", tx_ticks);

    conngc_session(time(NULL), NULL);
    return;
}

#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

static void do_udp_exchange_back(void *upp)
{
    int count;
    socklen_t in_len;
    char buf[2048];

    struct sockaddr_in6 in6addr;
    struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
    nat_conntrack_t *up = (nat_conntrack_t *)upp;

    while (tx_readable(&up->file)) {
        in_len = sizeof(in6addr);
        count = recvfrom(up->sockfd, buf, sizeof(buf), MSG_DONTWAIT, inaddr, &in_len);
        tx_aincb_update(&up->file, count);

        if (count <= 0) {
            LOG_VERBOSE("back recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
            break;
        }

        struct sockaddr *inp = (struct sockaddr *)&up->source;
        count = sendto(up->mainfd, buf, count, MSG_DONTWAIT, inp, sizeof(up->source));
        if (count == -1) {
            LOG_VERBOSE("back sendto len %d, %d, strerr %s", count, errno, strerror(errno));
        }
    }

    tx_aincb_active(&up->file, &up->task);
    return;
}

static nat_conntrack_t * newconn_session(struct sockaddr_in6 *from, int mainfd, int port, int dport)
{
    int sockfd;
    int rcvbufsiz = 4096;

    time_t now;
    nat_conntrack_t *conn;

    now = time(NULL);

    conn = ALLOC_NEW(nat_conntrack_t);
    if (conn != NULL) {
        conn->last_alive = now;
        conn->source = *from;
        conn->target = *from;
        conn->mainfd = mainfd;
        conn->port   = port;
        memset(&conn->target.sin6_addr, 0xff, 12);
        memset(&conn->target.sin6_addr, 0, 10);
		if (getenv("REDIR_HOST"))
			inet_pton(AF_INET6, getenv("REDIR_HOST"), &conn->target.sin6_addr);
        conn->target.sin6_port = htons(dport);

        sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
        TX_CHECK(sockfd != -1, "create udp socket failure");

        tx_setblockopt(sockfd, 0);
        // setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbufsiz, sizeof(rcvbufsiz));
        conn->sockfd = sockfd;

        tx_loop_t *loop = tx_loop_default();
        tx_aiocb_init(&conn->file, loop, sockfd);
        tx_task_init(&conn->task, loop, do_udp_exchange_back, conn);

        tx_aincb_active(&conn->file, &conn->task);

        static uint32_t ZEROS[4] = {};
        conn->hash_idx = get_connection_match_hash(&from->sin6_addr, ZEROS, port, from->sin6_port);
        LIST_INSERT_HEAD(&_session_header, conn, entry);
        _session_last[conn->hash_idx] = conn;
    }

    conngc_session(now, conn);
    return conn;
}

static void do_udp_exchange_recv(void *upp)
{
    int count;
    socklen_t in_len;
    char buf[2048];
    nat_conntrack_t *session = NULL;

    struct sockaddr_in6 in6addr;
    struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
    udp_exchange_context *up = (udp_exchange_context *)upp;

    while (tx_readable(&up->file)) {
        in_len = sizeof(in6addr);
        count = recvfrom(up->sockfd, buf, sizeof(buf), MSG_DONTWAIT, inaddr, &in_len);
        tx_aincb_update(&up->file, count);

        if (count <= 0) {
            LOG_VERBOSE("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
            break;
        }

        session = lookup_session(&in6addr, up->port);
        session = session? session: newconn_session(&in6addr, up->sockfd, up->port, up->dport);
        if (session == NULL) {
            LOG_INFO("session is NULL");
            continue;
        }

        struct sockaddr *inp = (struct sockaddr *)&session->target;
        // buf[0] ^= 0x5a;
        count = sendto(session->sockfd, buf, count, MSG_DONTWAIT, inp, sizeof(session->target));
        if (count == -1) {
            LOG_VERBOSE("sendto len %d, %d, strerr %s", count, errno, strerror(errno));
        }
    }

    tx_aincb_active(&up->file, &up->task);
    return;
}

static void * udp_exchange_create(int port, int dport)
{
    int sockfd;
    int error = -1;
    struct sockaddr_in6 in6addr;

    fprintf(stderr, "udp_exchange_create %d\n", port);
    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    TX_CHECK(sockfd != -1, "create udp socket failure");

    tx_setblockopt(sockfd, 0);
    int rcvbufsiz = 4096;
    // setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbufsiz, sizeof(rcvbufsiz));

    in6addr.sin6_family = AF_INET6;
    in6addr.sin6_port = htons(port);
    in6addr.sin6_addr = in6addr_loopback;
    in6addr.sin6_addr = in6addr_any;

    error = bind(sockfd, (struct sockaddr *)&in6addr, sizeof(in6addr));
    TX_CHECK(error == 0, "bind udp socket failure");

    struct udp_exchange_context *up = NULL;

    up = new udp_exchange_context();
    tx_loop_t *loop = tx_loop_default();

    up->port  = port;
    up->dport  = dport;
    up->sockfd = sockfd;
    tx_aiocb_init(&up->file, loop, sockfd);
    tx_task_init(&up->task, loop, do_udp_exchange_recv, up);

    tx_aincb_active(&up->file, &up->task);

    return 0;
}

int main(int argc, char *argv[])
{
    int err;
    unsigned int last_tick = 0;
    struct timer_task tmtask;

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    tx_loop_t *loop = tx_loop_default();
    tx_poll_t *poll = tx_epoll_init(loop);
    tx_timer_ring *provider = tx_timer_ring_get(loop);
    tx_timer_init(&tmtask.timer, loop, &tmtask.task);

    tx_task_init(&tmtask.task, loop, update_timer, &tmtask);
    tx_timer_reset(&tmtask.timer, 500);

    for (int i = 1; i < argc; i++) {
	int port, dport, match;
        match = sscanf(argv[i], "%d:%d", &port, &dport);
        switch (match) {
            case 1:
                assert (port >  0 && port < 65536);
                udp_exchange_create(port, port);
                break;

            case 2:
                assert (port >  0 && port < 65536);
                assert (dport >  0 && dport < 65536);
                udp_exchange_create(port, dport);
                break;

            default:
                fprintf(stderr, "argument is invalid: %s .%d\n", argv[i], match);
                break;
        }
    }

    tx_loop_main(loop);

    tx_timer_stop(&tmtask.timer);
    tx_loop_delete(loop);

    TX_UNUSED(last_tick);

    return 0;
}
