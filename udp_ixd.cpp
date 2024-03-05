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

static uint32_t _last_rx = 0;
static uint32_t _last_tx = 0;
static uint32_t _total_tx = 0;
static uint32_t _total_rx = 0;
static time_t _last_foobar = 0;

// tx_getticks
static uint32_t _last_rx_tick = 0;
static uint32_t _last_tx_tick = 0;
static uint32_t _first_rx_tick = 0;
static uint32_t _first_tx_tick = 0;

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
    in6_addr address;
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
                LOG_DEBUG("free datagram connection: %p, %d\n", skip, 0);
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

static nat_conntrack_t * lookup_session(struct sockaddr_in6 *from, uint16_t port, in6_addr addr)
{
    nat_conntrack_t *item;

    int hash_idx0 = get_connection_match_hash(&from->sin6_addr, &addr, port, from->sin6_port);

    item = _session_last[hash_idx0];
    if (item != NULL) {
        if ((item->source.sin6_port == from->sin6_port) && port == item->port &&
				IN6_ARE_ADDR_EQUAL(&addr, &item->address) &&
                IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
            item->last_alive = time(NULL);
            return item;
        }
    }

    LIST_FOREACH(item, &_session_header, entry) {
        if ((item->source.sin6_port == from->sin6_port) && port == item->port &&
				IN6_ARE_ADDR_EQUAL(&addr, &item->address) &&
                IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
            item->last_alive = time(NULL);
            assert(hash_idx0 == item->hash_idx);
            _session_last[hash_idx0] = item;
            return item;
        }
    }

    return NULL;
}

#define NONZERO(x) (x > 1? x: 1)
static uint64_t _tx_bytes = 0;
static uint64_t _rx_bytes = 0;
static char _last_log[4096] = {};

static void showbar(const char *title, size_t count)
{
	time_t foobar = 0;
	time_t delta  = _last_foobar ^ time(&foobar);

	if ((delta >> 1) == 0) {
		return;
	}

	int tx_rate = (_total_tx - _last_tx) * 1000 / NONZERO(_last_tx_tick - _first_tx_tick);
	int rx_rate = (_total_rx - _last_rx) * 1000 / NONZERO(_last_rx_tick - _first_rx_tick);

	_rx_bytes += (_total_rx - _last_rx);
	_tx_bytes += (_total_tx - _last_tx);

	LOG_INFO("%s len %d, rx/tx total: %ld/%ld rate: %d/%d ", title, count, _tx_bytes, _rx_bytes, tx_rate, rx_rate);
	LOG_INFO("%s", _last_log);
	_last_log[0] = 0;
	_first_tx_tick = _first_rx_tick = 0;
	// _first_rx_tick = _first_tx_tick = tx_getticks();

	_last_foobar = foobar;
	_last_tx = _total_tx;
	_last_rx = _total_rx;
}

static void update_timer(void *up)
{
    struct timer_task *ttp;
    ttp = (struct timer_task*)up;

    tx_timer_reset(&ttp->timer, 5000);
	log_set_lastbuf(NULL, 0);
    LOG_DEBUG("update_timer %d\n", tx_ticks);
	showbar("showbar", 0);
	log_set_lastbuf(_last_log, sizeof(_last_log));

    conngc_session(time(NULL), NULL);
    return;
}

#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

static int convert_from_ipv4(void *ipv6, const void *ipv4)
{
	unsigned *dest = (unsigned *)ipv6;
	const unsigned *from = (const unsigned *)ipv4;

	dest[0] = dest[1] = dest[2] = 0;
	dest[2] = htonl(0xffff);
	dest[3] = from[0];

    return 0;
}

static int udp6_recvmsg(int fd, void *buf, size_t len, int flags, struct sockaddr_in6 *from, struct sockaddr_in6 *dst)
{
    int count;
    struct iovec iovec[1];
    struct msghdr msg;
    char msg_control[1024];

    iovec[0].iov_base = buf;
    iovec[0].iov_len  = len;

    msg.msg_flags = 0;
    msg.msg_name = from;
    msg.msg_namelen = sizeof(*from);

    msg.msg_iov = iovec;
    msg.msg_iovlen = sizeof(iovec) / sizeof(*iovec);

    msg.msg_control = msg_control;
    msg.msg_controllen = sizeof(msg_control);

    count = recvmsg(fd, &msg, flags);

    if (count > 0) {
        struct cmsghdr *cmsg;
        for(cmsg = CMSG_FIRSTHDR(&msg);
                cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *info = (struct in_pktinfo*)CMSG_DATA(cmsg);
                LOG_VERBOSE("message received on address %s\n", inet_ntoa(info->ipi_addr));
				convert_from_ipv4(&dst->sin6_addr, &info->ipi_addr);
            }

            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
				char b[63];
                struct in6_pktinfo *info = (struct in6_pktinfo*)CMSG_DATA(cmsg);
                LOG_VERBOSE("message received on address %s\n", inet_ntop(AF_INET6, &info->ipi6_addr, b, sizeof(b)));
				dst->sin6_addr = info->ipi6_addr;
            }
        }
    }

    return count;
}

static int udp6_sendmsg(int fd, const void *buf, size_t len, int flags, const struct sockaddr_in6 *from, const struct sockaddr_in6 *dest)
{
    struct msghdr msg;
    struct iovec iovec[1];
    char msg_control[1024];

    iovec[0].iov_len  = len;
    iovec[0].iov_base = (void *)buf;

    msg.msg_flags = 0;
    msg.msg_name = (void *)dest;
    msg.msg_namelen = sizeof(*dest);

    msg.msg_iov = iovec;
    msg.msg_iovlen = sizeof(iovec) / sizeof(*iovec);

    msg.msg_control = msg_control;
    msg.msg_controllen = sizeof(msg_control);

    int cmsg_space = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    const int have_in6_pktinfo = 1, have_in_pktinfo = 0;

    if (have_in6_pktinfo) {
        struct in6_pktinfo in6_pktinfo = {};
		in6_pktinfo.ipi6_addr = from->sin6_addr;

		char b[63];
		LOG_VERBOSE("message send to address %s\n", inet_ntop(AF_INET6, &from->sin6_addr, b, sizeof(b)));

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
        *(struct in6_pktinfo*)CMSG_DATA(cmsg) = in6_pktinfo;
        cmsg_space += CMSG_SPACE(sizeof(in6_pktinfo));
    }

    if (have_in_pktinfo) {
        struct in_pktinfo in_pktinfo = {};
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
        *(struct in_pktinfo*)CMSG_DATA(cmsg) = in_pktinfo;
        cmsg_space += CMSG_SPACE(sizeof(in_pktinfo));
    }

    msg.msg_controllen = cmsg_space;

    return sendmsg(fd, &msg, flags);
}

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
			LOG_VERBOSE("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
            break;
        }

        struct sockaddr *inp = (struct sockaddr *)&up->source;
		struct sockaddr_in6 dest = {.sin6_addr = up->address};
        count = udp6_sendmsg(up->mainfd, buf, count, MSG_DONTWAIT, &dest, &up->source);
        if (count == -1) {
            LOG_DEBUG("back sendto len %d, %d, strerr %s", count, errno, strerror(errno));
        }

		if (count > 0) {
			if (!_first_tx_tick) _first_tx_tick = tx_getticks();
			_last_tx_tick = tx_getticks();
			_total_tx += count;
		}
    }

    tx_aincb_active(&up->file, &up->task);
    return;
}

static nat_conntrack_t * newconn_session(struct sockaddr_in6 *from, int mainfd, int port, int dport, in6_addr addr)
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
		conn->address = addr;
        memset(&conn->target.sin6_addr, 0xff, 12);
        memset(&conn->target.sin6_addr, 0, 10);
		if (getenv("REDIR_HOST"))
			inet_pton(AF_INET6, getenv("REDIR_HOST"), &conn->target.sin6_addr);
        conn->target.sin6_port = htons(dport);

        sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
        TX_CHECK(sockfd != -1, "create udp socket failure");

        tx_setblockopt(sockfd, 0);
        // setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));

		int sndbufsiz = 1638400;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));
        conn->sockfd = sockfd;

        tx_loop_t *loop = tx_loop_default();
        tx_aiocb_init(&conn->file, loop, sockfd);
        tx_task_init(&conn->task, loop, do_udp_exchange_back, conn);

        tx_aincb_active(&conn->file, &conn->task);

        conn->hash_idx = get_connection_match_hash(&from->sin6_addr, &addr, port, from->sin6_port);
        LIST_INSERT_HEAD(&_session_header, conn, entry);
        _session_last[conn->hash_idx] = conn;
    }

    conngc_session(now, conn);
    return conn;
}

static int _XOR_MASK_ = 0x5a;

static void do_udp_exchange_recv(void *upp)
{
    int count;
    socklen_t in_len;
    char buf[2048];
    nat_conntrack_t *session = NULL;

    struct sockaddr_in6 in6addr;
    struct sockaddr_in6 dest;
    struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
    udp_exchange_context *up = (udp_exchange_context *)upp;

    while (tx_readable(&up->file)) {
        in_len = sizeof(in6addr);
        count = udp6_recvmsg(up->sockfd, buf, sizeof(buf), MSG_DONTWAIT, &in6addr, &dest);
        tx_aincb_update(&up->file, count);

        if (count <= 0) {
			LOG_VERBOSE("back recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
            break;
        }

		_total_rx += count;
		if (!_first_rx_tick) _first_rx_tick = tx_getticks();
		_last_rx_tick = tx_getticks();

        session = lookup_session(&in6addr, up->port, dest.sin6_addr);
        session = session? session: newconn_session(&in6addr, up->sockfd, up->port, up->dport, dest.sin6_addr);
        if (session == NULL) {
            LOG_DEBUG("session is NULL");
            continue;
        }

        struct sockaddr *inp = (struct sockaddr *)&session->target;
        buf[0] ^= _XOR_MASK_;
		int padding = 0;
		struct sockaddr_in6 trop;
		trop.sin6_family = AF_INET6;
		trop.sin6_port   = htons(443);

		if (getenv("PING")) {
			memcpy(buf + count, ((uint32_t *)&dest.sin6_addr) + 3, 4);
			padding = 4;
		} else if (getenv("PONG")) {
			uint32_t *troping = (uint32_t *)&trop.sin6_addr;
			troping[0] = troping[1] = 0; troping[2] = htonl(0xffff);
			memcpy(troping + 3, buf + count - 4, 4);
			padding = -4;
			inp = (struct sockaddr *)&trop;
		}

        count = sendto(session->sockfd, buf, count + padding, MSG_DONTWAIT, inp, sizeof(session->target));
        if (count == -1) {
            LOG_DEBUG("sendto len %d, %d, strerr %s", count, errno, strerror(errno));
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
    // setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbufsiz, sizeof(rcvbufsiz));
	int sndbufsiz = 1638400;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));

    in6addr.sin6_family = AF_INET6;
    in6addr.sin6_port = htons(port);
    in6addr.sin6_addr = in6addr_loopback;
    in6addr.sin6_addr = in6addr_any;

	int yes = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes));
	setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
	setsockopt(sockfd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes));

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
		if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
			_XOR_MASK_ = atoi(argv[++i]);
			continue;
		}
 
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

	log_set_lastbuf(_last_log, sizeof(_last_log));
    tx_loop_main(loop);

    tx_timer_stop(&tmtask.timer);
    tx_loop_delete(loop);

    TX_UNUSED(last_tick);

    return 0;
}
