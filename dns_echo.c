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
#include "tx_debug.h"

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#define closesocket close
#endif

struct dns_context {
    int outfd;
    int sockfd;

    socklen_t dnslen;
    struct sockaddr *dnsaddr;

    socklen_t addrlen;
    struct sockaddr *last;
    struct sockaddr_in6 last6[0xffff + 1];
};

#define NSFLAG_QR    0x8000
#define NSFLAG_AA    0x0400
#define NSFLAG_TC    0x0200
#define NSFLAG_RD    0x0100
#define NSFLAG_RA    0x0080
#define NSFLAG_ZERO  0x0070
#define NSFLAG_RCODE 0x000F

#define RCODE_NXDOMAIN 3
#define RCODE_SERVFAIL 2
#define RCODE_REFUSED  5
#define NSCLASS_INET 0x01

struct dns_header {
    uint16_t ident;
    uint16_t flags;
    uint16_t question;
    uint16_t answer;
    uint16_t author;
    uint16_t addon;
};

int do_dns_forward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
	uint16_t ident;
	struct dns_header *h = (struct dns_header *)buf;
	h->flags |= htons(NSFLAG_RD);

	memcpy(&ident, buf, sizeof(ident));
	memcpy(&ctx->last6[ident], from, sizeof(*from));

	ctx->addrlen = sizeof(ctx->last6[0]);
	ctx->last = &ctx->last6[ident];

	int len;
	char tmp[216];

	len = sendto(ctx->outfd, buf, count, 0, ctx->dnsaddr, ctx->dnslen);

	LOG_DEBUG("%04x forward: [%s]:%d %d %d", ident, inet_ntop(AF_INET6, &from->sin6_addr, tmp, 216),
			htons(from->sin6_port), count, len);

	struct sockaddr_in6 *to = (struct sockaddr_in6 *)ctx->dnsaddr;
	LOG_DEBUG("to: [%s]:%d %d %d", inet_ntop(AF_INET6, &to->sin6_addr, tmp, 216),
			htons(to->sin6_port), count, len);
	return 0;
}

int do_dns_backward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
	char tmp[216];
	uint16_t ident;
	memcpy(&ident, buf, sizeof(ident));

#define ADDR(s) (s->sin6_family == AF_INET6? &s->sin6_addr: &((struct sockaddr_in *)s)->sin_addr)

	LOG_DEBUG("%04x backward: af=%d/%d [%s]:%d %d", ident, from->sin6_family, AF_INET6,
			inet_ntop(from->sin6_family, ADDR(from), tmp, 216), htons(from->sin6_port), count);

	ctx->last = &ctx->last6[ident];
	LOG_DEBUG("send: [%s]:%d %d", inet_ntop(AF_INET6, &ctx->last6[ident].sin6_addr, tmp, 216),
			htons(ctx->last6[ident].sin6_port), count);

	sendto(ctx->sockfd, buf, count, 0, ctx->last, ctx->addrlen);
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

    setenv("INCOMING", "0.0.0.0", 0);
    setenv("OUTGOING", "8.8.8.8", 0);

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
	inet_pton(AF_INET6, getenv("INCOMING"), &myaddr6.sin6_addr);
	if (getenv("INCOMING_PORT")) {
		int port = atoi(getenv("INCOMING_PORT"));
		if (port) myaddr6.sin6_port = htons(port);
	}

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

	dnsaddr.sin6_family = AF_INET6;
	dnsaddr.sin6_port   = htons(53);
	inet_pton(AF_INET6,  getenv("OUTGOING"), &dnsaddr.sin6_addr);
	if (getenv("OUTGOING_PORT")) {
		int port = atoi(getenv("OUTGOING_PORT"));
		if (port) myaddr6.sin6_port = htons(port);
	}


	c0.dnsaddr = (struct sockaddr *)&dnsaddr;
	LOG_DEBUG("nsaddr %p pointer %p %d", c0.dnsaddr, &dnsaddr, htons(dnsaddr.sin6_port));

	const struct sockaddr_in6 *inp = (const struct sockaddr_in6 *)&dnsaddr;
	LOG_DEBUG("dns_build bytes %d %d %d %s", 0, inp->sin6_family, htons(inp->sin6_port), getenv("NAMESERVER"));

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
			// LOG_DEBUG("outfd is readable");
			addrl = sizeof(myaddr);
			count = recvfrom(outfd, buf, sizeof(buf), 0, paddr, &addrl);
			assert(count > 0);
			do_dns_backward(&c0, buf, count, &myaddr);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			// LOG_DEBUG("sockfd is readable");
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
