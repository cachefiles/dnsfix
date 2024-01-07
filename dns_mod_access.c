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

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

struct dns_context {
	int sockfd;
};

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

	if (p0.head.question == 0) {
		p0.head.flags |= RCODE_REFUSED;
		p0.head.flags |= NSFLAG_QR;
		dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
		return 0;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int retval;
	int sockfd;

	struct sockaddr_in6 myaddr6;
	struct sockaddr * paddr1 = (struct sockaddr *)&myaddr6;

	setenv("LOCALADDR6", "::ffff:127.9.9.9", 0);

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

	struct dns_context c0 = {
		.sockfd = sockfd,
	};

	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

		retval = select(sockfd + 2, &readfds, 0, 0, 0);
		if (retval == -1) {
			LOG_DEBUG("select failure: %s", strerror(errno));
			break;
		}

		if (FD_ISSET(sockfd, &readfds)) {
			addrl = sizeof(myaddr6);
			count = recvfrom(sockfd, buf, sizeof(buf), 0, paddr1, &addrl);
			count > 0 || LOG_DEBUG("sockfd is readable: %d", count);
			assert(count > 0);
			do_dns_forward(&c0, buf, count, &myaddr6);
		}

	} while (retval >= 0);

	close(sockfd);

	return 0;
}
