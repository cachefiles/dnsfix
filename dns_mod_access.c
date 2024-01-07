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


static int load_client_subnet(struct dns_parser *p0, struct sockaddr_in6 *from)
{
#ifndef DISABLE_SUBNET

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
					info = hold;
					break;
				}
			}
		}
	}

	char cmd[1024];
	if (info != NULL) {
		char buf[256], bytes[16] = {};
		int prefixlen = info->source_netmask;//+ info->scope_netmask;
		size_t subnet_len = 8 + ((7 + prefixlen) >> 3);
		int family = htons(info->family);
		if (family == NS_IPV4) {
			family = AF_INET;
			if (prefixlen == 32) prefixlen = 24;
		} 
		else if (family == NS_IPV6) { 
			family = AF_INET6;
			if (prefixlen > 64) prefixlen = 48;
		}
		memcpy(bytes, info->addr, prefixlen >> 3);
		LOG_DEBUG("subnet family: %d sunet %s/%d", family, inet_ntop(family, bytes, buf, sizeof(buf)), prefixlen);
		if (family == AF_INET6) {
			sprintf(cmd, "ipset add bypass6 %s/%d", buf, prefixlen);
			system(cmd);
		} else {
			sprintf(cmd, "ipset add bypass %s/%d", buf, prefixlen);
			system(cmd);
		}
	} else {
		char buf[256], bytes[16] = {};
        if (IN6_IS_ADDR_V4MAPPED(&from->sin6_addr)) {
			memcpy(bytes, &from->sin6_addr, sizeof(from->sin6_addr));
			bytes[15] = 0;
			inet_ntop(AF_INET, bytes + 12, buf, sizeof(buf));
			sprintf(cmd, "ipset add bypass %s/%d", buf, 24);
			system(cmd);
		}
	}
#endif

	return 0;
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

static int translate_domain(struct dns_parser *pp, char **store, const char *domain)
{
    char buf[1024];
	char *accessp = strcasestr(domain, ".access.");
	if (accessp == NULL) {
		return -1;
	}

	int first_len = accessp - domain;
	memcpy(buf, domain, first_len);
    strcpy(buf + first_len, domain + first_len + 7);
    *store = add_domain(pp, buf);

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

	if (p0.head.question == 0) {
		p0.head.flags |= RCODE_REFUSED;
		p0.head.flags |= NSFLAG_QR;
		dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));
		return 0;
	}

	load_client_subnet(&p0, from);

	p0.head.flags |= NSFLAG_QR;
	if (~p0.head.flags & NSFLAG_RD)
		p0.head.flags |= NSFLAG_AA;

    p0.answer[0].domain = p0.question[0].domain;
    p0.answer[0].type   = NSTYPE_CNAME;
    p0.answer[0].ttl    = 600;
    p0.answer[0].klass  = NSCLASS_INET;
	if (translate_domain(&p0, (char **)p0.answer[0].value, p0.answer[0].domain) == 0) {
		p0.head.addon = 0;
		p0.head.answer++;
	}

	dns_sendto(ctx->sockfd, &p0, from, sizeof(*from));

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
