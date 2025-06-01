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
#include <net/if.h>
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
#define ARRAY_COUNT(array) (sizeof(array)/sizeof(array[0]))
struct data_t {
	void *buf;
	size_t len;
};

struct pair_t {
	struct data_t key;
	struct data_t value;
};

struct cache_t {
	size_t total;
	struct pair_t list[0x1000];
};

static struct cache_t _g_pool;

struct dns_context {
	int outfd;
	int sockfd;

	socklen_t dnslen;
	struct sockaddr *dnsaddr;
	struct sockaddr *qualaaddr;
};

struct zip_parser {
	char buf[1500];
	int len;
};

struct dns_query_context {
	int is_china_domain;
	int is_nonchina_domain;
	struct data_t key;
	struct sockaddr_in6 from;
	struct zip_parser parser, ecs_parser, def_parser;
};

static struct dns_query_context _orig_list[0x1000];
static int cache_reset(struct cache_t *pool)
{
	int i;
	struct pair_t *item;

	for (i = 0; i < pool->total; i++) {
		item = &pool->list[i];
		free(item->value.buf);
		item->value.buf = NULL;

		free(item->key.buf);
		item->key.buf = NULL;
	}
	pool->total = 0;

	return 0;
}

static int cache_lookup(struct cache_t *pool, const struct data_t *key, struct data_t *value)
{
	int i;
	struct pair_t item;

	for (i = 0; i < pool->total; i++) {
		item = pool->list[i];
		if ((key->len == item.key.len) &&
				(key->buf == item.key.buf || 
				 memcmp(key->buf, item.key.buf, key->len) == 0)) {
			value->len = item.value.len;
			value->buf = item.value.buf;
			return i;
		}
	}

	return -1;
}

static int cache_update(struct cache_t *pool, const struct data_t *key, const struct data_t *value)
{
	struct data_t item;
	struct pair_t *pair;

	int index = cache_lookup(pool, key, &item);

	{
		const uint16_t *src = (uint16_t *)key->buf;
		const uint16_t *dst = (uint16_t *)value->buf;
		LOG_DEBUG("cache_lookup: TODO:XXX %d ", memcmp(dst + 6, src + 5, key->len -10));
		LOG_DEBUG("cache_lookup: TODO:XXX %d %d %d %d", htons(src[1]), htons(src[2]), htons(src[3]), htons(src[4]));
		LOG_DEBUG("cache_lookup: TODO:XXX %d %d %d %d", htons(dst[2]), htons(dst[3]), htons(dst[4]), htons(dst[5]));
	}

	if (index >= 0) {
		pair = &pool->list[index];
		if (pair->value.buf == value->buf) {
			assert(pair->value.len == value->len);
			return 0;
		} else if (pair->value.buf != NULL) {
			free(pair->value.buf);
		} else {
			assert(pair->value.buf);
		}
		pair->value.buf = malloc(value->len);
		memcpy(pair->value.buf, value->buf, value->len);
		pair->value.len = value->len;
		return 0;
	} else if (pool->total + 1 < ARRAY_COUNT(pool->list)) {
		index = pool->total++;
		pair = &pool->list[index];

		pair->value.buf = malloc(value->len);
		assert(pair->value.buf != NULL);

		memcpy(pair->value.buf, value->buf, value->len);
		pair->value.len = value->len;

		pair->key.buf = malloc(key->len);
		assert(pair->key.buf != NULL);

		memcpy(pair->key.buf, key->buf, key->len);
		pair->key.len = key->len;
		return 0;
	}

	return -1;
}

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

static void xxdump(const char *title, const void *buf, size_t len)
{
	int i;
	const uint8_t *data = (const uint8_t *)buf;
	const char MAP[17] = "0123456789abcdef";
	char buf1[11111];
	char *ptr = buf1;

	for (i = 0; i < len; i++) {
		assert(ptr - buf1 + 2 < sizeof(buf1));
		uint8_t d = data[i];
		*ptr++ = MAP[d >> 4];
		*ptr++ = MAP[d & 0xf];
	}
	*ptr = 0;

	LOG_DEBUG("%s: %s", title, buf1);

	return ;
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

	size_t datalen = dns_build(&p0, buf, 2048);
	if (datalen == -1 || datalen > 1500) {
		LOG_DEBUG("do_dns_forward refill failure");
		return 0;
	};

	if (p0.head.question == 0 || p0.head.flags & 0x8000) {
		LOG_DEBUG("FROM: %s this is not query", "nothing");
		return -1;
	}

	{
		struct data_t item, value;
		char *keybuf = (char *)buf;
		struct cache_t *pool = &_g_pool;

		item.buf = keybuf + 2; // skip ident
		item.len = count - 2;
		xxdump("data", item.buf, item.len);

		int index = cache_lookup(pool, &item, &value);
		LOG_DEBUG("cache is lookup: %d %d vallen %d", count, index, value.len);
		if (index >= 0 && value.len > count) {
			memcpy(value.buf, keybuf, 2);
			sendto(ctx->sockfd, value.buf, value.len, 0, (struct sockaddr *)from, sizeof(*from));
			return 0;
		}

	}

	int retval = 0;
	int offset = (p0.head.ident & 0xfff);

	struct dns_query_context *qc = &_orig_list[offset];
	if (qc->key.len > 0) {
		qc->key.len = 0;
		free(qc->key.buf);
		qc->key.buf = NULL;
	}

	struct sockaddr *dnsaddr = ctx->qualaaddr;
	size_t dnslen = ctx->dnslen;

	if (p0.question[0].type == NSTYPE_AAAA) {
		dnsaddr = ctx->qualaaddr;
	} else if (p0.question[0].type == NSTYPE_A) {
		dnsaddr = ctx->dnsaddr;
	}

	retval = dns_sendto(ctx->outfd, &p0, dnsaddr, dnslen);
	if (retval == -1) {
		LOG_DEBUG("dns_sendto failure");
		return 0;
	}

	memset(qc, 0, sizeof(*qc));
	qc->from = *from;
	qc->key.len = count;
	qc->key.buf = malloc(count);
	memcpy(qc->key.buf, buf, count);

	return 0;
}

int do_dns_backward(struct dns_context *ctx, void *buf, int count, struct sockaddr_in6 *from)
{
	struct dns_parser p0;
	struct dns_parser *pp;

	LOG_DEBUG("count %d", count);

	pp = dns_parse(&p0, buf, count);
	if (pp == NULL) {
		LOG_DEBUG("do_dns_backward parse failure");
		return 0;
	}

	if (~p0.head.flags & htons(0x80)) {
		LOG_DEBUG("FROM: %s this is not response", ntop6(from->sin6_addr));
		return -1;
	}

	int offset = (p0.head.ident & 0xfff);
	struct dns_query_context *qc = &_orig_list[offset];
	LOG_DEBUG("cache_update: %d\n", qc->key.len);
	if (qc->key.len > 0) {
		struct data_t key, value;
		char *keybuf = (char *)qc->key.buf;
		key.len = qc->key.len - 2;
		key.buf = keybuf + 2;

		value.buf = buf;
		value.len = count;
		
		cache_update(&_g_pool, &key, &value);
		free(qc->key.buf);
		qc->key.buf = NULL;
		qc->key.len = 0;
	}

	dns_sendto(ctx->sockfd, &p0, (struct sockaddr *)&qc->from, sizeof(qc->from));

	return 0;
}

static void parse_sockaddr(const char *src, struct sockaddr_in6 *dst)
{
	char *data = strdup(src);
	char *per = data;
	int nalpha = 0;
	int colon = 0;
	int ndot = 0;
	int ndiv = -1;
	int i;

	for (i = 0; src[i] && colon < 2; i++) {
		if (src[i] == ':') colon++;
		if (src[i] == '.') ndot++;
		if (src[i] == '%') ndiv = i;
		if (isalpha(src[i])) nalpha++;
	}

	// [ipv6] [ipv6]:port
	if (*per == '[') {
		char *ipv6 = ++per;

		while (*per != ']' && *per != 0) per++;
		if (*per == ']')
			*per++ = 0;

		if (ndiv != -1) {
			data[ndiv] = 0;
			dst->sin6_scope_id = if_nametoindex(data + ndiv + 1);
		}

		inet_pton(AF_INET6, ipv6, &dst->sin6_addr);
		if (*per == ':')
			dst->sin6_port = htons(atoi(per + 1));
		return;
	}

	// ipv6: x::x
	if (colon >= 2) {
		LOG_DEBUG("IPV6: %s", src);
		inet_pton(AF_INET6, src, &dst->sin6_addr);
		if (ndiv != -1) {
			data[ndiv] = 0;
			dst->sin6_scope_id = if_nametoindex(data + ndiv + 1);
		}
		return;
	}

	// domain domain:port
	if (nalpha) {
		return;
	}

	// xx.xx.xx.xx xx.xx.xx.xx:port
	if (ndot) {
		char buf[56];
		while (*per != ':' && *per != 0) per++;
		if (*per == ':')
			*per++ = 0;
		sprintf(buf, "::ffff:%s", data);
		inet_pton(AF_INET6, buf, &dst->sin6_addr);
		if (*per) dst->sin6_port == htons(atoi(per));
		return;
	}

	// port
	dst->sin6_port == htons(atoi(src));
}

#define get_score_id(ifname) if_nametoindex(ifname)
// #define get_score_id(ifname) 0

int main(int argc, char *argv[])
{
	int retval;
	int outfd, sockfd;
	struct sockaddr_in6 myaddr;
	struct sockaddr * paddr = (struct sockaddr *)&myaddr;

	struct sockaddr_in6 myaddr6;
	struct sockaddr * paddr6 = (struct sockaddr *)&myaddr6;
	setenv("BINDLOCAL", "::ffff:127.0.0.111", 0);
	LOG_DEBUG("memory: %lu %lu %lu\n", sizeof(_orig_list), sizeof(_orig_list[0]), sizeof(_orig_list[0].parser));

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
	struct sockaddr_in6 qualaaddr;

	struct dns_context c0 = {
		.outfd = outfd,
		.sockfd = sockfd,
		.dnslen  = sizeof(dnsaddr),
	};

	setenv("NAMESERVER", "[::ffff:8.8.8.8]:53", 0);
	setenv("QUALASERVER", "[::ffff:8.8.8.8]:53", 0);

	dnsaddr.sin6_family = AF_INET6;
	dnsaddr.sin6_port   = htons(53);
	dnsaddr.sin6_addr   = in6addr_loopback;
	parse_sockaddr(getenv("NAMESERVER"), &dnsaddr);

	qualaaddr.sin6_family = AF_INET6;
	qualaaddr.sin6_port   = htons(53);
	qualaaddr.sin6_addr   = in6addr_loopback;
	parse_sockaddr(getenv("QUALASERVER"), &qualaaddr);

	char i6buf[64];
	LOG_DEBUG("NAMESERVER: %s :%d", inet_ntop(AF_INET6, &dnsaddr.sin6_addr, i6buf, sizeof(i6buf)), htons(dnsaddr.sin6_port));
	LOG_DEBUG("QUALASERVER: %s :%d", inet_ntop(AF_INET6, &qualaaddr.sin6_addr, i6buf, sizeof(i6buf)), htons(dnsaddr.sin6_port));

	c0.dnsaddr = (struct sockaddr *)&dnsaddr;
	c0.qualaaddr = (struct sockaddr *)&qualaaddr;
	LOG_DEBUG("nsaddr %p pointer %p %d", c0.dnsaddr, &dnsaddr, htons(dnsaddr.sin6_port));

	const struct sockaddr_in6 *inp = (const struct sockaddr_in6 *)&dnsaddr;
	LOG_DEBUG("dns_build bytes %d %d %d %s", 0, inp->sin6_family, htons(inp->sin6_port), ntop6(inp->sin6_addr));

	time_t uptime = time(NULL);

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

		if (uptime > time(NULL) || uptime + 600 < time(NULL) || _g_pool.total + 2 > ARRAY_COUNT(_g_pool.list)) {
			cache_reset(&_g_pool);
			uptime = time(NULL);
		}

	} while (retval >= 0);

	close(sockfd);
	close(outfd);

	return 0;
}
