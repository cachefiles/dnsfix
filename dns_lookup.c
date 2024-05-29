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

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
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

#define NS_PTR(p) *(const char **)p
#define LOG_DEBUG(fmt...)

struct root_server {
	char domain[32];
	int ttl;
	char ipv4[32];
	char ipv6[132];
};

static struct root_server _root_servers[]= {
	{"a.root-servers.net", 518400, "198.41.0.4", "2001:503:ba3e::2:30"},
	{"b.root-servers.net", 518400, "199.9.14.201", "2001:500:200::b"},
	{"c.root-servers.net", 518400, "192.33.4.12", "2001:500:2::c"},
	{"d.root-servers.net", 518400, "199.7.91.13", "2001:500:2d::d"},
	{"e.root-servers.net", 518400, "192.203.230.10", "2001:500:a8::e"},
	{"f.root-servers.net", 518400, "192.5.5.241", "2001:500:2f::f"},
	{"g.root-servers.net", 518400, "192.112.36.4", "2001:500:12::d0d"},
	{"h.root-servers.net", 518400, "198.97.190.53", "2001:500:1::53"},
	{"i.root-servers.net", 518400, "192.36.148.17", "2001:7fe::53"},
	{"j.root-servers.net", 518400, "192.58.128.30", "2001:503:c27::2:30"},
	{"k.root-servers.net", 518400, "193.0.14.129", "2001:7fd::1"},
	{"l.root-servers.net", 518400, "199.7.83.42", "2001:500:9f::42"},
	{"m.root-servers.net", 518400, "202.12.27.33", "2001:dc3::35"}
};

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
static int ncache = 0;
static struct dns_resource caches[1024] = {};

static int npendings = 0;
static struct dns_question pendings[1024] = {};
int is_query_pending(const char *domain, int type)
{
	int i;
	struct dns_question *que;

	for (i = 0; i < npendings; i++) {
		que = pendings + i;
		if (!strcasecmp(domain, que->domain) && type == que->type) {
			return 1;
		}
		
	}

	return 0;
    
}

int set_query_pending(const char *domain, int type)
{
	int i;
	struct dns_question que;

	if (is_query_pending(domain, type)) {
		return 0;
	}

	que.domain = domain;
	que.type = type;
	pendings[npendings++] = que;

	return 0;
    
}

int unset_query_pending(const char *domain, int type)
{
	int i;
	struct dns_question *que;

	for (i = 0; i < npendings; i++) {
		que = pendings + i;
		if (!strcasecmp(domain, que->domain) && type == que->type) {
			pendings[i] = pendings[--npendings];
			return 1;
		}
		
	}

	return 0;
    
}

int contains(const char *domain, const char *suffix)
{
	int full, part;
	full = strlen(domain);
	part = strlen(suffix);
	if (full == part) return !strcasecmp(domain, suffix);
	return full > part && !strcasecmp(domain + full - part, suffix) && domain[full - part - 1] == '.';
}


static int build_name_server(const char *domain, struct dns_resource p[], size_t l)
{
	int i;
	int nserver = ARRAY_SIZE(_root_servers);

	if (nserver > l)
		nserver = l;

	struct dns_resource tpl =  {
		.type = NSTYPE_NS,
		.klass = NSCLASS_INET,
		.ttl = 0,
		.len = 8,
		.flags = 0,
		.domain = "",
		.value = {}
	};

	for (i = 0; i < nserver; i++) {
		p[i] = tpl;
		const char *ptr =  _root_servers[i].domain;
		memcpy(p[i].value, &ptr, sizeof(ptr));
	}

	for (int j = 0; j < ncache; j++) {
		struct dns_resource *res = &caches[j];
		if (res->type == NSTYPE_NS &&
				contains(domain, res->domain)) {
			p[nserver++] = caches[j];
		}
	}

	return nserver;
}

static int lookup_cache(const char *domain, int type, struct dns_resource p[], size_t l)
{
	int count = 0;

	for (int j = 0; j < ncache; j++) {
		struct dns_resource *res = &caches[j];
		if (res->type == type && strcasecmp(domain, res->domain) == 0) {
			p[count] = *res;
			count++;
		}

		if (res->type == NSTYPE_CNAME && strcasecmp(domain, res->domain) == 0) {
			p[0] = *res;
			return 1;
		}
	}

	if (count > 0) {
		LOG_DEBUG("lookup_cache domain %s type %d\n", domain, type);
		return count;
	}

	return 0;
}

static int hold_to_cache(struct dns_resource *res, size_t count)
{
	int i, j;
	struct dns_resource *f, *t;

	cache_put(res, count);

	for (i = 0; i < count; i++) {
		f = res + i;

		int src = 0, dst = 0;
		for (j = 0; j < ncache; j++) {
			t = &caches[j];
			if (t->domain == f->domain && t->type == f->type)
				continue;
			if (src < j)
				caches[src] = caches[j];
			src++;
		}
		ncache = src;
	}

	for (i = 0; i < count; i++) {
		f = res + i;
		caches[ncache] = *f;
		ncache++;
	}
	
	return 0;
}

static int search(const char *domain, struct dns_resource p[], size_t l)
{
	int i; 
	struct dns_resource *res;

	for (i = 0; i < l; i++) {
		res = &p[i];
		// const char *ns = NS_PTR(res->value);
		if (res->type == NSTYPE_NS && !strcasecmp(res->domain, domain)) {
			return 1;
		}
	}

	return 0;
}

#define NSFLAG_QR    0x8000
#define NSFLAG_AA    0x0400

static const char *inet_4to6(void *v6ptr, const void *v4ptr)
{
    uint8_t *v4 = (uint8_t *)v4ptr;
    uint8_t *v6 = (uint8_t *)v6ptr;

    memset(v6, 0, 10);
    v6[10] = 0xff;
    v6[11] = 0xff;

    v6[12] = v4[0];
    v6[13] = v4[1];
    v6[14] = v4[2];
    v6[15] = v4[3];
    return "";
}

int wait_readable(int sockfd, int millsec)
{
	int check;
	fd_set readfds;
	struct timeval timeout = {
		.tv_sec = millsec/1000,
		.tv_usec = (millsec % 1000) * 1000
	};

	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);

	check = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
	return check > 0;
}

static int fetch_resource(const char *domain, int type, const struct in6_addr *server, struct dns_resource p[], size_t start, size_t l, const char *server_name, int *got_author)
{
	int i;
	int len;
	int sockfd;
	uint8_t buf[2048];
	struct dns_question *que;
	struct dns_resource *res;
	struct dns_parser parser = {};
	struct sockaddr_in6 dest = {};

	parser.head.flags = 0;
	parser.head.question = 1;
	que = &parser.question[0];
	que->domain = add_domain(&parser, domain);
	que->type   = type;
	que->klass  = NSCLASS_INET;

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	
	parser.head.ident = random();
	len = dns_build(&parser, buf, sizeof(buf));

	dest.sin6_family = AF_INET6;
	dest.sin6_port   = htons(53);
	dest.sin6_addr   = *server;

	len = sendto(sockfd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest));
	LOG_DEBUG("domain=%s send=%d to=%s %s\n", domain, len, ntop6(dest.sin6_addr), server_name);
	if (len > 0 && !wait_readable(sockfd, 400)) {
		len = sendto(sockfd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest));
		LOG_DEBUG("retry domain=%s send=%d to=%s %s\n", domain, len, ntop6(dest.sin6_addr), server_name);
	}

	if (len <= 0 || !wait_readable(sockfd, 1000)) {
		LOG_DEBUG("failure or timeout\n");
		printf("failure or timeout\n");
		return start;
	}

	socklen_t destlen = sizeof(dest);
	len = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&dest, &destlen);
	LOG_DEBUG("domain=%s recv=%d\n", domain, len);
	printf("domain=%s send=%d to=%s %s len=%d\n", domain, len, ntop6(dest.sin6_addr), server_name, len);

	close(sockfd);

	if (len < 12)
		return 0;

	memset(&parser, 0, sizeof(parser));
	if (NULL == dns_parse(&parser, buf, len)) {
		LOG_DEBUG("dns_parse failure\n");
		return 0;
	}

	if (~parser.head.flags & 0x8000) {
		LOG_DEBUG("not response\n");
		return 0;
	}

	if (parser.head.question != 1 || parser.head.answer + parser.head.author == 0) {
		LOG_DEBUG("not response correct\n");
		return 0;
	}

	que = &parser.question[0];

	int ans = start;
	const char * origin = que->domain;

	for (i = 0; i < parser.head.answer; i++) {
		res = &parser.answer[i];

		// fprintf(stderr, "anser: %s, domain: %s type %d\n", origin, res->domain, res->type);
		if (strcasecmp(origin, res->domain) == 0 && res->type == type) {
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		} else if (strcasecmp(origin, res->domain) == 0 &&
				res->type == NSTYPE_CNAME) {
			char **ptr = (char **)res->value;
			// fprintf(stderr, "cname %s -> %s\n", domain, *ptr);
			domain = *ptr;
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
#if 0
		} else if (contains(origin, res->domain) &&
				res->type == NSTYPE_NS) {
			const char **ptr = (const char **)res->value;
			fprintf(stderr, "NS: %s\n", *ptr);
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
#endif
		}
	}

	*got_author = ans > start || !!(parser.head.flags & NSFLAG_AA);
	if (ans > start || (parser.head.flags & NSFLAG_AA)) {
		// fprintf(stderr, "ans: %d\n", ans);
		hold_to_cache(p, ans);
		return ans > start? ans: 0;
	}


	for (i = 0; i < parser.head.author; i++) {
		res = &parser.author[i];

		// fprintf(stderr, "author: %s, domain: %s type %d type %d\n", origin, res->domain, res->type, type);
#if 0
		if (strcasecmp(origin, res->domain) == 0 && res->type == type) {
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		} else if (strcasecmp(origin, res->domain) == 0 &&
				res->type == NSTYPE_CNAME) {
			char **ptr = (char **)res->value;
			domain = *ptr;
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		} else 
#endif
			if (contains(origin, res->domain) &&
				res->type == NSTYPE_NS) {
			const char *ptr = NS_PTR(res->value);
			LOG_DEBUG("NS: %s zone: %s\n", ptr, res->domain);
			if (ans < l && !search(res->domain, p, start)) {
				p[ans] = *res;
				ans++;
			}
		}
	}

	int oldans = ans;
	for (i = 0; i < parser.head.addon; i++) {
		res = &parser.addon[i];

		// fprintf(stderr, "addon: %s, domain: %s type %d\n", origin, res->domain, res->type);
		if (res->type == NSTYPE_A) {
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		}
		if (res->type == NSTYPE_AAAA) {
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		}
	}

	// fprintf(stderr, "ans=%d\n", ans);
	hold_to_cache(p, ans);
	return oldans;
}

int filter(struct dns_resource p[], size_t l, size_t count, const char *domain, int type)
{
	int i, save = 0;
	struct dns_resource *res = NULL;

	// fprintf(stderr, "filter start\n");
	for (i = 0; i < l; i++) {
		res = p + i;
		if (strcasecmp(domain, res->domain) == 0 && type == res->type) {
	        // fprintf(stderr, "%s %s %d %d\n", domain, res->domain, save, count);
			p[save++] = *res;
		}
	}

	// fprintf(stderr, "%s %d %d\n", domain, save, count);

	assert(save == count);
	return count;
}

static int get_max_suffix(struct dns_resource *item, size_t len, const char *domain, int type)
{
	int nsuffix;
	int ndot = 0;

	while (len-- > 0) {
		if (item->type == NSTYPE_NS) {
			nsuffix = strlen(item->domain);
			if (nsuffix > ndot)
				ndot = nsuffix;
		}

		if ((type == item->type || item->type == NSTYPE_CNAME) && 
				!strcasecmp(domain, item->domain)) {
			ndot = 1000;
			break;
		}

		item++;
	}

	return ndot;
}

static int query_resource(const char *domain, int type, struct dns_resource p[], size_t l);

static int query_resource_alias(const char *domain, int type, struct dns_resource p[], size_t l)
{
	struct dns_resource *iter;
	struct dns_resource *origin_p = p;

	for ( ; ; ) {
		int c = query_resource(domain, type, p, l);

		if (c == 1 && p[0].type == NSTYPE_CNAME && type != NSTYPE_CNAME) {
			domain = NS_PTR(p->value);
			for (iter = origin_p; iter < p; iter++)
				if (!strcasecmp(domain, iter->domain))
					goto next;
			p++, l--;
			continue;
		}

next:
		p += c;
		break;
	} 

	return p - origin_p;
}

static int query_resource(const char *domain, int type, struct dns_resource p[], size_t l)
{
	int c, i, j, ndot = 0;
	struct dns_resource * res  = NULL;

	LOG_DEBUG("query_resource: %s type %d\n", domain, type);
	printf("query_resource: %s type %d\n", domain, type);
	assert(l > 100);
	c = lookup_cache(domain, type, p, l);
	if (c == 1 && type != NSTYPE_CNAME && p->type == NSTYPE_CNAME) c = 0;
	if (c > 0)
		return c;

	if (is_query_pending(domain, type)) {
		printf("query_pending: %s type %d\n", domain, type);
		return 0;
	}

	c = build_name_server(domain, p, l);

	ndot = get_max_suffix(p, c, domain, type);

	int stage = 0;
	int got_author = 0;
	set_query_pending(domain, type);
    for (stage = 0; stage < 2; stage++)
	for (i = 0; i < c && !got_author; i++) {
		res = p + i;
		if (res->type != NSTYPE_NS)
			continue;

		if (ndot > strlen(res->domain))
			continue;

		LOG_DEBUG("prepare query_resource_alias: zone %s type %d ndot %d ns %s i=%d c=%d\n", res->domain, type, ndot, "XXX", i, c);
		const char * ns = NS_PTR(res->value);
		if (search(ns, p, c)) {
			/* avoid lookup loop */
			// fprintf(stderr, "ns: %s\n", ns);
			continue;
		}

		if (strcmp(domain, ns) == 0) {
			/* avoid lookup loop */
			// fprintf(stderr, "ns: %s domain: %s\n", ns, domain);
			continue;
		}

		struct in6_addr dest_addr;
		struct dns_resource * server  = p + c;

		int types[] = {NSTYPE_A, NSTYPE_AAAA};

		if (type == NSTYPE_AAAA) {
			types[0] = NSTYPE_AAAA;
			types[1] = NSTYPE_A;
		}


		if (stage == 0) {
			int count = lookup_cache(ns, types[0], server, l - c);
			for (j = 0; j < count; j++) {
				res = server + j;
				if (res->type != types[0])
					continue;
				if (res->type == NSTYPE_A)
					inet_4to6(&dest_addr, res->value);
				else
					memcpy(&dest_addr, res->value, 16);
				int newc = fetch_resource(domain, type, &dest_addr, p, c, l, ns, &got_author);
				if (newc > c || got_author) {
					c = newc;
					break;
				}
			}
			goto next;
		}

		int count1 = query_resource_alias(ns, types[0], server, l - c);
		LOG_DEBUG("query_resource_alias: ipv4 %s type %d ndot %d ns %s i=%d c=%d\n", domain, type, ndot, ns, i, c);
		for (j = 0; j < count1; j++) {
			res = server + j;
			if (res->type != types[0])
				continue;
			if (res->type == NSTYPE_A)
				inet_4to6(&dest_addr, res->value);
			else
				memcpy(&dest_addr, res->value, 16);
			int newc = fetch_resource(domain, type, &dest_addr, p, c, l, ns, &got_author);
			if (newc > c || got_author) {
				c = newc;
				goto next;
			}
		}

		int count2 = query_resource_alias(ns, types[1], server, l - c);
		LOG_DEBUG("query_resource_alias: ipv6 %s type %d ndot %d ns %s i=%d c=%d\n", domain, type, ndot, ns, i, c);
		for (j = 0; j < count2; j++) {
			res = server + j;
			if (res->type != types[1])
				continue;
			if (res->type == NSTYPE_A)
				inet_4to6(&dest_addr, res->value);
			else
				memcpy(&dest_addr, res->value, 16);
			int newc = fetch_resource(domain, type, &dest_addr, p, c, l, ns, &got_author);
			if (newc > c || got_author) {
				c = newc;
				goto next;
			}
		}
next:
		ndot = get_max_suffix(p, c, domain, type);
	}

	// unset_query_pending(domain, type);
	c = lookup_cache(domain, type, p, l);

	return c;
}

int main(int argc, char *argv[])
{
	int c, i, j;
	struct dns_resource *res;
	struct dns_resource answser[2560];


	int nserver = ARRAY_SIZE(_root_servers);

	struct dns_resource tpl =  {
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 0,
		.len = 4,
		.flags = 0,
		.domain = ".",
		.value = {}
	};

	for (i = 0; i < nserver; i++) {
		answser[i] = tpl;
		answser[i].ttl = _root_servers[i].ttl;
		answser[i].domain = _root_servers[i].domain;
		inet_pton(AF_INET, _root_servers[i].ipv4, answser[i].value);
	}

	for (i = 0; i < nserver; i++) {
		answser[i + nserver] = tpl;
		answser[i + nserver].type = NSTYPE_AAAA;
		answser[i + nserver].ttl = _root_servers[i].ttl;
		answser[i + nserver].domain = _root_servers[i].domain;
		inet_pton(AF_INET6, _root_servers[i].ipv6, answser[i + nserver].value);
	}
	hold_to_cache(answser, nserver * 2);


	for (i = 1; i < argc; i++) {
		c = query_resource_alias(argv[i], NSTYPE_A, answser, 2560);
		fprintf(stderr, "main c=%d\n", c);

		for (j = 0; j < c; j++) {
			res = &answser[j];
			if (res->type == NSTYPE_CNAME) {
				fprintf(stderr, "CNAME %s -> %s\n", res->domain, *(char **)res->value);
			} else if (res->type == NSTYPE_A) {
				fprintf(stderr, "A %s -> %s\n", res->domain, inet_ntoa(*(struct in_addr *)res->value));
			} else if (res->type == NSTYPE_AAAA) {
				fprintf(stderr, "AAAA %s -> %s\n", res->domain, ntop6(res->value));
			}
		}

		c = query_resource_alias(argv[i], NSTYPE_AAAA, answser, 2560);
		fprintf(stderr, "main c=%d\n", c);

		for (j = 0; j < c; j++) {
			res = &answser[j];
			if (res->type == NSTYPE_CNAME) {
				fprintf(stderr, "CNAME %s -> %s\n", res->domain, *(char **)res->value);
			} else if (res->type == NSTYPE_AAAA) {
				fprintf(stderr, "AAAA %s -> %s\n", res->domain, ntop6(res->value));
			} else if (res->type == NSTYPE_A) {
				fprintf(stderr, "A %s -> %s\n", res->domain, inet_ntoa(*(struct in_addr *)res->value));
			}
		}
	}

	return 0;
}
