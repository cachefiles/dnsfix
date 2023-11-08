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

static int build_root_server6(struct dns_resource p[], size_t l)
{
	int i;
	int nserver = ARRAY_SIZE(_root_servers);

	if (nserver > l)
		nserver = l;

	struct dns_resource tpl =  {
		.type = NSTYPE_AAAA,
		.klass = NSCLASS_INET,
		.ttl = 518400,
		.len = 4,
		.flags = 0,
		.domain = "dummy",
		.value = {}
	};

	for (i = 0; i < nserver; i++) {
		p[i] = tpl;
		p[i].domain = _root_servers[i].domain;
		inet_pton(AF_INET6, _root_servers[i].ipv6, p[i].value);
	}

	return nserver;
}

static int build_root_server(struct dns_resource p[], size_t l)
{
	int i;
	int nserver = ARRAY_SIZE(_root_servers);

	if (nserver > l)
		nserver = l;

	struct dns_resource tpl =  {
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 518400,
		.len = 4,
		.flags = 0,
		.domain = "dummy",
		.value = {}
	};

	for (i = 0; i < nserver; i++) {
		p[i] = tpl;
		p[i].domain = _root_servers[i].domain;
		
		in_addr_t target = inet_addr(_root_servers[i].ipv4);
		memcpy(p[i].value, &target, sizeof(target));
	}

	return nserver;
}

static int ncache = 0;
static struct dns_resource caches[1024] = {};

static int lookup_cache(const char *domain, int type, struct dns_resource p[], size_t l)
{
	int count = 0;

	for (int j = 0; j < ncache; j++) {
		struct dns_resource *res = &caches[j];
		if (res->type == type && strcasecmp(domain, res->domain) == 0) {
			p[count] = *res;
			count++;
		}
	}

	if (count > 0) {
		fprintf(stderr, "lookup_cache domain %s type %d\n", domain, type);
		return count;
	}

	assert (l > 2 * ARRAY_SIZE(_root_servers));
	count = build_root_server6(p, l);
	return build_root_server(p + count, l - count);
}

static int hold_to_cache(struct dns_resource *res, size_t count)
{
	int i, j;
	struct dns_resource *f, *t;

	cache_put(res, count);

	for (i = 0; i < count; i++) {
		f = res + i;

		int target = *(int *)f->value;
		if (f->type == NSTYPE_A && lookupRoute4(htonl(target)) == 0) {
			// fprintf(stderr, "china domain detect\n");
			// exit(0);
		}

		int found = 0;
		for (j = 0; j < ncache; j++) {
			t = &caches[j];
			if (t->domain == f->domain && t->type == f->type) {
				*t = *f;
				found = 1;
				break;
			}
		}

		if (found == 0) {
			caches[ncache] = *f;
			ncache++;
		}
	}
	
	return 0;
}

static int search(const char *domain, struct dns_resource p[], size_t l)
{
	int i; 
	struct dns_resource *res;

	for (i = 0; i < l; i++) {
		res = &p[i];
		const char **ptr = (const char **)res->value;
		if (res->type == NSTYPE_NS && strcasecmp(*ptr, domain)) {
			res->ttl = 0;
			return 1;
		}
	}

	return 0;
}

#define contains(main, part) NULL != strstr(main, part)
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

static int fetch_resource(const char *domain, int type, const struct in6_addr *server, struct dns_resource p[], size_t start, size_t l, const char *server_name)
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
	fprintf(stderr, "domain=%s send=%d to=%s %s\n", domain, len, ntop6(dest.sin6_addr), server_name);
	if (len > 0 && !wait_readable(sockfd, 400)) {
		len = sendto(sockfd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest));
		fprintf(stderr, "retry domain=%s send=%d to=%s %s\n", domain, len, ntop6(dest.sin6_addr), server_name);
	}

	if (len <= 0 || !wait_readable(sockfd, 1000)) {
		fprintf(stderr, "failure or timeout");
		return start;
	}

	socklen_t destlen = sizeof(dest);
	len = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&dest, &destlen);
	fprintf(stderr, "domain=%s recv=%d\n", domain, len);

	close(sockfd);

	if (len < 12)
		return 0;

	memset(&parser, 0, sizeof(parser));
	if (NULL == dns_parse(&parser, buf, len)) {
		fprintf(stderr, "dns_parse failure\n");
		return 0;
	}

	if (~parser.head.flags & 0x8000) {
		fprintf(stderr, "not response\n");
		return 0;
	}

	if (parser.head.question != 1 || parser.head.answer + parser.head.author == 0) {
		fprintf(stderr, "not response correct\n");
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
		} else if (contains(origin, res->domain) &&
				res->type == NSTYPE_NS) {
			const char **ptr = (const char **)res->value;
			fprintf(stderr, "NS: %s\n", *ptr);
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		}
	}

	if (ans > start || (parser.head.flags & NSFLAG_AA)) {
		// fprintf(stderr, "ans: %d\n", ans);
		hold_to_cache(p, ans);
		return ans > start? ans: 0;
	}

	for (i = 0; i < parser.head.author; i++) {
		res = &parser.author[i];

		// fprintf(stderr, "author: %s, domain: %s type %d type %d\n", origin, res->domain, res->type, type);
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
		} else if (contains(origin, res->domain) &&
				res->type == NSTYPE_NS) {
			char **ptr = (char **)res->value;
			fprintf(stderr, "NS: %s\n", *ptr);
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		}
	}

	for (i = 0; i < parser.head.addon; i++) {
		res = &parser.addon[i];

		// fprintf(stderr, "addon: %s, domain: %s type %d\n", origin, res->domain, res->type);
		if (search(res->domain, p, ans) && res->type == NSTYPE_A) {
			if (ans < l) {
				p[ans] = *res;
				ans++;
			}
		}
	}

	// fprintf(stderr, "ans=%d\n", ans);
	hold_to_cache(p, ans);
	return ans;
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

static int query_resource(const char *domain, int type, struct dns_resource p[], size_t l)
{
	int c, i, count = 0;
	struct dns_resource * res  = NULL;

	c = lookup_cache(domain, type, p, l);

	for (i = 0; i < c; i++) {
		res = p + i;
		if (res->type == type &&
				strcasecmp(domain, res->domain) == 0) {
			count++;
		}
	}

	if (count > 0)  {
		fprintf(stderr, "return cached d %s t %d c %d\n", domain, type, count);
		return count;
	}

	for (i = 0; i < c; i++) {
		res = p + i;
		if (res->type == NSTYPE_CNAME &&
				strcasecmp(domain, res->domain) == 0) {
			const char **alias = (const char **)res->value;
			return query_resource(*alias, type, p, l);
		}
	}

	int oc = c;
	for (i = c - 1; i >= 0; i--) {
		res = p + i;
		if (res->ttl == 0) {
			continue;
		}

		res->ttl = 0;

		oc = c;
		if (res->type == NSTYPE_A) {
			struct in6_addr dest_addr;
			inet_4to6(&dest_addr, res->value);
			c = fetch_resource(domain, type, &dest_addr, p, c, l, res->domain);
		}

		if (res->type == NSTYPE_AAAA) {
			const struct in6_addr *dest_addr = (const struct in6_addr *)res->value;
			c = fetch_resource(domain, type, dest_addr, p, c, l, res->domain);
		}

		if (c == 0) break;

		if (res->type == NSTYPE_NS) {
			char **alias = (char **)res->value;

			c += count;
			if (count == 0) {
				int delta = query_resource(*alias, NSTYPE_A, p + c, l - c);
				struct dns_resource *nres = &p[c];
				fprintf(stderr, "XX domain %s delta %d\n", *alias, delta);
				if (delta > 0)
					fprintf(stderr, "record domain %s %d\n", nres->domain, nres->type);
				c += delta;
			}
		}

		if (c != oc) {
			i = c - 1;
		}

		for (int j = oc;  j < c; j++) {
			res = p + j;
			if (res->type == type &&
					strcasecmp(domain, res->domain) == 0) {
				count++;
			} else if (res->type == NSTYPE_CNAME &&
					strcasecmp(domain, res->domain) == 0) {
				const char **alias = (const char **)res->value;
				p[0] = *res;
				return query_resource(*alias, type, p + 1, l - 1) + 1;
			}
		}

		if (count > 0)  {
			fprintf(stderr, "result %d\n", count);
			filter(p, c, count, domain, type);
			return count;
		}
	}
	
	return 0;
}

int main(int argc, char *argv[])
{
	int c, i, j;
	struct dns_resource *res;
	struct dns_resource answser[2560];

	for (i = 1; i < argc; i++) {
		c = query_resource(argv[i], NSTYPE_A, answser, 2560);
		fprintf(stderr, "main c=%d\n", c);

		for (j = 0; j < c; j++) {
			res = &answser[j];
			if (res->type == NSTYPE_CNAME) {
				fprintf(stderr, "CNAME %s -> %s\n", res->domain, *(char **)res->value);
			} else if (res->type == NSTYPE_A) {
				fprintf(stderr, "A %s -> %s\n", res->domain, inet_ntoa(*(struct in_addr *)res->value));
			}
		}
	}

	return 0;
}
