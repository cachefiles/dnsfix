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

	return build_root_server(p, l);
}

static int hold_to_cache(struct dns_resource *res, size_t count)
{
	int i, j;
	struct dns_resource *f, *t;

	cache_put(res, count);

	for (i = 0; i < count; i++) {
		f = res + i;

		int target = *(int *)f->value;
		if (f->type == NSTYPE_A && lookupRoute(htonl(target)) == 0) {
			fprintf(stderr, "china domain detect\n");
			exit(0);
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

static int fetch_resource(const char *domain, int type, struct in_addr *server, struct dns_resource p[], size_t start, size_t l, const char *server_name)
{
	int i;
	int len;
	int sockfd;
	uint8_t buf[2048];
	struct dns_question *que;
	struct dns_resource *res;
	struct dns_parser parser = {};
	struct sockaddr_in dest = {};

	parser.head.flags = 0;
	parser.head.question = 1;
	que = &parser.question[0];
	que->domain = add_domain(&parser, domain);
	que->type   = type;
	que->klass  = NSCLASS_INET;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	
	parser.head.ident = random();
	len = dns_build(&parser, buf, sizeof(buf));

	dest.sin_family = AF_INET;
	dest.sin_port   = htons(53);
	dest.sin_addr   = *server;

	len = sendto(sockfd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest));
	fprintf(stderr, "domain=%s send=%d to=%s %s\n", domain, len, inet_ntoa(dest.sin_addr), server_name);

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
			const char **ptr = (char **)res->value;
			// fprintf(stderr, "NS: %s\n", *ptr);
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
			// fprintf(stderr, "NS: %s\n", *ptr);
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
	char * dot = NULL;
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
			const char **alias = res->value;
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
		if (res->type == NSTYPE_A)
			c = fetch_resource(domain, type, (struct in_addr *)res->value, p, c, l, res->domain);

		if (c == 0) break;

		if (res->type == NSTYPE_NS) {
			char **alias = res->value;

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
				const char **alias = res->value;
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
