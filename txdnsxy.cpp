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

typedef unsigned char u_char;
typedef unsigned long u_long;

#define DNSFMT_CHECK(p, val) if ((p)->err) return val;
#define DNSFMT_ASSERT(expr, msgfmt) do { \
	if (expr); else { printf msgfmt; dpt->err = 1; return 0; } \
} while ( 0 )

struct dns_cname {
	const char *alias;
};

struct dns_soa {
	const char *name_server;
	const char *admin_email;
	uint32_t serial;
	uint32_t day2;
	uint32_t day3;
	uint32_t day4;
	uint32_t day5;
};

static int _is_client = 1;
static uint32_t _wrap_address = 0;

static int _my_location_is_oversea = 1;

static char SUFFIXES[128] = "";
static char SUFFIXES_FORMAT[128] = "%s.pac.yiz.me";
static size_t SUFFIXES_LEN = 0;

static char DETECT_SERVER[64] = "192.5.5.241";
static char SECURITY_SERVER[64] = "8.8.8.8";

static struct dns_soa _rr_soa = {
	.name_server = "one.cachefiles.net",
	.admin_email = "pagx.cachefiles.net",
	.serial = 20231523,
	.day2 = 7200,
	.day3 = 1800,
	.day4 = 1209600,
	.day5 = 60
};

#if 0
QR: 1;
opcode: 4;
AA: 1;
TC: 1;
RD: 1;
RA: 1;
zero: 3;
rcode: 4;
#endif

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

#define SOA_INDEX 0
#define NS_INDEX  1

struct dns_resource _predefine_resource_record_58_217_249[] = {
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 360,
		.len = 4,
		.flags = 0,
		.domain = "gate.855899.xyz",
		.value = {172, 31, 1, 30}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 360,
		.len = 4,
		.flags = 0,
		.domain = "auto.gate.855899.xyz",
		.value = {172, 31, 1, 30}},
};


struct dns_resource _predefine_resource_record[] = {
	{
		.type = NSTYPE_SOA,
		.klass = NSCLASS_INET,
		.ttl = 86400,
		.len = 4,
		.flags = 0,
		.domain = "",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_NS,
		.klass = NSCLASS_INET,
		.ttl = 86400,
		.len = 4,
		.flags = 0,
		.domain = "",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 360,
		.len = 4,
		.flags = 0,
		.domain = "gate.855899.xyz",
		.value = {172, 31, 1, 30}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 360,
		.len = 4,
		.flags = 0,
		.domain = "gate.855899.xyz",
		.value = {10, 0, 3, 1}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 360,
		.len = 4,
		.flags = 0,
		.domain = "auto.gate.855899.xyz",
		.value = {192, 168, 1, 1}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt1-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt2-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt3-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt4-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt4-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt5-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt6-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt7-mtalk.google.com",
		.value = {110, 42, 145, 164}},
	{
		.type = NSTYPE_A,
		.klass = NSCLASS_INET,
		.ttl = 36000,
		.len = 4,
		.flags = 0,
		.domain = "alt8-mtalk.google.com",
		.value = {110, 42, 145, 164}},
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))
int __unmap_code(int c)
{
	int cc = (c & 0xFF);

	if ('A' <= cc && cc <= 'Z') {
		return 'A' + (cc - 'A' + 13) % 26;
	}

	if ('a' <= cc && cc <= 'z') {
		return 'a' + (cc - 'a' + 13) % 26;
	}

	return cc;
}

int __map_code(int c)
{
	int cc = (c & 0xFF);

	if ('A' <= cc && cc <= 'Z') {
		return 'A' + (cc - 'A' + 13) % 26;
	}

	if ('a' <= cc && cc <= 'z') {
		return 'a' + (cc - 'a' + 13) % 26;
	}

	return cc;
}

static int is_localdn(const char *name);

static const char *last2dot(const char *name)
{
	const char *dotp[3] = {NULL, NULL, NULL};

	if (name != NULL) {
		while (*name) {
			if (*name == '.') {
				dotp[2] = dotp[1];
				dotp[1] = dotp[0];
				dotp[0] = name;
			}
			name ++;
		}

		if (dotp[2] != NULL) {
			return dotp[2];
		}
	}

	return name;
}

void domain_wrap(char *dst, const char *src, const char *suffixies)
{
	char *d = dst;
	const char *s = src;

	while (*s) {
		*d++ = __unmap_code(*s);
		s++;
	}

	strcpy(d, suffixies + ((d == dst) && '.' == *suffixies));
	return;
}

char * domain_unwrap(char *dst, const char *src, char *suffixes)
{
	const char *n = src;
	size_t ln = -1;
	size_t lt = strlen(SUFFIXES);

	if (n == NULL || *n == 0 || lt == 0) {
		return NULL;
	}

	ln = strlen(n);
	if (lt < ln && strcasecmp(n + ln - lt, SUFFIXES) == 0) {
		if (suffixes) strcpy(suffixes, n + ln - lt);

		dst[ln - lt] = 0;
		for (int l = 0; l < ln - lt; l++) dst[l] = __map_code(n[l]);
		return dst;
	}

	return NULL;
}

static int config_ip_rule(const uint8_t t[])
{
	char target[128];
	const char *IP_RULE = getenv("IP_RULE_CMD");

	if (IP_RULE != NULL) {
		inet_ntop(AF_INET, t, target, sizeof(target));
		setenv("IP", target, 1);
		system(IP_RULE);
	} 

	return 0;
}


typedef void (*forward_callback)(struct cached_client *, struct dns_udp_context_t *);

static struct cached_client {
	int flags;
	int rewrap;
	int ecs_mode;
	unsigned short r_ident;
	unsigned short l_ident;

	union {
		struct sockaddr sa;
		struct sockaddr_in in0;
	} from;

	char suffixies[64];
	struct dns_parser parser;
	forward_callback  callback;
} __cached_client[4096];

enum {POISONING, SECURITY, CHECKER};

static int __last_index = 0;

#if 1
static int _localip_ptr = 0;
static unsigned int _localip_matcher[20480];

int add_localnet(unsigned int network, unsigned int netmask)
{
	int index = _localip_ptr++;
	_localip_matcher[index++] = htonl(network);
	_localip_matcher[index] = ~netmask;
	_localip_ptr++;
	return 0;
}

static int is_localip(const void *valout)
{
	int i;
	unsigned int ip;

	memcpy(&ip, valout, 4);
	ip = htonl(ip);

	for (i = 0; i < _localip_ptr; i += 2) {
		if (_localip_matcher[i] == (ip & _localip_matcher[i + 1])) {
			return 1;
		} 
	}

	return 0;
}

static int _localdn_ptr = 0;
static char _localdn_matcher[8192];

int add_localdn(const char *dn)
{
	char *ptr, *optr;
	const char *p = dn + strlen(dn);

	ptr = &_localdn_matcher[_localdn_ptr];

	optr = ptr;
	while (p-- > dn) {
		*++ptr = *p;
		_localdn_ptr++;
	}

	if (optr != ptr) {
		*optr = (ptr - optr);
		_localdn_ptr ++;
		*++ptr = 0;
	}

	return 0;
}

static int is_localdn(const char *name)
{
	int i, len;
	char *ptr, cache[256];
	const char *p = name + strlen(name);

	ptr = cache;
	assert((p - name) < sizeof(cache));

	while (p-- > name) {
		*ptr++ = *p;
	}
	*ptr++ = '.';
	*ptr = 0;

	ptr = cache;
	for (i = 0; i < _localdn_ptr; ) {
		len = (_localdn_matcher[i++] & 0xff);

		assert(len > 0);
		if (strncmp(_localdn_matcher + i, cache, len) == 0) {
			return 1;
		}

		i += len;
	}

	return 0;
}

static int _fakeip_ptr = 0;
static unsigned int _fakeip_matcher[1024];

int add_fakeip(unsigned int ip)
{
	int index = _fakeip_ptr++;
	_fakeip_matcher[index] = htonl(ip);
	return 0;
}

static int _fakenet_ptr = 0;
static unsigned int _fakenet_matcher[20480];

int add_fakenet(unsigned int network, unsigned int mask)
{
	int index = _fakenet_ptr++;
	_fakenet_matcher[index++] = htonl(network);
	_fakenet_matcher[index] = ~mask;
	_fakenet_ptr++;
	return 0;
}

static int is_fakeip(const void *valout)
{
	int i;
	unsigned int ip;

	memcpy(&ip, valout, 4);
	ip = htonl(ip);

	for (i = 0; i < _fakenet_ptr; i += 2) {
		if (_fakenet_matcher[i] == (ip & _fakenet_matcher[i + 1])) {
			return 1;
		} 
	}

	for (i = 0; i < _fakeip_ptr; i++) {
		if (_fakeip_matcher[i] == ip) {
			return 1;
		}
	}

	return 0;
}

static int _fakedn_ptr = 0;
static char _fakedn_matcher[8192*1024];
static time_t _fakedn_touch = 0;

void update_fakedn(void)
{
	if (_fakedn_touch + 6000 < time(NULL)) {
		_fakedn_touch = time(NULL);
		_fakedn_ptr = 0;
	}
}


int add_fakedn(const char *dn)
{
	char *ptr, *optr;
	const char *p = dn + strlen(dn);

	ptr = &_fakedn_matcher[_fakedn_ptr];

	optr = ptr;
	while (p-- > dn) {
		assert (ptr < _fakedn_matcher + sizeof(_fakedn_matcher));
		*++ptr = *p;
		_fakedn_ptr++;
	}

	if (optr != ptr) {
		*optr = (ptr - optr);
		_fakedn_ptr++;
		assert (ptr < _fakedn_matcher + sizeof(_fakedn_matcher));
		*++ptr = 0;
	}

	return 0;
}

static int is_fakedn(const char *name)
{
	int i, len;
	char *ptr, cache[256];
	const char *p = name + strlen(name);

	ptr = cache;
	assert((p - name) < sizeof(cache));

	while (p-- > name) {
		*ptr++ = *p;
	}
	*ptr++ = '.';
	*ptr = 0;

	ptr = cache;
	for (i = 0; i < _fakedn_ptr; ) {
		len = (_fakedn_matcher[i++] & 0xff);

		assert(len > 0);
		if (strncmp(_fakedn_matcher + i, cache, len) == 0) {
			return 1;
		}

		i += len;
	}

	return 0;
}

static int _okaydn_ptr = 0;
static char _okaydn_matcher[8192*1024];
static time_t _okaydn_touch = 0;

void update_okaydn(void)
{
	if (_okaydn_touch + 600 < time(NULL)) {
		_okaydn_touch = time(NULL);
		_okaydn_ptr = 0;
	}
}

int add_okaydn(const char *dn)
{
	char *ptr, *optr;
	const char *p = dn + strlen(dn);

	ptr = &_okaydn_matcher[_okaydn_ptr];

	optr = ptr;
	while (p-- > dn) {
		assert (ptr < _okaydn_matcher + sizeof(_okaydn_matcher));
		*++ptr = *p;
		_okaydn_ptr++;
	}

	if (optr != ptr) {
		assert (ptr < _okaydn_matcher + sizeof(_okaydn_matcher));
		*optr = (ptr - optr);
		_okaydn_ptr++;
		*++ptr = 0;
	}

	return 0;
}

static int is_okaydn(const char *name)
{
	int i, len;
	char *ptr, cache[256];
	const char *p = name + strlen(name);

	ptr = cache;
	assert((p - name) < sizeof(cache));

	while (p-- > name) {
		*ptr++ = *p;
	}
	*ptr++ = '.';
	*ptr = 0;

	ptr = cache;
	for (i = 0; i < _okaydn_ptr; ) {
		len = (_okaydn_matcher[i++] & 0xff);

		assert(len > 0);
		if (strncmp(_okaydn_matcher + i, cache, len) == 0) {
			return 1;
		}

		i += len;
	}

	return 0;
}
#endif

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

const char *dns_type(int type)
{
	static char _unkown_type[128];
	sprintf(_unkown_type, "NST_%x", type);
	switch(type) {
		case NSTYPE_A: return "A";
		case NSTYPE_AAAA: return "AAAA";
		case NSTYPE_CNAME: return "CNAME";
		case NSTYPE_SOA: return "SOA";
		case NSTYPE_MX: return "MX";
		case 41: return "OPT";
	}

	return _unkown_type;
}

int in_list(const char *list, const char *name)
{
	int test = 0;
	const char *ptr, *np;

	np = name;
	for (ptr = list; *ptr || ptr[1]; ptr++) {
		if (*np == *ptr && test == 0) {
			np++;
		} else {
			test = 1;
		}

		if (test == 0 && *np == 0) {
			break;
		}

		if (*ptr == 0) {
			np = name;
			test = 0;
		}
	}

	return test == 0 && *np == 0;
}

extern "C" void log_fake_route(uint8_t *ipv4);

static int is_myip_name(const char *test)
{
	int i = 0;
	const char *_myip_list[] = {"ip", "vc", "my.ip", "zl.vc", NULL};
	while (test != NULL && _myip_list[i] && strcmp(_myip_list[i], test)) i++;

	return test == NULL || _myip_list[i] != NULL;
}

static int setup_route(uint32_t ipv4)
{
	char sTarget[128], sNetwork[128];
	uint32_t target = htonl(ipv4);
	subnet_t *subnet = lookupRoute(target);

	inet_ntop(AF_INET, &ipv4, sTarget, sizeof(sTarget));

	if (subnet != 0 && subnet->flags == 0) {
		unsigned network = htonl(subnet->network);

		inet_ntop(AF_INET, &network, sNetwork, sizeof(sNetwork));
		fprintf(stderr, "ACTIVE network: %s/%d by %s\n", sNetwork, subnet->prefixlen, sTarget);
		subnet->flags = 1;

		char sCmd[1024];
		sprintf(sCmd, "ipset add ipsec %s/%d", sNetwork, subnet->prefixlen);
		fprintf(stderr, "CMD=%s\n", sCmd);
		system(sCmd);
		sprintf(sCmd, "ip route add %s/%d dev tunnel1 mtu 1400 table 20", sNetwork, subnet->prefixlen);
		fprintf(stderr, "CMD=%s\n", sCmd);
		system(sCmd);
		return 0;
	}

	return 0;
}

static void update_route_table(struct dns_parser *parse)
{
	int i;

	if (parse == NULL) {
		return ;
	}

	for (i = 0; i < parse->head.answer; i++) {
		int type = parse->answer[i].type;
		if (type != NSTYPE_A) {
			continue;
		}

		unsigned *v4addrp = (unsigned *)parse->answer[i].value;
		setup_route(*v4addrp);
	}

	return;
}

int have_china(struct dns_parser * parser)
{
	int i;
	for (i = 0; i < parser->head.answer; i++) {
		int type = parser->answer[i].type;
		if (type != NSTYPE_A) {
			continue;
		}

		unsigned *v4addrp = (unsigned *)parser->answer[i].value;
		uint32_t target = htonl(*v4addrp);
		subnet_t *subnet = lookupRoute(target);

		if (subnet == NULL) {
			return 1;
		}
	}

	return 0;
}

int is_oversea(struct dns_parser * parser)
{
	int i;
	int have_oversea = 0;

	for (i = 0; i < parser->head.answer; i++) {
		int type = parser->answer[i].type;
		if (type != NSTYPE_A) {
			continue;
		}

		unsigned *v4addrp = (unsigned *)parser->answer[i].value;
		uint32_t target = htonl(*v4addrp);
		subnet_t *subnet = lookupRoute(target);

		if (subnet == NULL) {
			return 0;
		}

		have_oversea = 1;
	}

	return have_oversea;
}

int inject_dns_record(struct dns_parser *parse, int ecs_mode)
{

	int i;

#if 1
	if (ecs_mode) {
		struct dns_parser &p0 = *parse;
		for (i = 0; i < p0.head.addon; i++) {
			struct dns_resource *res = &parse->addon[i];
			if (res->type != NSTYPE_OPT) {
				continue;
			}

			if (res->domain == NULL || strcmp(res->domain, "") == 0) {
				size_t len = res->len;
				// int have_edns = 0;
				const uint8_t * valp = *(const uint8_t **)res->value;
				const uint8_t * base = valp;
				struct tagheader {uint16_t tag; uint16_t len; } tag0;

				while (len > sizeof(tag0)) {
					memcpy(&tag0, valp, sizeof(tag0));
					if (len < sizeof(tag0) + htons(tag0.len)) break;
					const uint8_t *originp = valp;
					valp += sizeof(tag0) + htons(tag0.len);
					len -= (sizeof(tag0) + htons(tag0.len));
					if (tag0.tag == htons(0x0008)) {
						memmove((void*)originp, valp, len);
						res->len = (originp + len) - base;
						// have_edns = 1;
						break;
					}
				}
			}
		}
	}
#endif

	if (_wrap_address == 0) {
		return 0;
	}

	int nanswer = 0;
	char last_domain[256] = "";
	struct dns_resource *dst = parse->answer;

	for (i = 0; i < parse->head.answer; i++) {
		int type = parse->answer[i].type;
		if (type != NSTYPE_A) {
			*dst++ = parse->answer[i];
			nanswer++;
			continue;
		}

		unsigned *v4addrp = (unsigned *)parse->answer[i].value;
		uint32_t target = htonl(*v4addrp);
		subnet_t *subnet = lookupRoute(target);
		// if (subnet != 0) *(unsigned *)parse->answer[i].value = htonl(INADDR_LOOPBACK);
		if (subnet != 0) {
			*(unsigned *)parse->answer[i].value = _wrap_address;
			if (strcmp(last_domain, parse->answer[i].domain) == 0) {
				continue;
			}
			strcpy(last_domain, parse->answer[i].domain);
		}
		*dst++ = parse->answer[i];
		nanswer++;
	}

	parse->head.answer = nanswer;

	return 0;
}

int dns_search(const char *domain, const char *list[], int count)
{
	int i;

	// LOG_DEBUG("dns_search: %s %p, %d\n", domain, list, count);
	if (domain == NULL) return 0;
	for (i = 0; i < count; i++) {
		if (strcmp(domain, list[i]) == 0) {
			return i + 1;
		}
	}

	return 0;
}

int dns_unwrap(struct dns_parser *p)
{
	int i, idx = 0;
	char one[256];
	const char *last[56] = {};
	struct dns_question *que = NULL;
	struct dns_resource *res = NULL;
	struct dns_soa *psoa = NULL;

	for (i = 0;  i < p->head.question; i++) {
		que = &p->question[i];
		if (strlen (que->domain) > 3) last[idx++] = que->domain;
		if (NULL == domain_unwrap(one, que->domain, NULL)) {
			LOG_DEBUG("dns_unwrap: %s\n", que->domain);
			return 0;
		}
		que->domain = add_domain(p, one);
	}

	for (i = 0;  i < p->head.answer; i++) {
		res = &p->answer[i];
		if (dns_search(res->domain, last, idx)) {
			last[idx++] = res->domain;
			if (domain_unwrap(one, res->domain, NULL))
				res->domain = add_domain(p, one);
		}

		if (res->type != NSTYPE_CNAME) {
			continue;
		}

		struct dns_cname *alias = (struct dns_cname *)res->value;
		if (domain_unwrap(one, alias->alias, NULL)) {
			last[idx++] = alias->alias;
			alias->alias = add_domain(p, one);
		}
	}

	for (i = 0;  i < p->head.author; i++) {
		res = &p->author[i];
		if (res->type == NSTYPE_SOA) {
			res->domain = "";
			psoa = (struct dns_soa *)res->value;

			*psoa = _rr_soa;
			res->ttl = 3600;
			res->len = sizeof(*psoa);
			continue;
		}

		if (dns_search(res->domain, last, idx)) {
			last[idx++] = res->domain;
			if (domain_unwrap(one, res->domain, NULL))
				res->domain = add_domain(p, one);
		}
	}

	for (i = 0;  i < p->head.addon; i++) {
		res = &p->addon[i];
		if (dns_search(res->domain, last, idx)) {
			last[idx++] = res->domain;
			domain_unwrap(one, res->domain, NULL);
			res->domain = add_domain(p, one);
		}
	}

	return 0;
}


int dns_rewrap(struct dns_parser *p, const char *suffixies, int add_cname)
{
	int i, idx = 0;
	const char *last[56] = {};
	char qname[2028];
	const char *origin = NULL;
	struct dns_question *que = NULL;
	struct dns_resource *res = NULL;
	struct dns_soa *psoa = NULL;
	int isoversea = is_oversea(p);

	for (i = 0;  i < p->head.question; i++) {
		que = &p->question[i];
		origin = que->domain;
		if (strlen (que->domain) > 3) last[idx++] = que->domain;
		domain_wrap(qname, que->domain, suffixies);
		que->domain = add_domain(p, qname);
	}

	if (add_cname) {
		memmove(&p->answer[1], p->answer, p->head.answer * sizeof(p->answer[0]));
		res = &p->answer[0];
		res->domain = que->domain;
		res->ttl = 3600;
		res->type = NSTYPE_CNAME;
		res->klass = que->klass;
		res->len = 8;
		struct dns_cname *alias = (struct dns_cname*)res->value;
		alias->alias = origin;
		p->head.answer++;
	} else
	for (i = 0;  i < p->head.answer; i++) {
		res = &p->answer[i];
        const char *origin_domain = res->domain;
		if (dns_search(res->domain, last, idx)) {
			last[idx++] = res->domain;
			domain_wrap(qname, res->domain, suffixies);
			res->domain = add_domain(p, qname);
		}

		struct dns_cname *pcname = (struct dns_cname *)res->value;
		if (res->type == NSTYPE_CNAME && origin_domain == pcname->alias) {
			break;
		}

		if (res->type == NSTYPE_CNAME && (isoversea)) {
			LOG_DEBUG("CNAME: %s  -> %s\n", res->domain, pcname->alias);
			last[idx++] = pcname->alias;

			domain_wrap(qname, pcname->alias, suffixies);
			pcname->alias = add_domain(p, qname);
		}
	}

	int authorn = 0;

	for (i = 0;  i < p->head.author; i++) {
		res = &p->author[i];

		if (res->type == NSTYPE_NSEC ||
				res->type == NSTYPE_NSEC3 ||
				res->type == NSTYPE_RRSIG) {
			continue;
		}

		if (res->type == NSTYPE_SOA) {
#if 0
			psoa = (struct dns_soa *)res->value;

			domain_wrap(qname, res->domain, suffixies);
			res->domain = add_domain(p, qname);

			psoa->name_server = _rr_soa.name_server;
			res->len = sizeof(*psoa);
#endif
			 *res = _predefine_resource_record[SOA_INDEX];

#define NSFLAG_MERGED (NSFLAG_RD| NSFLAG_AA| NSFLAG_QR)
			p->head.flags = (p->head.flags & RCODE_NXDOMAIN) | NSFLAG_MERGED;
		}

		p->author[authorn++] = *res;
		if (dns_search(res->domain, last, idx)) {
			last[idx++] = res->domain;
			domain_wrap(qname, res->domain, suffixies);
			res->domain = add_domain(p, qname);
		}
	}
	p->head.author = authorn;

	for (i = 0;  i < p->head.addon; i++) {
		res = &p->addon[i];
		if (dns_search(res->domain, last, idx)) {
			last[idx++] = res->domain;
			domain_wrap(qname, res->domain, suffixies);
			res->domain = add_domain(p, qname);
		}
	}

	return 0;
}

inline int is_allow_type(int type)
{
	return (type == NSTYPE_CNAME || type == NSTYPE_A || type == NSTYPE_TXT);
}

static int add_client_subnet(struct cached_client *client, struct dns_parser &p0, uint8_t *optbuf)
{
#ifndef DISABLE_SUBNET
	// china telecom 114.92.130.127/21
	// const static char subnet_data[] = "\x00\x08\x00\x07\x00\x01\x18\x00\x72\x5c\x82";

	// china mobile 223.104.213.0/24
	const static char subnet_data[] = "\x00\x08\x00\x07\x00\x01\x18\x00\xdf\x68\xd5";

	// china unicom (58.247.23.21)
	// const static char subnet_data[] = "\x00\x08\x00\x07\x00\x01\x18\x00\x3a\xf7\x17";

#define subnet_len (sizeof(subnet_data) - 1)

	int have_edns = 0;

	for (int i = 0; i < p0.head.addon; i++) {
		struct dns_resource *res = &p0.addon[i];
		if (res->type != NSTYPE_OPT) {
			continue;
		}

		if (res->domain == NULL || strcmp(res->domain, "") == 0) {
			size_t len = res->len;
			const uint8_t * valp = *(const uint8_t **)res->value;
			struct tagheader {uint16_t tag; uint16_t len; } tag0;

			while (len > sizeof(tag0)) {
				memcpy(&tag0, valp, sizeof(tag0));
				if (len < sizeof(tag0) + htons(tag0.len)) break;
				const uint8_t *hold = valp;
				valp += sizeof(tag0) + htons(tag0.len);
				len -= (sizeof(tag0) + htons(tag0.len));
				LOG_DEBUG("%04x - tag: %x", client->l_ident, tag0.tag);
				if (tag0.tag == htons(0x0008)) {
					const uint8_t * valp0 = *(const uint8_t **)res->value;
					memcpy(optbuf, valp0, (hold - valp0));
					memcpy(optbuf + (hold - valp0), valp, len);

					memcpy(optbuf + (hold - valp0) + len, subnet_data, subnet_len);
					*(void **)res->value = optbuf;
					LOG_DEBUG("%04x - INJECTED addon record to dns query", client->l_ident);
					res->len = len + (hold - valp0) + subnet_len;
					have_edns = 0;
					break;
				}
			}

			if (have_edns == 0 && is_allow_type(p0.question[0].type)) {
				const uint8_t * valp = *(const uint8_t **)res->value;
				memcpy(optbuf, valp, res->len);
				memcpy(optbuf + res->len, subnet_data, subnet_len);
				*(void **)res->value = optbuf;
				LOG_DEBUG("%04x - INJECTED addon record to dns query", client->l_ident);
				client->ecs_mode = 1;
				res->len += subnet_len;
			}
		}
	}

	if (p0.head.addon == 0 && is_allow_type(p0.question[0].type)) {
		struct dns_resource *res = &p0.addon[0];
		p0.head.addon = 1;
		res->domain = "";
		res->klass = 0x1000;
		res->type = NSTYPE_OPT;
		res->ttl  = 0;
		res->len  = subnet_len;
		*(const void **)res->value = subnet_data;
		LOG_DEBUG("%04x - add addon record to dns query", client->l_ident);
		client->ecs_mode = 2;
	}
#endif
	return 0;
}

int disallow_cname_resource_record(struct dns_parser *parser, int appended_cname)
{
	struct dns_resource *res;
	struct dns_question *que = &parser->question[0];

	for (int i = 0; i < ARRAY_SIZE(_predefine_resource_record); i++) {
		res = &_predefine_resource_record[i];
		if (strcasecmp(res->domain, que->domain) == 0) {
			goto remove_cname;
		}
	}

	if (!is_allow_type(que->type)) {
		goto remove_cname;
	}

	return 0;

remove_cname:

	int answer = 0;
	int isfirst_cname = !appended_cname;

	for (int i = 0; i < parser->head.answer; i++) {
		res = &parser->answer[i];
		if (res->type == NSTYPE_CNAME && isfirst_cname == 0) {
			continue;
		}

		if (res->type == NSTYPE_CNAME) {
			struct dns_cname *alias = (struct dns_cname *)res->value;
			alias->alias = que->domain;
			isfirst_cname = 0;
		}

		res->domain = que->domain;
		parser->answer[answer++] = *res;
	}

	parser->head.answer = answer;

	return 0;
}

int dns_parser_copy(struct dns_parser *dst, struct dns_parser *src)
{
	static uint8_t _hold[2048];
	size_t len  = dns_build(src, _hold, 2048);
	return dns_parse(dst, _hold, len) == NULL;
}

int setup_forwarder(struct cached_client *client, int index, struct sockaddr_in *from, size_t namelen, struct dns_parser *parser, forward_callback callback)
{
	memset(client, 0, sizeof(*client));
	memcpy(&client->from, from, namelen);

	client->l_ident = parser->head.ident;
	client->r_ident = (rand() & 0xF000) | index;
	dns_parser_copy(&client->parser, parser);
	client->callback = callback;

	return 0;
}

#define FLAG_RECEIVE  (1 << 0)
#define FLAG_SENTOUT  (1 << 1)
#define FLAG_DONE     (1 << 2)
#define FLAG_TRUSTED     (1 << 3)
#define FLAG_UNTRUST     (1 << 4)
#define FLAG_CNAME       (1 << 5)

struct cached_client * client_next(struct cached_client *client) 
{
	int ident;

	if (client < __cached_client || client >= __cached_client + 0xFFF) {
		return NULL;
	}

	assert(client != NULL);
	int index = client - __cached_client;

	ident = client->l_ident;
	client = &__cached_client[++index & 0xFFF];
	if (client->l_ident == ident) {
		return client;
	}

	return NULL;
}

void checker_callback(struct cached_client *client, dns_udp_context_t *up)
{
	struct dns_parser *parser = &client->parser;

	if (client->flags & FLAG_DONE) {
		LOG_DEBUG("%x checker_callback should not be call, flags: %x", client->l_ident, client->flags);
		assert(client->flags & FLAG_RECEIVE);
		return;
	} else if (client->flags & FLAG_RECEIVE) {
		int atype = parser->answer[0].type;
		int qtype = parser->question[0].type;

		struct dns_question *que = &parser->question[0];
		struct dns_resource *res = &parser->author[0];
		LOG_DEBUG("MM q %d ans %d au %d %s %d", parser->head.question, parser->head.answer, parser->head.author, que->domain, _is_client);

		// q 1 ans 10 au 0 ns3.dnsv5.com 0
		if ((parser->head.answer > 0 || strchr(que->domain, '_') == NULL) && que->type == NSTYPE_A) {
		     LOG_DEBUG("oko xxx q %d ans %d au %d %s %d", parser->head.question, parser->head.answer, parser->head.author, que->domain, _is_client);
			if (_is_client == 0 && strncmp(que->domain, "_.", 2) != 0 && !have_china(parser)) {
		     LOG_DEBUG("xxx isok q %d ans %d au %d %s %d", parser->head.question, parser->head.answer, parser->head.author, que->domain, _is_client);
				client->flags |= FLAG_UNTRUST;
			} else {
		     LOG_DEBUG("xxx noword q %d ans %d au %d %s %d", parser->head.question, parser->head.answer, parser->head.author, que->domain, _is_client);
				client->flags |= (FLAG_CNAME| FLAG_TRUSTED);
			}
			client->flags |= FLAG_DONE;

			int flags = client->flags & (FLAG_UNTRUST| FLAG_TRUSTED| FLAG_CNAME);

			client = client_next(client);
			if (client != NULL) {
				client->flags |= flags;
				client->callback(client, up);
			}

			client = client_next(client);
			if (client != NULL) {
				client->flags |= flags;
				client->callback(client, up);
			}

			return;
		}

#if 0
10-08 08:52:29.000 D MM q 1 ans 0 au 1 _.v2ex.com 0
10-08 08:52:29.000 D oko xxx q 1 ans 0 au 1 _.v2ex.com 0
10-08 08:52:29.000 D xxx noword q 1 ans 0 au 1 _.v2ex.com 0


10-07 19:40:54.636 I 4378 COMBINE FROM: 8.8.8.8: _.Ds.V6nS.jp2.tEsT-iPv6.COM SOA                                                                                [29/1960]
10-07 19:40:54.638 D 1f4b RESPONSE: 8.8.8.8: _.Ds.V6nS.jp2.tEsT-iPv6.COM SOA
10-07 19:40:54.638 D MM q 1 ans 0 au 1 _.Ds.V6nS.jp2.tEsT-iPv6.COM 0
10-07 19:40:54.639 D SOA: =v6ns1.jp2.tEsT-iPv6.COM=
10-07 19:40:54.649 I 4378 COMBINE FROM: 8.8.8.8: v6ns1.jp2.tEsT-iPv6.COM A
10-07 19:40:54.649 D 1f4b RESPONSE: 8.8.8.8: v6ns1.jp2.tEsT-iPv6.COM A
10-07 19:40:54.649 D MM q 1 ans 0 au 1 v6ns1.jp2.tEsT-iPv6.COM 0
10-07 19:40:54.649 D 1f4b checker_callback qtype: 0, atype: 1 1 0
10-07 19:40:54.649 D bbb 8
10-07 19:40:54.649 D 1f4b untrust_callback should not be call, flags: a
10-07 19:40:54.649 D 1f4b waiting for checker mytrust_callback b
10-07 19:40:54.672 I e379 COMBINE FROM: 223.5.5.5: Ds.V6nS.jp2.tEsT-iPv6.COM A
10-07 19:40:54.674 D 1f4b RESPONSE: 223.5.5.5: Ds.V6nS.jp2.tEsT-iPv6.COM A
10-07 19:40:54.674 D 1f4b waiting for checker untrust_callback 8
#endif

		if (parser->head.question == 1 && parser->head.author == 1 && parser->head.answer == 0) {
			if (_is_client == 0 && strncmp(que->domain, "_.", 2) == 0 && res->type == NSTYPE_SOA) {
				uint8_t bufward[2048];
				struct dns_soa *soa = (struct dns_soa *)res->value;
				LOG_DEBUG("SOA: =%s=", soa->name_server);

				if (*soa->name_server == 0) {
					client->flags |= FLAG_DONE;
					client->flags |= FLAG_TRUSTED;
					client->flags |= FLAG_CNAME;
					// client->flags |= FLAG_UNTRUST;

					int flags = client->flags & (FLAG_UNTRUST| FLAG_TRUSTED| FLAG_CNAME);

					client = client_next(client);
					if (client != NULL) {
						client->flags |= flags;
						client->callback(client, up);
					}

					client = client_next(client);
					if (client != NULL) {
						client->flags |= flags;
						client->callback(client, up);
					}

					return;
				}

				parser->head.ident = client->r_ident;
				parser->head.flags = NSFLAG_RD;
				parser->head.question = 1;
				parser->head.answer = 0;
				parser->head.author = 0;
				parser->head.addon = 0;

				que->domain = add_domain(parser, soa->name_server);
				que->type = NSTYPE_A;

				int len = dns_build(parser, bufward, sizeof(bufward));
				if (len <= 0) {
					LOG_DEBUG("%x dok checker_callback: dns_build error", client->l_ident);
					return;
				}

				struct sockaddr_in in0;

				in0.sin_family = AF_INET;
				in0.sin_port = htons(53);
				in0.sin_addr.s_addr = inet_addr(SECURITY_SERVER);

				int err = sendto(up->outfd, bufward, len, 0, (struct sockaddr *)&in0, sizeof(in0));
				client->flags &= ~FLAG_RECEIVE;
				return;
			}
		}

		LOG_DEBUG("%x checker_callback qtype: %d, atype: %d %d %d", client->l_ident, atype, qtype, parser->head.question, parser->head.answer);
		if (parser->head.question == 1 && parser->head.answer == 1 &&
				qtype != atype && (atype == NSTYPE_A || atype == NSTYPE_AAAA)) {
			client->flags |= FLAG_UNTRUST;
		} else {
			client->flags |= FLAG_TRUSTED;
		}
		client->flags |= FLAG_DONE;

		int flags = client->flags & (FLAG_UNTRUST| FLAG_TRUSTED| FLAG_CNAME);

		LOG_DEBUG("bbb %x", flags);
		client = client_next(client);
		if (client != NULL) {
			client->flags |= flags;
			client->callback(client, up);
		}

		client = client_next(client);
		if (client != NULL) {
			client->flags |= flags;
			client->callback(client, up);
		}

		return;
	} else if (client->flags & FLAG_SENTOUT) {
		LOG_DEBUG("%x checker_callback should not be call, flags: %x", client->l_ident, client->flags);
		return;
	}

	LOG_DEBUG("%x checker_callback flags: %x", client->l_ident, client->flags);
	assert(client->flags == 0);
	client->flags |= FLAG_SENTOUT;

	uint8_t bufward[2048];
	struct sockaddr_in in0;
	int err, len;

	in0.sin_family = AF_INET;
	in0.sin_port = htons(53);
	in0.sin_addr.s_addr = inet_addr(DETECT_SERVER);

	parser->head.flags &= ~NSFLAG_RD;
	parser->head.flags &= ~NSFLAG_ZERO;
	parser->head.ident = client->r_ident;

	for (int i = 0; i < parser->head.question; i++) {
		struct dns_question *que = &parser->question[i];
		if (_is_client) {
			que->type = (que->type == NSTYPE_MX? NSTYPE_SRV: NSTYPE_MX);
		} else if (que->type == NSTYPE_A || que->type == NSTYPE_AAAA) {
            const char *pdot = strchr(que->domain, '.');
			if (pdot != NULL) {
				char tdomain[245] = {'_'};
				strcpy(tdomain + 1, pdot);
				parser->head.flags |= NSFLAG_RD;
				que->domain = add_domain(parser, tdomain);
	            in0.sin_addr.s_addr = inet_addr(SECURITY_SERVER);
			}
		}
	}

	len = dns_build(parser, bufward, sizeof(bufward));
	if (len <= 0) {
		LOG_DEBUG("%x checker_callback: dns_build error", client->l_ident);
		return;
	}

	err = sendto(up->outfd, bufward, len, 0, (struct sockaddr *)&in0, sizeof(in0));
	(void)err;

	return;
}

void untrust_callback(struct cached_client *client, dns_udp_context_t *up)
{
	struct dns_parser *parser = &client->parser;

	if (client->flags & FLAG_DONE) {
		LOG_DEBUG("%x untrust_callback should not be call, flags: %x", client->l_ident, client->flags);
		assert(client->flags & FLAG_RECEIVE);
		return;
	} else if (client->flags & FLAG_RECEIVE) {
		int atype = parser->answer[0].type;
		int qtype = parser->question[0].type;

		if (parser->head.flags == htons(0x8281) &&
				(htons(parser->head.flags) &  NSFLAG_RCODE) == RCODE_SERVFAIL &&
				parser->head.answer == 0 &&
				parser->head.addon == 1) {
			LOG_DEBUG("%x - add_localdn %s\n", client->l_ident, parser->question[0].domain);
			if (!is_localdn(last2dot(parser->question[0].domain)))
				add_localdn(last2dot(parser->question[0].domain));
		}

		int isoversea = is_oversea(parser);
		if (parser->head.question == 1 && parser->head.answer == 1 &&
				qtype != atype && (atype == NSTYPE_A || atype == NSTYPE_AAAA)) {
			client->flags |= (_is_client || isoversea == 0)? FLAG_UNTRUST: 0;
		} else if (parser->head.answer > 1) {
			client->flags |= (_is_client || isoversea == 0)? FLAG_TRUSTED: 0;
		} else {
			for (int i = 0; i < parser->head.answer; i++) {
				if (parser->answer[i].type == NSTYPE_CNAME) {
					LOG_DEBUG("%x untrust_callback set nopoisoning here with cname", client->l_ident);
					client->flags |= (_is_client || isoversea == 0)? FLAG_TRUSTED: 0;
					break;
				}
			}

			if (parser->head.answer == 0 &&
					parser->head.author >= 1 && parser->head.addon >= 1) {
				LOG_DEBUG("%x untrust_callback set nopoisoning here dnd %d %d", client->l_ident, parser->head.author, parser->head.addon);
				client->flags |= (_is_client || isoversea == 0)? FLAG_TRUSTED: 0;
			}
		}

		if ((client->flags & FLAG_TRUSTED) && ((client->flags & FLAG_CNAME) || !is_oversea(parser) )) {
			LOG_DEBUG("%x send untrust response", client->l_ident);
		} else if ((client->flags & FLAG_UNTRUST) || is_oversea(parser) && _is_client) {
			LOG_DEBUG("%x send trust response", client->l_ident);
			client->flags |= FLAG_DONE;
			client = client_next(client);
			if (client != NULL) {
				client->flags |= FLAG_UNTRUST;
				client->callback(client, up);
			}
			return;
		} else {
			LOG_DEBUG("%x waiting for checker untrust_callback %x", client->l_ident, client->flags & (FLAG_UNTRUST|FLAG_TRUSTED|FLAG_CNAME));
			return;
		}

		disallow_cname_resource_record(parser, client->flags & FLAG_CNAME);
		inject_dns_record(parser, client->ecs_mode);
		if (client->rewrap) dns_rewrap(parser, client->suffixies, client->flags & FLAG_CNAME);

		int err;
		uint8_t bufward[2048];
		int len = dns_build(parser, bufward, sizeof(bufward));

		if (len <= 0) {
			LOG_DEBUG("%x forward_without_poisoning: dns_build error", client->l_ident);
			return ;
		}

		update_route_table(parser);
		err = sendto(up->sockfd, bufward, len, 0, &client->from.sa, sizeof(client->from));
        LOG_DEBUG("%x send response %d %d %s", client->l_ident, err, len, strerror(errno));
		client->flags |= FLAG_DONE;
		return;
	} else if (client->flags & FLAG_SENTOUT) {
		LOG_DEBUG("%x untrust_callback should not be call, flags: %x", client->l_ident, client->flags);
		return;
	}

	client->flags |= FLAG_SENTOUT;

	uint8_t bufward[2048], optbuf[64];
	struct sockaddr_in in0;
	int len;
	int err;

	in0.sin_family = AF_INET;
	in0.sin_port = htons(53);
	in0.sin_addr.s_addr = up->forward.address;

	parser->head.flags |= NSFLAG_RD;
	parser->head.ident = client->r_ident;

	if (is_localdn(last2dot(parser->question[0].domain))) {
		parser->head.addon = 0;
	} else if (_my_location_is_oversea) {
		add_client_subnet(client, *parser, optbuf);
	}

	len = dns_build(parser, bufward, sizeof(bufward));
	if (len <= 0) {
		LOG_DEBUG("%x checker_callback: dns_build error", client->l_ident);
		return;
	}

	err = sendto(up->outfd, bufward, len, 0, (struct sockaddr *)&in0, sizeof(in0));
	(void)err;
}


void mytrust_callback(struct cached_client *client, dns_udp_context_t *up)
{
	struct dns_parser *parser = &client->parser;

	if (client->flags & FLAG_DONE) {
		LOG_DEBUG("%x untrust_callback should not be call, flags: %x", client->l_ident, client->flags);
		assert(client->flags & FLAG_RECEIVE);
		return;
	} else if (client->flags & FLAG_RECEIVE) {

		if (client->flags & FLAG_UNTRUST) {
			LOG_DEBUG("%x send mytrust response", client->l_ident);
		} else {
			LOG_DEBUG("%x waiting for checker mytrust_callback %x", client->l_ident, client->flags);
			return;
		}

		disallow_cname_resource_record(parser, 0);
		inject_dns_record(parser, client->ecs_mode);
		if (_is_client && SUFFIXES_LEN > 0) dns_unwrap(parser);

		int err, len;
		uint8_t bufward[2048];
		if (client->rewrap && SUFFIXES_LEN > 0) dns_rewrap(parser, client->suffixies, 0);
		len = dns_build(parser, bufward, sizeof(bufward));

		if (len <= 0) {
			LOG_DEBUG("%x forward_without_poisoning: dns_build error", client->l_ident);
			return ;
		}

		update_route_table(parser);
		err = sendto(up->sockfd, bufward, len, 0, &client->from.sa, sizeof(client->from));
        LOG_DEBUG("%x send response %d %d %s", client->l_ident, err, len, strerror(errno));
		client->flags |= FLAG_DONE;
		return;
	} else if (client->flags & FLAG_SENTOUT) {
		LOG_DEBUG("%x mytrust_callback should not be call, flags: %x", client->l_ident, client->flags);
		return;
	}

	client->flags |= FLAG_SENTOUT;

	uint8_t bufward[2048], optbuf[64];
	struct sockaddr_in in0;
	size_t len;
	int err;

	in0.sin_family = AF_INET;
	in0.sin_port = htons(53);
	in0.sin_addr.s_addr = inet_addr(SECURITY_SERVER);

	parser->head.flags |= NSFLAG_RD;
	parser->head.ident = client->r_ident;

	if (_is_client && SUFFIXES_LEN > 0) dns_rewrap(parser, SUFFIXES, 0);
	// if (!_my_location_is_oversea) add_client_subnet(client, *parser, optbuf);
	 add_client_subnet(client, *parser, optbuf);

	len = dns_build(parser, bufward, sizeof(bufward));
	if (len <= 0) {
		LOG_DEBUG("%x checker_callback: dns_build error", client->l_ident);
		return;
	}

	err = sendto(up->outfd, bufward, len, 0, (struct sockaddr *)&in0, sizeof(in0));
	(void)err;
}

int fetch_predefine_resource_record_sp(struct dns_parser *parser, u_long from)
{
	int found = 0;
	struct dns_resource *res;
	struct dns_question *que = &parser->question[0];
	size_t domain_plen = strlen(que->domain);

	fprintf(stderr, "%08x\n", htonl(from) & 0xFFFFFF00);


    uint32_t list[] = {0x7ae40200, 0x79c4db00, 0x08d27e00, 0x3ad9f900, 0x7ae40200, 0x4a7dbe00};
	for (int i = 0; i < ARRAY_SIZE(list); i++) {
		if (list[i] == (htonl(from) & 0xffffff00)) goto fetch;
	}
	return 0;

fetch:

	parser->head.answer = 0;
	for (int i = 0; i < ARRAY_SIZE(_predefine_resource_record_58_217_249); i++) {

		if (MAX_RECORD_COUNT <= parser->head.answer) {
			break;
		}

		res = &_predefine_resource_record_58_217_249[i];
		if ((res->type == que->type) && strcasecmp(res->domain, que->domain) == 0) {
			int index = parser->head.answer++;
			parser->answer[index].type = res->type;
			parser->answer[index].klass = res->klass;
			parser->answer[index].flags = res->flags;
			parser->answer[index].ttl   = res->ttl;
			memcpy(parser->answer[index].value, res->value, res->len);
			parser->answer[index].domain = add_domain(parser, que->domain);
		}
	}

	return 0;
}

int check_canonical(const char *domain, const char *suffixes, size_t len)
{
	int i;
	int ndot = 0;
	size_t domain_plen = strlen(domain);

	if (len == 0) {
		return 0;
	}

	if (strcasecmp(domain, suffixes + 1) == 0) {
		return 1;
	}

	if (domain_plen < len) {
		return 0;
	}

	int offset = 0;
	if (domain[0] == '_' && domain[1] == '.') {
		offset = 2;
		return 1;
	}

	if (0 == strcasecmp(domain + domain_plen - len, suffixes)) {
		for (i = offset; i < domain_plen - len; i++) {
			if (domain[i] != '.') {
				continue;
			}

			if (++ndot > 2) {
				break;
			}
		}

	    LOG_DEBUG("match %s %s %d", domain + domain_plen - len, suffixes, ndot);
		return ndot < 1;
	}

	LOG_DEBUG("match %s %s %d", domain + domain_plen - len, suffixes, ndot);
	return 0;
}

int fetch_predefine_resource_record(struct dns_parser *parser)
{
    int found = 0;
	struct dns_resource *res;
	struct dns_question *que = &parser->question[0];
	size_t domain_plen = strlen(que->domain);

	for (int i = 0; i < ARRAY_SIZE(_predefine_resource_record); i++) {

		if (MAX_RECORD_COUNT <= parser->head.answer) {
			break;
		}

		res = &_predefine_resource_record[i];
		if ((res->type == que->type) && strcasecmp(res->domain, que->domain) == 0) {
			int index = parser->head.answer++;
			parser->answer[index].type = res->type;
			parser->answer[index].klass = res->klass;
			parser->answer[index].flags = res->flags;
			parser->answer[index].ttl   = res->ttl;
			memcpy(parser->answer[index].value, res->value, res->len);
			parser->answer[index].domain = add_domain(parser, que->domain);
		}

		if (res->type == NSTYPE_ANY && strcasestr(que->domain, res->domain) != 0) {
			found = 1;
		}
	}

	if (_is_client == 0 && check_canonical(que->domain, SUFFIXES, SUFFIXES_LEN)) {
		parser->head.flags |= (NSFLAG_QR| NSFLAG_AA);
		if (que->type == NSTYPE_SOA) {
			parser->head.author = 1;
			res = &parser->author[0];

			res->domain = que->domain;
			res->klass = que->klass;
			res->ttl  = 86400;
			res->type = NSTYPE_NS;

			struct dns_cname* cname = (struct dns_cname *)res->value;
			cname->alias = _rr_soa.name_server;
		}

		parser->head.author = 1;
		res = &parser->author[0];
#if 0
		res->domain = que->domain;
		res->klass = que->klass;
		res->ttl  = 86400;
		res->type = NSTYPE_SOA;
		struct dns_soa *psoa = (struct dns_soa *)res->value;
		*psoa = _rr_soa;
#endif

		*res = _predefine_resource_record[SOA_INDEX];

		return 1;
	} else if (SUFFIXES_LEN > 2 && _is_client == 0 &&
			(domain_plen < SUFFIXES_LEN || strcasecmp(que->domain + domain_plen - SUFFIXES_LEN, SUFFIXES))) {
		parser->head.flags &= NSFLAG_RCODE;
		parser->head.flags |= (RCODE_REFUSED| NSFLAG_QR);

		parser->head.addon = 1;
		res = &parser->addon[0];
		res->domain = que->domain;
		res->klass = que->klass;
		res->type = NSTYPE_CNAME;
		res->ttl  = 86400;

		char tmpbuf[256];
		struct dns_cname* cname = (struct dns_cname *)res->value;
		domain_wrap(tmpbuf, que->domain, "");
		cname->alias = add_domain(parser, tmpbuf);
		return 1;
	}

	return (parser->head.answer > 0) || (found == 1);
}

int dns_forward(dns_udp_context_t *up, char *buf, size_t count, struct sockaddr_in *in_addr1, socklen_t namlen, int fakeresp)
{
	int len;
	int err = 0;

	struct dns_question *que;
	struct cached_client *client;
	static union { struct sockaddr sa; struct sockaddr_in in0; } dns;

	struct dns_parser parser, *pparse;
	pparse = dns_parse(&parser, (uint8_t *)buf, count);
	if (pparse == NULL || parser.head.question == 0) {
		LOG_DEBUG("FROM: %s dns_forward dns_parse failure", inet_ntoa(in_addr1->sin_addr));
		return -1;
	}

#if 0
	if (strcmp(parser.question[0].domain, SUFFIXES + 1) == 0) {
		LOG_DEBUG("%p forward_prehook dns_send_response 1.1.1.1 xxx", client);
		return 0;
	}
#endif

	LOG_INFO("%x COMBINE FROM: %s: %s %s\n", parser.head.ident, inet_ntoa(in_addr1->sin_addr), parser.question[0].domain, dns_type(parser.question[0].type));
	if ((parser.head.flags & NSFLAG_QR) == 0 && fetch_predefine_resource_record(&parser)) {
		unsigned char tmpbuf[2048];
		parser.head.flags |= (NSFLAG_QR| NSFLAG_RA);
		fetch_predefine_resource_record_sp(&parser, in_addr1->sin_addr.s_addr);

		size_t len = dns_build(&parser, tmpbuf, sizeof(tmpbuf));
		int err = sendto(up->sockfd, tmpbuf, len, 0, (struct sockaddr *)in_addr1, namlen);
	    LOG_DEBUG("%x FROM: %s: %s %s predefine dns resource record\n", parser.head.ident, inet_ntoa(in_addr1->sin_addr), parser.question[0].domain, dns_type(parser.question[0].type));
		return 0;
	}

	if (parser.head.flags & NSFLAG_QR) {
		int ident = parser.head.ident;
		client = &__cached_client[ident & 0xFFF];

		if (client->r_ident != ident) {
			LOG_DEBUG("get unexpected response, just return: %x %x @%x", client->r_ident, ident, ident & 0xfff);
			return 0;
		}

		LOG_DEBUG("%x RESPONSE: %s: %s %s\n", client->l_ident, inet_ntoa(in_addr1->sin_addr), parser.question[0].domain, dns_type(parser.question[0].type));
		dns_parser_copy(&client->parser, &parser);
		client->parser.head.ident = client->l_ident;
		client->flags |= FLAG_RECEIVE;
		client->callback(client, up);
		return 0;
	}

	int rewrap = 0;
	char domain[256], mysuffixes[256];

	LOG_DEBUG("%x QUERY: %s: %s %s\n", parser.head.ident, inet_ntoa(in_addr1->sin_addr), parser.question[0].domain, dns_type(parser.question[0].type));
	for (int i = 0; i < parser.head.question; i++) {
		que = &parser.question[i];
		if (domain_unwrap(domain, que->domain, mysuffixes) != NULL) {
			que->domain = add_domain(&parser, domain);
			rewrap = 1;
		}
	}

	int index = (__last_index & 0xFFF);

	client = &__cached_client[index];
	setup_forwarder(client, index++, in_addr1, namlen, &parser, checker_callback); 
	client->callback(client, up);

	client = &__cached_client[index];
	setup_forwarder(client, index++, in_addr1, namlen, &parser, untrust_callback); 
	strcpy(client->suffixies, mysuffixes);
	client->rewrap = rewrap;
	client->callback(client, up);

	client = &__cached_client[index];
	setup_forwarder(client, index++, in_addr1, namlen, &parser, mytrust_callback); 
	strcpy(client->suffixies, mysuffixes);
	client->rewrap = rewrap;
	client->callback(client, up);

	__last_index = index;
	return 0;
}

static void do_dns_udp_recv(void *upp)
{
	int count;
	socklen_t in_len1;
	char buf[2048];
	struct sockaddr_in in_addr1;
	dns_udp_context_t *up = (dns_udp_context_t *)upp;

	update_okaydn();
	update_fakedn();
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

		dns_forward(up, buf, count, &in_addr1, in_len1, 0);
	}

	tx_aincb_active(&up->outgoing, &up->task);
	tx_aincb_active(&up->file, &up->task);
	return ;
}

int txdns_create(struct tcpip_info *local, struct tcpip_info *remote)
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
	in_addr1.sin_port = local->port;
	in_addr1.sin_addr.s_addr = local->address;
	error = bind(sockfd, (struct sockaddr *)&in_addr1, sizeof(in_addr1));
	TX_CHECK(error == 0, "bind dns socket failure");

	outfd = socket(AF_INET, SOCK_DGRAM, 0);
	TX_CHECK(outfd != -1, "create dns out socket failure");

	tx_setblockopt(outfd, 0);
	setsockopt(outfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbufsiz, sizeof(rcvbufsiz));

#if 0
#if defined(SO_MARK)
	int mark = 0x3cc3;
	error = setsockopt(outfd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	TX_CHECK(error == 0, "set udp dns socket mark failure");
#endif
#endif

#if 1
	char * detect = getenv("DETECT_SERVER");
	char * security = getenv("SECURITY_SERVER");
	char * wrap_address = getenv("WRAP_ADDRESS");
	if (detect) strcpy(DETECT_SERVER, detect);
	if (security) strcpy(SECURITY_SERVER, security);
	if (wrap_address) _wrap_address = inet_addr(wrap_address);
#endif

	in_addr1.sin_family = AF_INET;
	in_addr1.sin_port = 0;
	in_addr1.sin_addr.s_addr = 0;
	error = bind(outfd, (struct sockaddr *)&in_addr1, sizeof(in_addr1));
	TX_CHECK(error == 0, "bind dns out socket failure");

	up = new dns_udp_context_t();
	loop = tx_loop_default();

	up->forward = *remote;
	up->outfd = outfd;
	tx_aiocb_init(&up->outgoing, loop, outfd);

	up->sockfd = sockfd;
	tx_aiocb_init(&up->file, loop, sockfd);
	tx_task_init(&up->task, loop, do_dns_udp_recv, up);

#if 0
	tx_task_init(&up->mark_detect, loop, do_mark_detect, up);
	tx_timer_init(&up->reset_detect, loop, &up->mark_detect);
	tx_timer_reset(&up->reset_detect, 50);
#endif

	tx_aincb_active(&up->file, &up->task);
	tx_aincb_active(&up->outgoing, &up->task);

	return 0;
}

void suffixes_config(int isclient, const char *suffixes)
{
	if (*suffixes == '.') {
		snprintf(SUFFIXES_FORMAT, sizeof(SUFFIXES_FORMAT), "%%s%s", suffixes);
		snprintf(SUFFIXES, sizeof(SUFFIXES), "%s", suffixes);
	} else{
		snprintf(SUFFIXES_FORMAT, sizeof(SUFFIXES_FORMAT), "%%s.%s", suffixes);
		snprintf(SUFFIXES, sizeof(SUFFIXES), ".%s", suffixes);
	}

	_is_client = isclient;
	SUFFIXES_LEN = strlen(SUFFIXES);
	if (_is_client == 0 && SUFFIXES_LEN > 2) {
		struct dns_resource *res = &_predefine_resource_record[NS_INDEX];
		res->domain = SUFFIXES + 1;
		struct dns_cname *ns = (struct dns_cname *)res->value;
		ns->alias = _rr_soa.name_server;
		res->len = sizeof(void*);

		res = &_predefine_resource_record[SOA_INDEX];
		res->domain = SUFFIXES + 1;
		res->len = sizeof(_rr_soa);
		memcpy(res->value, &_rr_soa, sizeof(_rr_soa));
	}

	return;
}
