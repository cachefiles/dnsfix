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

static int _is_client = 0;
static char SUFFIXES[128] = ".pac.yiz.me";
static char SUFFIXES_FORMAT[128] = "%s.pac.yiz.me";

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
#define NSCLASS_INET 0x01

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

void encrypt_domain(char *dst, const char *src)
{
	char *d = dst;
	const char *s = src;

	while (*s) {
		*d++ = __unmap_code(*s);
		s++;
	}

	strcpy(d, SUFFIXES);
	return;
}

char * decrypt_domain(char *name)
{
	char *n = name;
	size_t ln = -1;
	size_t lt = strlen(SUFFIXES);

	if (n == NULL || *n == 0) {
		return NULL;
	}

	ln = strlen(n);
	if (lt < ln && strcasecmp(n + ln - lt, SUFFIXES) == 0) {
		n[ln - lt] = 0;
		for (int l = 0; l < ln - lt; l++) n[l] = __map_code(n[l]);
		return name;
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

static struct cached_client {
	int flags;
	int rewrap;
	int status;
	int poisoning, nopoisoning;
	unsigned short r_ident;
	unsigned short l_ident;

	int pair;
	int len_cached;
	char pair_cached[1400];

	union {
		struct sockaddr sa;
		struct sockaddr_in in0;
	} from;
} __cached_client[4096];

static int __last_index = 0;

int add_domain(const char *name, unsigned int localip)
{
	return 1;
}

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
	struct tcpip_info forward;

	tx_task_t task;
};

const char *dns_type(int type)
{
	static char _unkown_type[128];
	sprintf(_unkown_type, "NST%x", type);
	switch(type) {
		case NSTYPE_A: return "A";
		case NSTYPE_AAAA: return "AAAA";
		case NSTYPE_CNAME: return "CNAME";
		case NSTYPE_SOA: return "SOA";
		case 41: return "OPT";
	}

	return _unkown_type;
}

int get_suffixes_forward(struct dns_parser *parser)
{
	char name[256], text[256];
	static char nambuf[4096];
	struct dns_question *que;
	struct dns_resource *res;

	char *dotp = nambuf;
	char *dotp_limit = nambuf + sizeof(nambuf);

	for (int i = 0; i < parser->head.question && dotp < dotp_limit; i++) {
		que = &parser->question[i];

		strcpy(name, que->domain);
		strcpy(text, que->domain);
		if (!decrypt_domain(name) && 0) {
			LOG_DEBUG("not allow %s %s", name, dns_type(parser->question[i].type));
			return 0;
		}

		if (0x0000 == (parser->head.flags & 0x8100)) {
			parser->head.flags |= 0x100;
		}

		que->domain = add_domain(parser, name);
		if (que->domain == NULL) {
			return 0;
		}

		LOG_DEBUG("crypt name %s from %s", name, text);
	}

	for (int i = 0; i < parser->head.answer; i++) {
		res = &parser->answer[i];

		const char *orig_name = res->domain;
		if (strcasecmp(text, res->domain) == 0) {
			res->domain = parser->question[0].domain;
		}

		LOG_DEBUG("orig name: %s\n", orig_name);
		if (res->type == NSTYPE_A &&
				strcasestr(orig_name, SUFFIXES) != NULL) {
			config_ip_rule(res->value);
		}
	}

	return -1;
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

#if 0
int nsttl = 239643;
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "j.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "c.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "g.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "m.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "k.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "e.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "a.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "f.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "h.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "b.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "i.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "l.root-servers.net");
dst_buf = dns_auth_addNS(dst_buf, ".", nsttl, htons(dnscls), "d.root-servers.net");
dns_dstp->q_nscount = htons(13);

dst_buf = dns_addon_addA(dst_buf, "a.root-servers.net", nsttl, htons(dnscls), inet_addr("198.41.0.4"));
dst_buf = dns_addon_addA(dst_buf, "b.root-servers.net", nsttl, htons(dnscls), inet_addr("192.228.79.201"));
dst_buf = dns_addon_addA(dst_buf, "c.root-servers.net", nsttl, htons(dnscls), inet_addr("192.33.4.12"));
dst_buf = dns_addon_addA(dst_buf, "d.root-servers.net", nsttl, htons(dnscls), inet_addr("199.7.91.13"));
dst_buf = dns_addon_addA(dst_buf, "e.root-servers.net", nsttl, htons(dnscls), inet_addr("192.203.230.10"));
dst_buf = dns_addon_addA(dst_buf, "f.root-servers.net", nsttl, htons(dnscls), inet_addr("192.5.5.241"));
dst_buf = dns_addon_addA(dst_buf, "g.root-servers.net", nsttl, htons(dnscls), inet_addr("192.112.36.4"));
dst_buf = dns_addon_addA(dst_buf, "h.root-servers.net", nsttl, htons(dnscls), inet_addr("198.97.190.53"));
dst_buf = dns_addon_addA(dst_buf, "i.root-servers.net", nsttl, htons(dnscls), inet_addr("192.36.148.17"));
dst_buf = dns_addon_addA(dst_buf, "j.root-servers.net", nsttl, htons(dnscls), inet_addr("114.114.114.114"));
dst_buf = dns_addon_addA(dst_buf, "k.root-servers.net", nsttl, htons(dnscls), inet_addr("193.0.14.129"));
dst_buf = dns_addon_addA(dst_buf, "l.root-servers.net", nsttl, htons(dnscls), inet_addr("199.7.83.42"));
dst_buf = dns_addon_addA(dst_buf, "m.root-servers.net", nsttl, htons(dnscls), inet_addr("202.12.27.33"));
dns_dstp->q_arcount = htons(13);
#endif

struct dns_cname {
	const char *alias;
};

extern "C" void log_fake_route(uint8_t *ipv4);

int get_suffixes_backward(struct dns_parser *parser)
{
	char crypt[256], text[256];
	const char *namptr = NULL;
	struct dns_question *que;
	struct dns_resource *res;
	int namlen = 0;

	int trace_cname = 0, have_cname = 0, non_cname = 0, ask_cname = 0;
	LOG_DEBUG("get_suffixes_backward nsflag %x", 0);

	for (int i = 0; i < parser->head.question; i++) {
		que = &parser->question[i];
		strcpy(text, que->domain);
		encrypt_domain(crypt, que->domain);

		namptr = que->domain;
		if ((0x8000 & parser->head.flags) || is_fakedn(que->domain)) {
			que->domain = add_domain(parser, crypt);
		}

		if (que->domain == NULL) {
			return 0;
		}

		if (que->type == NSTYPE_CNAME) {
			ask_cname = 1;
		}
	}

	if ((0x8000 & parser->head.flags) && is_fakedn(text)) {
		trace_cname = 1;
	}

	for (int i = 0; i < parser->head.answer; i++) {
		res = &parser->answer[i];

		if (strcasecmp(res->domain, text) == 0) {
			res->domain = parser->question[0].domain;
		}

		if (res->domain == NULL) {
			return 0;
		}

		if (res->type == NSTYPE_CNAME) {
			have_cname = 1;
		} else {
			non_cname = 1;
		}
	}

	int total = 0;
	LOG_DEBUG("%d %s %d trace %d have %d non %d ask %d\n", parser->head.answer, text, is_fakedn(text), trace_cname, have_cname, non_cname, ask_cname);
	if (trace_cname && have_cname && non_cname && !ask_cname) {
		for (int i = 0; i < parser->head.answer; i++) {
			res = &parser->answer[i];
			if (res->type == NSTYPE_CNAME) continue;
			if (res->type == NSTYPE_A) log_fake_route(res->value);
			res->domain = parser->question[0].domain;
			if (i > total)
				parser->answer[total] = *res;
			total++;
		}
		parser->head.answer = total;

	} else if ((parser->head.answer == 0)
			&& (0x8000 & parser->head.flags)) {
		parser->answer[0].domain = parser->question[0].domain;
		parser->answer[0].klass  = parser->question[0].klass;
		parser->answer[0].type   = NSTYPE_CNAME;
		parser->answer[0].ttl    = 36000;
		parser->answer[0].len    = 100; // invalid value;

		struct dns_cname *cptr = (struct dns_cname *)parser->answer[0].value;
		cptr->alias = namptr;
		parser->head.answer++;
	}

	return -1;
}

static int is_myip_name(const char *test)
{
	int i = 0;
	const char *_myip_list[] = {"ip", "vc", "my.ip", "zl.vc", NULL};
	while (test != NULL && _myip_list[i] && strcmp(_myip_list[i], test)) i++;

	return test == NULL || _myip_list[i] != NULL;
}

static const char GCM_DOMAIN[] = "mtalk.google.com";
static const size_t GCM_LEN = sizeof(GCM_DOMAIN) -1;

int self_query_hook(int fd, struct dns_parser *parser, struct sockaddr_in *from)
{
	int dns_rcode = 0;
	int flags = (parser->head.flags & 0x8100);
	char shname[256], *test, *last;

	int gcm = 0;
	u_char tmp[1500];
	struct dns_question *que;

	for (int i = 0; i < parser->head.question; i++) {
		que = &parser->question[i];

		strcpy(shname, que->domain);
		test = decrypt_domain(shname);
		if (!test && strcmp(shname, SUFFIXES + 1) != 0) return 1;

#if ENABLE_GOGL_NAME_REMAP
		size_t len = strlen(shname);
		if (que->type == NSTYPE_A && len >= GCM_LEN
				&& 0 == strcmp(&shname[len - GCM_LEN], GCM_DOMAIN)) {
			gcm = 1;
			break;
		}

#define GOGL_DOMAIN "www.google.com"
		if (que->type == NSTYPE_A 
				&& 0 == strcmp(shname, GOGL_DOMAIN)) {
			gcm = 2;
			break;
		}
#endif

		if (test != NULL) {
			LOG_DEBUG("test is %s, flags %x", test, flags);
			last = strrchr(shname, '.');
			dns_rcode = RCODE_NXDOMAIN;
			if (last == NULL) {
				dns_rcode = RCODE_NXDOMAIN;
			} else if (isalpha(last[1])
					&& (0x0100 == flags || is_fakedn(shname))) {
				return 0;
			}
		}

	}

	if (parser->head.question <= 0) {
		return 1;
	}

	parser->head.flags  &= NSFLAG_RD;
	parser->head.flags  |= (NSFLAG_QR| NSFLAG_AA);

	parser->head.answer = 0;
	parser->head.author = 0;
	parser->head.addon = 0;

	if (parser->question[0].type == NSTYPE_A && gcm >= 1) {
		parser->head.answer = 0;
		parser->head.author = 0;
		parser->head.addon = 0;

		parser->answer[0].domain = parser->question[0].domain;
		parser->answer[0].klass = parser->question[0].klass;
		parser->answer[0].type = NSTYPE_CNAME;
		parser->answer[0].ttl  = 3600;
		parser->answer[0].len  = 4;

		struct dns_cname *cptr = (struct dns_cname *)parser->answer[0].value;
		cptr->alias = add_domain(parser, gcm == 1? "mtalk.cachefiles.net": "www.g.cn");
		parser->head.answer = 1;
	} else if (parser->question[0].type == NSTYPE_A && is_myip_name(test)) {
		LOG_DEBUG("fake IPv4 response, from %s", inet_ntoa(from->sin_addr));
		parser->answer[0].domain = parser->question[0].domain;
		parser->answer[0].klass = parser->question[0].klass;
		parser->answer[0].type = parser->question[0].type;
		parser->answer[0].ttl  = 3600;
		parser->answer[0].len  = 4;

		u_long in_addr = htonl(from->sin_addr.s_addr);
		memcpy(parser->answer[0].value, &in_addr, sizeof(in_addr));
		parser->head.answer = 1;
	} else if (flags == 0x0000 && parser->head.answer == 0) {
		parser->answer[0].domain = parser->question[0].domain;
		parser->answer[0].klass = parser->question[0].klass;
		parser->answer[0].type = NSTYPE_CNAME;
		parser->answer[0].ttl  = 3600;
		parser->answer[0].len  = 4;
		parser->head.answer = 1;

		struct dns_cname *cptr = (struct dns_cname *)parser->answer[0].value;
		cptr->alias = add_domain(parser, shname);
	} else {
		parser->head.flags  |= dns_rcode;
	}

	struct dns_soa {
		const char *name_server;
		const char *admin_email;
		uint32_t serial;
		uint32_t day2;
		uint32_t day3;
		uint32_t day4;
		uint32_t day5;
	};

	if (dns_rcode == RCODE_NXDOMAIN) {
		struct dns_soa *psoa = (struct dns_soa *)parser->author[0].value;

		psoa->name_server = SUFFIXES + 1;
		psoa->admin_email = "pagx.163.com";
		psoa->serial = 18000;
		psoa->day2 = 18000;
		psoa->day3 = 18000;
		psoa->day4 = 18000;
		psoa->day5 = 18000;

		parser->author[0].domain = "domain.pac.yrli.bid";
		parser->author[0].klass = parser->question[0].klass;
		parser->author[0].type = NSTYPE_SOA;
		parser->author[0].ttl  = 3600;
		parser->author[0].len  = 100;
		parser->head.author = 1;
	}

	int len = dns_build(parser, tmp, sizeof(tmp));
	sendto(fd, (char *)tmp, len, 0, (struct sockaddr *)from, sizeof(*from));

	return 1;
}

int none_query_hook(int outfd, struct dns_parser *parser, struct sockaddr_in *from)
{
	size_t len;
	u_char tmp[1500];
	struct dns_question *que;

	for (int i = 0; i < parser->head.question; i++) {
		que = &parser->question[i];
		len = strlen(que->domain);
		if (que->type != NSTYPE_A || len < GCM_LEN
				|| strcmp(&que->domain[len - GCM_LEN], GCM_DOMAIN)) {
			return 0;
		}
#if ENABLE_GOGL_NAME_REMAP
#define GOGL_DOMAIN "www.google.com"
		if (que->type == NSTYPE_A 
				&& 0 == strcmp(shname, GOGL_DOMAIN)) {
			gcm = 2;
			break;
		}
#endif
	}

	if (parser->head.question <= 0) {
		return 1;
	}

	parser->head.flags  &= NSFLAG_RD;
	parser->head.flags  |= (NSFLAG_QR| NSFLAG_AA);

	parser->head.answer = 0;
	parser->head.author = 0;
	parser->head.addon = 0;

	parser->answer[0].domain = parser->question[0].domain;
	parser->answer[0].klass = parser->question[0].klass;
	parser->answer[0].type = parser->question[0].type;
	parser->answer[0].ttl  = 3600;
	parser->answer[0].len  = 4;

	u_long in_addr = inet_addr("1.1.1.1");
	memcpy(parser->answer[0].value, &in_addr, sizeof(in_addr));
	parser->head.answer = 1;

	len = dns_build(parser, tmp, sizeof(tmp));
	sendto(outfd, (char *)tmp, len, 0, (struct sockaddr *)from, sizeof(*from));

	return 1;
}

static int (*dns_query_hook)(int fd, struct dns_parser *parser, struct sockaddr_in *) = self_query_hook;
static int (*dns_tr_request)(struct dns_parser *parser) = get_suffixes_forward;
static int (*dns_tr_response)(struct dns_parser *parser) = get_suffixes_backward;


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
		// sprintf(sCmd, "ip route add %s/%d dev tun0 table 20", sNetwork, subnet->prefixlen);
		sprintf(sCmd, "ipset add ipsec %s/%d", sNetwork, subnet->prefixlen);
		fprintf(stderr, "CMD=%s\n", sCmd);
		system(sCmd);
	}

	return 0;
}
 
int dns_send_response(dns_udp_context_t *up, struct cached_client *client, struct dns_parser *req, struct dns_parser *resp, const char *value)
{
       
    int err;
    int len = 0;
    char domain[256];
    char bufout[8192];

    struct dns_parser *parser = req? req: resp;

    if (client->rewrap) 
	encrypt_domain(domain, parser->question[0].domain);
    else
	strcpy(domain, parser->question[0].domain);

    parser->head.ident = client->l_ident;
    parser->question[0].domain = domain;
    parser->question[0].type = NSTYPE_A;

    parser->head.flags  &= NSFLAG_RD;
    parser->head.flags  |= (NSFLAG_QR| NSFLAG_AA);

    parser->head.answer = 0;
    parser->head.author = 0;
    parser->head.addon = 0;

    parser->answer[0].domain = domain;
    parser->answer[0].klass = parser->question[0].klass;
    parser->answer[0].type = parser->question[0].type;
    parser->answer[0].ttl  = 360;
    parser->answer[0].len  = 4;

    u_long in_addr = inet_addr(value);
    memcpy(parser->answer[0].value, &in_addr, sizeof(in_addr));
    parser->head.answer = 1;

    len = dns_build(parser, (uint8_t *)bufout, sizeof(bufout));
    len > 0 && (err = sendto(up->sockfd, bufout, len, 0, &client->from.sa, sizeof(client->from)));
    return 0;
}

enum {STATUS_INITIAL, STATUS_WAIT_RESPONSE, STATUS_DONE};

int forward_prehook(dns_udp_context_t *up, struct cached_client *client, struct dns_parser *parser)
{
	int atype, qtype, i;

	if (client->status == STATUS_INITIAL && parser->head.question > 0) {
		if (is_fakedn(parser->question[0].domain) && parser->question[0].type == NSTYPE_A) {
			// dns_send_response(up, client, &parser, NULL, "1.1.1.1");
			LOG_DEBUG("forward_prehook dns_send_response 1.1.1.1");
			client->status = STATUS_DONE;
			return 0;
		}
		client->poisoning = 0;
		client->nopoisoning = 0;
	}

	if ((parser->head.flags & 0x8000) &&
			(client->status == STATUS_WAIT_RESPONSE)) {

		qtype = parser->question[0].type;
		atype = parser->answer[0].type;
		LOG_DEBUG("qtype: %d, atype: %d", atype, qtype);
		if (parser->head.question == 1 && parser->head.answer == 1 &&
				qtype != atype && (atype == NSTYPE_A || qtype == NSTYPE_AAAA)) {
			client->poisoning = 1;
		}

		if (parser->head.answer > 1) {
			client->nopoisoning = 1;
		} else if (!client->poisoning) {
			for (i = 0; i < parser->head.answer; i++) {
				if (parser->answer[i].type == NSTYPE_CNAME) {
					client->nopoisoning = 1;
					break;
				}
			}

			if (parser->head.answer == 0 &&
					parser->head.author > 1 && parser->head.addon > 1) {
				client->nopoisoning = 1;
			}
		}

	}

	return 0;
}

int forward_posthook(dns_udp_context_t *up, struct cached_client *client, struct dns_parser *parser)
{
	int err, len;
	char *bufward;

	if (client->status == STATUS_INITIAL && parser->head.question > 0) {
		client->status = STATUS_WAIT_RESPONSE;
	} else if (client->status == STATUS_WAIT_RESPONSE) {
		if ((parser->head.flags & 0x8000) && (parser->head.answer > 0)
				&& client->nopoisoning == 0 && client->poisoning == 0) {
			client->len_cached = dns_build(parser, (uint8_t*)client->pair_cached, sizeof(client->pair_cached));
		}

		if (client->len_cached > 0 && client->nopoisoning) {
			len = client->len_cached;
			bufward = client->pair_cached;
			err = sendto(up->sockfd, bufward, len, 0, &client->from.sa, sizeof(client->from));
			client->status = STATUS_DONE;
		}
		LOG_DEBUG("poisoning: %d nopoisoning: %d", client->poisoning, client->nopoisoning);
	}

	return 0;
}

int forward_allow_poisoning(dns_udp_context_t *up, struct cached_client *client, struct dns_parser *parser, struct sockaddr_in *in_addr1)
{
	int err, len;
	char bufward[4096];
	struct sockaddr_in in0;
	struct dns_parser p0 = *parser;

	if (client->status == STATUS_INITIAL && parser->head.question > 0) {

		in0.sin_family = AF_INET;
		in0.sin_port = htons(53);
		in0.sin_addr.s_addr = inet_addr("223.5.5.5");

		p0.head.flags |= NSFLAG_RD;
		if (p0.head.addon == 0) {
			p0.head.addon = 1;
			p0.addon[0].domain = "";
			p0.addon[0].klass = 0x1000;
			p0.addon[0].type = NSTYPE_OPT;
			p0.addon[0].ttl  = 0;
			p0.addon[0].len  = 10;
			const void ** valp = (const void **)p0.addon[0].value;
			*valp = "\x00\x08\x00\x06\x00\x01\x10\x00\x6e\x2a";
			LOG_DEBUG("add addon record to dns query");
		}

		len = dns_build(&p0, (uint8_t *)bufward, sizeof(bufward));
		if (len <= 0) {
			LOG_DEBUG("forward_allow_poisoning: dns_build error");
			return -1;
		}

		err = sendto(up->outfd, bufward, len, 0, (struct sockaddr *)&in0, sizeof(in0));
	}

	if ((parser->head.flags & 0x8000) && client->nopoisoning &&
			// in_addr1->sin_addr.s_addr == inet_addr("223.5.5.5") &&
			(client->status == STATUS_WAIT_RESPONSE)) {
		len = dns_build(parser, (uint8_t *)bufward, sizeof(bufward));
		if (len <= 0) {
			LOG_DEBUG("forward_allow_poisoning: dns_build error");
			return -1;
		}

		LOG_DEBUG("forward_allow_poisoning: ");
		err = sendto(up->sockfd, bufward, len, 0, &client->from.sa, sizeof(client->from));
		client->status = STATUS_DONE;
	}

	return 0;
}

int forward_without_poisoning(dns_udp_context_t *up, struct cached_client *client, struct dns_parser *parser, struct sockaddr_in *in_addr1)
{
	int err, len;
	char bufward[4096];
	struct sockaddr_in in0;
	struct dns_parser p0 = *parser;

	if (client->status == STATUS_INITIAL && parser->head.question > 0) {

		in0.sin_family = AF_INET;
		in0.sin_port = htons(53);
		in0.sin_addr.s_addr = inet_addr("8.8.8.8");

		p0.head.flags |= NSFLAG_RD;
		if (p0.head.addon == 0) {
			p0.head.addon = 1;
			p0.addon[0].domain = "";
			p0.addon[0].klass = 0x1000;
			p0.addon[0].type = NSTYPE_OPT;
			p0.addon[0].ttl  = 0;
			p0.addon[0].len  = 10;
			const void ** valp = (const void **)p0.addon[0].value;
			*valp = "\x00\x08\x00\x06\x00\x01\x10\x00\x6e\x2a";
			LOG_DEBUG("add addon record to dns query");
		}

		len = dns_build(&p0, (uint8_t *)bufward, sizeof(bufward));
		if (len <= 0) {
			LOG_DEBUG("forward_without_poisoning: dns_build error");
			return -1;
		}

		err = sendto(up->outfd, bufward, len, 0, (struct sockaddr *)&in0, sizeof(in0));
	}

	if ((parser->head.flags & 0x8000) && client->poisoning &&
			in_addr1->sin_addr.s_addr == inet_addr("8.8.8.8") &&
			(client->status == STATUS_WAIT_RESPONSE)) {
		if (parser->head.addon == 0) {
			LOG_DEBUG("forward_without_poisoning: drop poisoning packet");
			return -1;
		}

		len = dns_build(parser, (uint8_t *)bufward, sizeof(bufward));
		if (len <= 0) {
			LOG_DEBUG("forward_without_poisoning: dns_build error");
			return -1;
		}

		LOG_DEBUG("forward_without_poisoning: ");
		err = sendto(up->sockfd, bufward, len, 0, &client->from.sa, sizeof(client->from));
		client->status = STATUS_DONE;
	}

	return 0;
}

int forward_detect_poisoning(dns_udp_context_t *up, struct cached_client *client, struct dns_parser *parser)
{
	int err, len;
	char bufward[4096];
	struct sockaddr_in in0;
	struct dns_question *que;
	struct dns_parser p0 = *parser;

	if (client->status != STATUS_INITIAL || parser->head.question == 0) {
		return 0;
	}

	p0.head.flags &= ~NSFLAG_RD;
	for (int i = 0; i < p0.head.question; i++) {
		que = &p0.question[i];
		que->type = (que->type == NSTYPE_MX? NSTYPE_SRV: NSTYPE_MX);
	}

	len = dns_build(&p0, (uint8_t *)bufward, sizeof(bufward));
	if (len <= 0) {
		LOG_DEBUG("forward_detect_poisoning: dns_build error");
		return -1;
	}

	in0.sin_family = AF_INET;
	in0.sin_port = htons(53);
	in0.sin_addr.s_addr = inet_addr("198.97.190.53");

	err = sendto(up->outfd, bufward, len, 0, (struct sockaddr *)&in0, sizeof(in0));

	return 0;
}

int process_client_event(dns_udp_context_t *up,
		struct cached_client *client, struct dns_parser *parser, struct sockaddr_in *in_addr1, socklen_t namlen)
{

	LOG_DEBUG("FROM: %s\n", inet_ntoa(in_addr1->sin_addr));
	forward_prehook(up, client, parser);
	if (in_addr1->sin_addr.s_addr == inet_addr("198.97.190.53")) {
		forward_posthook(up, client, parser);
		return 0;
	}
	forward_allow_poisoning(up, client, parser, in_addr1);
	forward_without_poisoning(up, client, parser, in_addr1);
	forward_detect_poisoning(up, client, parser);
	forward_posthook(up, client, parser);

	return 0;
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
	if (pparse == NULL) {
		return -1;
	}

	int index = (__last_index & 0xFFF);
	if (parser.head.flags & 0x8000) {
		int ident = parser.head.ident;
		client = &__cached_client[ident & 0xFFF];

		if (client->r_ident != ident) {
			LOG_DEBUG("get unexpected response, just return");
			return 0;
		}

		parser.head.ident = client->l_ident;
	} else {
		client = &__cached_client[index];
		memcpy(&client->from, in_addr1, namlen);
		client->l_ident = (parser.head.ident);
		client->r_ident = (rand() & 0xF000) | index;
		client->len_cached = client->status = 0;
		parser.head.ident = (client->r_ident);
	}

	process_client_event(up, client, &parser, in_addr1, namlen);

	return 0;
}

#if 0
		if (parser.head.question == 1) {
			type = parser.question[0].type;
			for (int i = 0; i < parser.head.answer; i++) {
				if (parser.answer[i].type == NSTYPE_A) {
					found1 = 1;
				} else if (parser.answer[i].type == NSTYPE_CNAME) {
					have_cname = 1;
				} else if (parser.answer[i].type == type) {
					found = 1;
				}
			}

			if (in_addr1->sin_addr.s_addr == inet_addr("114.114.114.114")) {
				int isnew = 0;
				if (found == 0 && found1 == 1 && type != NSTYPE_A) {
					LOG_DEBUG("bad query anser: %s\n", parser.question[0].domain);
					isnew = !is_fakedn(parser.question[0].domain);
					if (isnew) add_fakedn(parser.question[0].domain);
				} else if (!is_fakedn(parser.question[0].domain)){
					LOG_DEBUG("good query anser: %s\n", parser.question[0].domain);
					isnew = !is_okaydn(parser.question[0].domain);
					if (isnew) add_okaydn(parser.question[0].domain);
				}

				LOG_DEBUG("resume %p %p %p", last_client, client, suspend_client);
				if (/* last_client == client && */ is_fakedn(parser.question[0].domain)) {
				    LOG_DEBUG("send response with block ip %d %d", last_len, len);
				    dns_send_response(up, client, NULL, &parser, "1.1.1.1");
				} else if (suspend_client == client && is_okaydn(parser.question[0].domain)) {
				    len = sendto(up->sockfd, bufout_suspend, suspend_len, 0, &client->from.sa, sizeof(client->from));
				    LOG_DEBUG("delivery %d %d", suspend_len, len);
				}

#endif

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

	if (isclient) {
		LOG_DEBUG("client mode");
		dns_tr_request = get_suffixes_backward;
		dns_tr_response = get_suffixes_forward;
		dns_query_hook  = none_query_hook;
		_is_client = 1;
	} else {
		LOG_DEBUG("server mode");
		dns_tr_request = get_suffixes_forward;
		dns_tr_response = get_suffixes_backward;
		dns_query_hook  = self_query_hook;
		_is_client = 0;
	}

	return;
}

