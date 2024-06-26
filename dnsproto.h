#ifndef _DNSPROTO_H
#define _DNSPROTO_H

#define NSTYPE_A     1
#define NSTYPE_NS    2
#define NSTYPE_CNAME 5
#define NSTYPE_SOA   6
#define NSTYPE_PTR  12
#define NSTYPE_MX   15
#define NSTYPE_TXT  16
#define NSTYPE_AAAA 28
#define NSTYPE_SRV  33
#define NSTYPE_DNAME 39
#define NSTYPE_OPT  41
#define NSTYPE_DS  43
#define NSTYPE_RRSIG  46
#define NSTYPE_NSEC   47
#define NSTYPE_NSEC3  50
#define NSTYPE_SVCB   64
#define NSTYPE_HTTPS  65
#define NSTYPE_ANY    0xffff

#define NSSIG_SOA   "ssuuuuu"
#define NSSIG_MX    "qs"
#define NSSIG_CNAME "s"
#define NSSIG_DNAME "s"
#define NSSIG_NS    "s"
#define NSSIG_SRV   "qqqs"
#define NSSIG_PTR   "s"
#define NSSIG_A     "A"
#define NSSIG_TXT   "B"
#define NSSIG_AAAA  "AAAA"
#define NSSIG_NSEC  "B"
#define NSSIG_NSEC3 "B"
#define NSSIG_RRSIG "B"
#define NSSIG_OPT   "B"
#define NSSIG_DS    "B"
#define NSSIG_SVCB  "B"
#define NSSIG_HTTPS "B"

#define MAX_RECORD_COUNT 64

// #define DN_EXPANDED 0x8000

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
#define RCODE_NOTAUTH  9
#define NSCLASS_INET 0x01

struct dns_header {
	uint16_t ident;
	uint16_t flags;
	uint16_t question;
	uint16_t answer;
	uint16_t author;
	uint16_t addon;
};

struct dns_question {
	uint16_t type;
	uint16_t klass;

	const char *domain;
};

struct dns_resource {
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t len;

	short flags;
	const char *domain;
	uint8_t value[64];
};

struct dns_parser {
	int strcnt;
	char strtab[2048];
	char *lastptr;
	const char *strptr[100];
	uint8_t *comptr[MAX_RECORD_COUNT * 2];

	struct dns_header head;
	struct dns_question question[4];
	struct dns_resource *answer;
	struct dns_resource *author;
	struct dns_resource *addon;
	struct dns_resource records[MAX_RECORD_COUNT];
};

#define COUNTOF(arr) (sizeof(arr)/sizeof(arr[0]))

#ifdef __cplusplus 
extern "C" { 
#endif

int dns_build(struct dns_parser *parser, uint8_t *frame, size_t len);
const char *add_domain(struct dns_parser *parser, const char *dn);
const char *cache_get_name(const char *domain);
int cache_put(struct dns_resource *res, size_t count);
struct dns_parser * dns_parse(struct dns_parser *parser, const uint8_t *frame, size_t len);

#ifdef __cplusplus 
} 
#endif

#endif
