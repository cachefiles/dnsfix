#ifndef _DNSPROTO_H
#define _DNSPROTO_H

#define NSTYPE_A     1
#define NSTYPE_NS    2
#define NSTYPE_CNAME 5
#define NSTYPE_SOA   6
#define NSTYPE_PTR  12
#define NSTYPE_MX   15
#define NSTYPE_AAAA 28
#define NSTYPE_SRV  33
#define NSTYPE_OPT  41

#define NSSIG_SOA   "ssuuuuu"
#define NSSIG_MX    "qs"
#define NSSIG_CNAME "s"
#define NSSIG_NS    "s"
#define NSSIG_SRV   "qqqs"
#define NSSIG_PTR   "s"
#define NSSIG_A     "u"
#define NSSIG_AAAA  "uuuu"
#define NSSIG_OPT   "B"

#define MAX_RECORD_COUNT 16
#define DN_EXPANDED 0x8000

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

	int flags;
	const uint8_t *domain;
};

struct dns_resource {
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t len;

	int flags;
	const uint8_t *domain;
	const uint8_t *value;
};

struct dns_parser {
	const uint8_t *strtab;
	const uint8_t *limit;
	uint8_t *comptr[MAX_RECORD_COUNT];

	struct dns_header head;
	struct dns_question question[MAX_RECORD_COUNT];
	struct dns_resource answer[MAX_RECORD_COUNT];
	struct dns_resource author[MAX_RECORD_COUNT];
	struct dns_resource addon[MAX_RECORD_COUNT];
};

#ifdef __cplusplus 
extern "C" { 
#endif

int dns_build(struct dns_parser *parser, uint8_t *frame, size_t len);
struct dns_parser * dns_parse(struct dns_parser *parser, const uint8_t *frame, size_t len);

#ifdef __cplusplus 
} 
#endif

#endif
