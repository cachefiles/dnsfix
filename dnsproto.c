#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <assert.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "dnsproto.h"

struct dns_rsc_fixed {
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t len;
} __attribute__ ((packed));

static int get_rsc_fixed(struct dns_resource *res, struct dns_rsc_fixed *pf, const void *s, size_t len)
{
	*pf = *(const struct dns_rsc_fixed *)s;

	assert(len == sizeof(*pf));
	res->type = pf->type = ntohs(pf->type);
	res->klass = pf->klass = ntohs(pf->klass);
	res->ttl = pf->ttl = ntohl(pf->ttl);
	res->len = pf->len = ntohs(pf->len);

	return 0;
}

static const uint8_t * dn_skip(const uint8_t *dn, const uint8_t *limit)
{
	uint8_t pfx;

	while (dn < limit) {
		pfx = *dn++;
		if (pfx == 0) break;
		if (pfx & 0xc0) { dn++;  break; }
		dn += pfx;
	}

	return dn;
}

static const char * rsrc_verify_signature[256] = {
	[NSTYPE_A] = NSSIG_A,
	[NSTYPE_NS] = NSSIG_NS,
	[NSTYPE_CNAME] = NSSIG_CNAME,
	[NSTYPE_SOA] = NSSIG_SOA,
	[NSTYPE_PTR] = NSSIG_PTR,
	[NSTYPE_MX] = NSSIG_MX,
	[NSTYPE_AAAA] = NSSIG_AAAA,
	[NSTYPE_SRV] = NSSIG_SRV,
	[NSTYPE_OPT] = NSSIG_OPT,
};

const uint8_t * rsc_verify_handle(struct dns_resource *res, const uint8_t *buf, const uint8_t *frame, const uint8_t *limit)
{
	int len;
	uint8_t dn[256];
	const uint8_t *dopt = buf;

	if (res->type < 256 && rsrc_verify_signature[res->type]) {
		const char *sig0;
		const char *signature = rsrc_verify_signature[res->type];
		sig0 = signature;

		while (*signature) {
			switch (*signature++) {
				case 'B':
					dopt += res->len;
					break;

				case 'u':
					dopt += 4;
					break;

				case 'q':
					dopt += 2;
					break;

				case 's':
					len = dn_expand(frame, limit, dopt, dn, sizeof(dn));
					if (len > 0) {
						dopt += len;
						break;
					}

				default:
					return limit;
			}
		}

		if (dopt == buf + res->len) {
			return buf;
		}

	}

	return limit;
}

#define GET_SHORT(v, p) v = ntohs(*(uint16_t *)p)

struct dns_parser * dns_parse(struct dns_parser *parser, const uint8_t *frame, size_t len)
{
	const struct dns_header *phead = (const struct dns_header *)frame;
	const uint8_t *dotp = NULL;
	int num = 0;

	int16_t nstype, nsclass;
	struct dns_rsc_fixed f0;
	struct dns_question *nsq;
	struct dns_resource *res;
	memset(parser, 0, sizeof(*parser));

	parser->strtab = frame;
	parser->limit  = &frame[len];

	parser->head.ident = phead->ident;
	parser->head.flags = ntohs(phead->flags);
	parser->head.question = ntohs(phead->question);
	parser->head.answer   = ntohs(phead->answer);
	parser->head.author   = ntohs(phead->author);
	parser->head.addon    = ntohs(phead->addon);

	dotp = (const uint8_t *)(phead + 1);

	assert(parser->head.question < MAX_RECORD_COUNT);
	for (num = 0; dotp < parser->limit && num < parser->head.question; num ++)  {
		nsq = &parser->question[num];
		nsq->domain = dotp;
		dotp = dn_skip(dotp, parser->limit);
		GET_SHORT(nsq->type, dotp);
		dotp += sizeof(nstype);
		GET_SHORT(nsq->klass, dotp);
		dotp += sizeof(nsclass);
	}

	assert(parser->head.answer < MAX_RECORD_COUNT);
	for (num = 0; dotp < parser->limit && num < parser->head.answer; num ++)  {
		res = &parser->answer[num];
		res->domain = dotp;
		dotp = dn_skip(dotp, parser->limit);

		get_rsc_fixed(res, &f0, dotp, sizeof(f0));
		dotp += sizeof(f0);

		res->value = dotp;
		dotp = rsc_verify_handle(res, dotp, frame, parser->limit);
		dotp += f0.len;
	}

	assert(parser->head.author < MAX_RECORD_COUNT);
	for (num = 0; dotp < parser->limit && num < parser->head.author; num ++)  {
		res = &parser->author[num];
		res->domain = dotp;
		dotp = dn_skip(dotp, parser->limit);

		get_rsc_fixed(res, &f0, dotp, sizeof(f0));
		dotp += sizeof(f0);

		res->value = dotp;
		dotp = rsc_verify_handle(res, dotp, frame, parser->limit);
		dotp += f0.len;
	}

	assert(parser->head.addon < MAX_RECORD_COUNT);
	for (num = 0; dotp < parser->limit && num < parser->head.addon; num ++)  {
		res = &parser->addon[num];
		res->domain = dotp;
		dotp = dn_skip(dotp, parser->limit);

		get_rsc_fixed(res, &f0, dotp, sizeof(f0));
		dotp += sizeof(f0);

		res->value = dotp;
		dotp = rsc_verify_handle(res, dotp, frame, parser->limit);
		dotp += f0.len;
	}

	if (dotp > parser->limit) {
		return NULL;
	}

	return parser;
}

uint8_t * dn_put_domain(uint8_t *buf, uint8_t *limit, const uint8_t *domain, uint8_t **ptr, size_t count)
{
	int ret;

	if (buf < limit) {
		ret = dn_comp(domain, buf, limit - buf, ptr, ptr + count);
		if (ret > 0) {
			return buf + ret;
		}
	}

	return limit;
}

uint8_t * dn_put_short(uint8_t *buf, uint8_t *limit, uint16_t val)
{
	if (buf + sizeof(val) < limit) {
		val = htons(val);
		memcpy(buf, &val, sizeof(val));
		return buf + sizeof(val);
	}

	return limit;
}

uint8_t * dn_put_long(uint8_t *buf, uint8_t *limit, uint32_t val)
{
	if (buf + sizeof(val) < limit) {
		val = htonl(val);
		memcpy(buf, &val, sizeof(val));
		return buf + sizeof(val);
	}

	return limit;
}

uint8_t * dn_put_resource(uint8_t *dotp, uint8_t *limit, const struct dns_resource *res, struct dns_parser *parse)
{
	int ret, skip;
	uint8_t dn[256];
	const uint8_t *dnp;
	uint8_t *mark = NULL;

	if (res->type < 256 && rsrc_verify_signature[res->type]) {
		const char *right_val = res->value;
		const char *signature = rsrc_verify_signature[res->type];

		dnp = dn;
		if (res->flags & DN_EXPANDED) {
			dnp = res->domain;
		} else {
			dn_expand(parse->strtab, parse->limit, res->domain, dn, sizeof(dn));
		}

		ret = dn_comp(dnp, dotp, limit - dotp, parse->comptr, parse->comptr + MAX_RECORD_COUNT);
		if (ret <= 0 || dotp + ret >= limit) {
			return limit;
		}

		dotp += ret;
		dotp = dn_put_short(dotp, limit, res->type);
		dotp = dn_put_short(dotp, limit, res->klass);
		dotp = dn_put_long(dotp, limit, res->ttl);

		mark = dotp;
		dotp = dn_put_short(dotp, limit, res->len);

		while (*signature) {
			switch (*signature++) {
				case 'B':
					memcpy(dotp, right_val, res->len);
					right_val += res->len;
					dotp += res->len;
					break;

				case 'u':
					memcpy(dotp, right_val, 4);
					right_val += 4;
					dotp += 4;
					break;

				case 'q':
					memcpy(dotp, right_val, 2);
					right_val += 2;
					dotp += 2;
					break;

				case 's':
					if (right_val < parse->limit && right_val >= parse->strtab) {
						skip = dn_expand(parse->strtab, parse->limit, right_val, dn, sizeof(dn));
					} else {
						skip = dn_expand(res->value, res->value + res->len, right_val, dn, sizeof(dn));
					}

					ret = dn_comp(dn, dotp, limit - dotp, parse->comptr, parse->comptr + MAX_RECORD_COUNT);
					if (ret > 0) {
						right_val = dn_skip(right_val, res->value + res->len);
						dotp += ret;
						break;
					}

				default:
					return limit;
			}
		}

		if (dotp < limit && mark + res->len + 2 != dotp) {
			dn_put_short(mark, limit, dotp - mark - 2);
		}

		return dotp;
	}

	return limit;
}

int dns_build(struct dns_parser *parser, uint8_t *frame, size_t len)
{
	struct dns_header *phead = (struct dns_header *)frame;
	uint8_t *dotp = NULL;
	int num = 0;

	int16_t nstype, nsclass;
	struct dns_rsc_fixed f0;
	struct dns_resource *res;
	struct dns_question *nsq;

	uint8_t *strtab = frame;
	uint8_t *limit  = &frame[len];
	uint8_t dn[256];
	const uint8_t *dnp;

	phead->ident = parser->head.ident;
	phead->flags = htons(parser->head.flags);
	phead->question = htons(parser->head.question);
	phead->answer = htons(parser->head.answer);
	phead->author = htons(parser->head.author);
	phead->addon = htons(parser->head.addon);

	dotp = (uint8_t *)(phead + 1);
	memset(parser->comptr, 0, sizeof(parser->comptr));
	parser->comptr[0] = frame;

	assert(parser->head.question < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.question; num ++)  {
		nsq = &parser->question[num];

		dnp = dn;
		if (nsq->flags & DN_EXPANDED) {
			dnp = nsq->domain;
		} else {
			dn_expand(parser->strtab, parser->limit, nsq->domain, dn, sizeof(dn));
		}

		dotp = dn_put_domain(dotp, limit, dnp, parser->comptr, MAX_RECORD_COUNT);
		dotp = dn_put_short(dotp, limit, nsq->type);
		dotp = dn_put_short(dotp, limit, nsq->klass);
	}

	assert(parser->head.answer < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.answer; num ++)  {
		res = &parser->answer[num];
		dotp = dn_put_resource(dotp, limit, res, parser);
	}

	assert(parser->head.author < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.author; num ++)  {
		res = &parser->author[num];
		dotp = dn_put_resource(dotp, limit, res, parser);
	}

	assert(parser->head.addon < MAX_RECORD_COUNT);
	for (num = 0; dotp < limit && num < parser->head.addon; num ++)  {
		res = &parser->addon[num];
		dotp = dn_put_resource(dotp, limit, res, parser);
	}

	if (dotp >= limit) {
		return -1;
	}

	return dotp - frame;
}
