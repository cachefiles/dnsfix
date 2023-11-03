#ifndef _SUBNET_H_
#define _SUBNET_H_

#include <stdint.h>

typedef struct subnet_s {
	uint8_t  flags;
	uint8_t  prefixlen;
	uint16_t zero;
	uint32_t keep;
	uint64_t network;
} subnet_t;

extern int _net4_count;
extern subnet_t _net4_list[];

extern int _net6_count;
extern subnet_t _net6_list[];

#ifdef __cplusplus
extern "C"
#endif

subnet_t * lookupRoute4(uint64_t ip);
subnet_t * lookupRoute6(uint64_t v6ip);

uint64_t htonll(uint64_t val);
uint64_t pton_val(const char *addr, int family);

#endif
