#ifndef _SUBNET_H_
#define _SUBNET_H_

#include <stdint.h>

typedef struct subnet_s {
	uint32_t network;
	uint16_t zero;
	uint8_t  flags;
	uint8_t  prefixlen;
} subnet_t;

extern int _net_count;
extern subnet_t _net_list[];

#ifdef __cplusplus
extern "C"
#endif
subnet_t * lookupRoute(unsigned ip);

#endif
