#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#include "subnet_api.h"

subnet_t * lookupRoute6(uint64_t ip)
{
	int low = 0, high = _net6_count -1;

	while (low <= high) {
		int mid = (low + high) / 2;
		int pref = _net6_list[mid].prefixlen;
		uint64_t msk1 = (~0ull >> pref);
		uint64_t net0 = (_net6_list[mid].network);

		if ((ip & ~msk1) == net0)
			return &_net6_list[mid];

		if (net0 > ip) {
			high = mid - 1;
		} else if (net0 < ip) {
			low = mid + 1;
		} else {
			fprintf(stderr, "break, %lx %d\n", ip, _net6_count);
			break;
		}
	}

	return NULL;
}

subnet_t * lookupRoute4(uint64_t ip)
{
	int low = 0, high = _net4_count -1;

	while (low <= high) {
		int mid = (low + high) / 2;
		int pref = _net4_list[mid].prefixlen;
		uint64_t msk1 = (~0ull >> pref);
		uint64_t net0 = (_net4_list[mid].network);

		if ((ip & ~msk1) == net0)
			return &_net4_list[mid];

		if (net0 > ip) {
			high = mid - 1;
		} else if (net0 < ip) {
			low = mid + 1;
		} else {
			fprintf(stderr, "break, %llx %d\n", ip, _net4_count);
			break;
		}
	}

	return NULL;
}

uint64_t htonll(uint64_t val)
{
	uint64_t data[2];

	if (htons(0x1234) == 0x1234) {
		return val;
	}

	data[0] = htonl(val >> 32);
	data[1] = htonl(val & 0xffffffff);

	return (data[1] << 32) | data[0];
}

uint64_t pton_val(const char *addr, int family)
{
	uint64_t val[2] = {};
	inet_pton(family, addr, val);
	return htonll(val[0]);
}
