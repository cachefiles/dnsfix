#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#include "subnet_api.h"

subnet_t * lookupRoute(unsigned ip)
{
	int low = 0, high = _net_count -1;

	while (low <= high) {
		int mid = (low + high) / 2;
		int pref = _net_list[mid].prefixlen;
		unsigned msk1 = (~0u >> pref);
		unsigned net0 = (_net_list[mid].network);

		if ((ip & ~msk1) == net0)
			return &_net_list[mid];

		if (net0 > ip) {
			high = mid - 1;
		} else if (net0 < ip) {
			low = mid + 1;
		} else {
			fprintf(stderr, "break, %x %d\n", ip, _net_count);
			break;
		}
	}

	return NULL;
}
