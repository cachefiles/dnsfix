#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "subnet_api.h"

int _net_count = 0;
subnet_t _net_list[25600];

int includeNetwork(uint32_t network, uint8_t prefix)
{
	int i, j = 0;
	/* super, exclude, subset, merge */
	uint32_t mask = (~0u >> prefix);

	/* step1: subset check */
	for (i = 0; i < _net_count; i++) {
		subnet_t snet = _net_list[i];
		uint32_t smask = (~0u >> snet.prefixlen);

		if (snet.prefixlen <= prefix &&
				snet.network == (~smask & network))
			return 0;
	}

	/* step2: merge */
    uint32_t test, ksam, scale = 0;
	subnet_t nnet = {network & ~mask, 0, 0, prefix};

    for (i = 0; i < _net_count; i++) {
        subnet_t snet = _net_list[i];

        if (snet.prefixlen > nnet.prefixlen)
            continue;

		ksam = (~0u >> snet.prefixlen);
        test = snet.network ^ (nnet.network & ~ksam);

		if (test == ksam + 1)
			scale |= test;
    }

	scale >>= (32 - nnet.prefixlen);
	while (nnet.prefixlen > 0 && (scale & 1)) {
		nnet.prefixlen--;
		scale >>= 1;
	}

	mask = (~0u >> nnet.prefixlen);
	nnet.network &= ~mask;

	/* step3: super check */
	for (i = 0; i < _net_count; i++) {
		subnet_t snet = _net_list[i];

		if ((snet.network & ~mask) != nnet.network)
			_net_list[j++] = _net_list[i];
		else if (snet.prefixlen < nnet.prefixlen)
			assert(0);
	}

	_net_list[j++] = nnet;
	_net_count = j;

	return 0;
}

int excludeNetwork(uint32_t network, uint8_t prefixlen)
{
	int i, j = 0, n = 0;
	uint32_t net1, msk1, newnet;
	uint32_t net0, msk0 = (~0u >> prefixlen);

	for (i = 0; i < _net_count; i++) {
		int pref = _net_list[i].prefixlen;

		if (pref <= prefixlen) {
			msk1 = (~0u >> pref);
			net0 = (network & ~msk1);

			if (_net_list[i].network == net0) {
				assert(i == j);

				while (++i < _net_count)
					_net_list[j++] = _net_list[i];
				_net_count = j;

				for (int k = pref + 1; k <= prefixlen; k++) {
					msk1   = (~0u >> k);
					newnet = network & ~msk1;
					includeNetwork(newnet ^ (msk1 + 1), (int)k);
				}

				return 0;
			}

			_net_list[j++] = _net_list[i];
			continue;
		}

		net1 = (_net_list[i].network & ~msk0);
		if (net1 == network) {
			continue;
		}

		_net_list[j++] = _net_list[i];
	}

	_net_count = j;
	return 0;
}

#define COUNTOF(list) (sizeof(list)/sizeof(*list))
void initRoute(const char *tag)
{
	char * _include[] = {"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3"};
	char * _internal[] = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"};

	char *_exclude[] = {"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"};
	/* prebuilt: NONE INTERNAL EXTERNAL */

	int prefixlen;
	unsigned network;
	char sNetwork[128];

	_net_count = 0;
	for (int i = 0; i < COUNTOF(_include); i++) {
		int nmatch = sscanf(_include[i], "%128[0-9.]/%d%*s", sNetwork, &prefixlen);

		if (nmatch != 2) {
			fprintf(stderr, "match: %d %s\n", nmatch, _include[i]);
			continue;
		}

		network = inet_addr(sNetwork);
		includeNetwork(htonl(network), prefixlen);
	}

	for (int i = 0; i < COUNTOF(_exclude); i++) {
		int nmatch = sscanf(_exclude[i], "%128[0-9.]/%d%*s", sNetwork, &prefixlen);

		if (nmatch != 2) {
			continue;
		}

		network = inet_addr(sNetwork);
		excludeNetwork(htonl(network), prefixlen);
	}

	return;
}

void loadRoute(const char *path, int (*callback)(uint32_t , uint8_t))
{

	int prefixlen;
	uint32_t network;
	char sNetwork[128];

	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		return;
	}

    char line[1024] = "";
    while (fgets(line, sizeof(line) -1, fp) != NULL) {
        int nmatch = sscanf(line, "%123[^/]/%d", sNetwork, &prefixlen);

        if (nmatch == 2) {
            network = inet_addr(sNetwork);
            (*callback)(htonl(network), prefixlen);
        } else {
            // fscanf(fp, "%s", sNetwork);
            fprintf(stderr, "break nmatch %d %s\n", nmatch, sNetwork);
            break;
        }
    }
    fclose(fp);

	return;
} 

int subnet_compare(const void *a, const void *b)
{
	subnet_t *pa, *pb;
	pa = (subnet_t *)a, pb = (subnet_t *)b;
	return (pa->network > pb->network) - (pa->network < pb->network);
}

static void dumpRoute(void)
{
	qsort(_net_list, _net_count, sizeof(_net_list[0]), subnet_compare);

	fprintf(stdout, "#include \"subnet_api.h\"\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "int _net_count = %d;\n", _net_count);
	fprintf(stdout, "\n");
	fprintf(stdout, "subnet_t _net_list[25600] = {");

	for (int i = 0; i < _net_count; i++) {
		int slim = (i & 0x03);
		fprintf(stdout, "%s", slim? " ": "\n    ");
		fprintf(stdout, "{0x%08x, 0, 0, %2d}%s", _net_list[i].network,
				_net_list[i].prefixlen, (i + 1 == _net_count? "\n": ","));
	}
	fprintf(stdout, "};\n");

	return;
}

int queryRoute(uint32_t ipv4)
{
    char sTarget[128], sNetwork[128];

    uint32_t target = ntohl(ipv4);
    subnet_t *subnet = lookupRoute(target);

    inet_ntop(AF_INET, &ipv4, sTarget, sizeof(sTarget));

	uint32_t last_network = 0;
	for (int i = 0; i < _net_count; i++) {
		// fprintf(stderr, "%08x/%d\n", _net_list[i].network, _net_list[i].prefixlen);
		assert(last_network < _net_list[i].network || last_network == 0);
		last_network = _net_list[i].network;
	}

    if (subnet != 0) {
        unsigned network = htonl(subnet->network);

        inet_ntop(AF_INET, &network, sNetwork, sizeof(sNetwork));
        fprintf(stderr, "ACTIVE network: %s/%d by %s\n", sNetwork, subnet->prefixlen, sTarget);
	}

	fprintf(stderr, "count %d\n", _net_count);
	return 0;
}

int main(int argc, char *argv[])
{
    int i, skip = 0, query = 0;

    for (i = 1; i < argc; i++) {
        if (skip-- > 0)
            continue;

        if (strcmp(argv[i], "-h") == 0) {
            fprintf(stderr, "%s -h -i <include> -e <exclude> -t <reset>  -q query exclude-file-list\n", argv[0]);
            exit(0);
        }

        if (i + 1 < argc &&
                strcmp(argv[i], "-i") == 0) {
            skip = 1;
            loadRoute(argv[i + skip], includeNetwork);
            continue;
        }

        if (i + 1 < argc &&
                strcmp(argv[i], "-e") == 0) {
            skip = 1;
            loadRoute(argv[i + skip], excludeNetwork);
            continue;
        }

        if (i + 1 < argc &&
                strcmp(argv[i], "-t") == 0) {
            skip = 1;
            initRoute(argv[i + skip]);
            continue;
        }

        if (i + 1 < argc &&
                strcmp(argv[i], "-q") == 0) {
            skip = 1;
            if (query == 0) {
                qsort(_net_list, _net_count, sizeof(_net_list[0]), subnet_compare);
                query = 1;
            }
            queryRoute(inet_addr(argv[i + 1]));
            continue;
        }

        if (_net_count == 0)
            initRoute("DEFAULT");

        loadRoute(argv[i], excludeNetwork);
    }

    if (query == 0)
        dumpRoute();

    return 0;
}
