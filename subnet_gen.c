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
static int _family = AF_INET;

uint64_t pton_val(const char *addr)
{
	uint64_t val = 0;
	uint32_t data[4];

	inet_pton(_family, addr, data);

	if (_family == AF_INET) {
		val = htonl(data[0]);
		return val << 32;
	}

	if (_family == AF_INET6) {
		val = htonl(data[0]);
		return (val << 32) | htonl(data[1]);
	}

	return val;
}

int includeNetwork(uint64_t network, uint8_t prefix)
{
	int i, j = 0;
	/* super, exclude, subset, merge */
	uint64_t mask = (~0ull >> prefix);

	/* step1: subset check */
	for (i = 0; i < _net_count; i++) {
		subnet_t snet = _net_list[i];
		uint64_t smask = (~0ull >> snet.prefixlen);

		if (snet.prefixlen <= prefix &&
				snet.network == (~smask & network)) {
			return 0;
		}
	}

	/* step2: merge */
    uint64_t test, ksam, scale = 0;
	subnet_t nnet = {.network = network & ~mask, .prefixlen = prefix};

    for (i = 0; i < _net_count; i++) {
        subnet_t snet = _net_list[i];

        if (snet.prefixlen > nnet.prefixlen)
            continue;

		ksam = (~0ull >> snet.prefixlen);
        test = snet.network ^ (nnet.network & ~ksam);

		if (test == ksam + 1)
			scale |= test;
    }

	scale >>= (64 - nnet.prefixlen);
	while (nnet.prefixlen > 0 && (scale & 1)) {
		nnet.prefixlen--;
		scale >>= 1;
	}

	mask = (~0ull >> nnet.prefixlen);
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

int excludeNetwork(uint64_t network, uint8_t prefixlen)
{
	int i, j = 0, n = 0;
	uint64_t net1, msk1, newnet;
	uint64_t net0, msk0 = (~0ull >> prefixlen);

	for (i = 0; i < _net_count; i++) {
		int pref = _net_list[i].prefixlen;

		if (pref <= prefixlen) {
			msk1 = (~0ull >> pref);
			net0 = (network & ~msk1);

			if (_net_list[i].network == net0) {
				assert(i == j);

				while (++i < _net_count)
					_net_list[j++] = _net_list[i];
				_net_count = j;

				for (int k = pref + 1; k <= prefixlen; k++) {
					msk1   = (~0ull >> k);
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
void initRoute6(const char *tag)
{
	char * _include[] = {"2000::/3"};
	char * _internal[] = {""};

	char *_exclude[] = {"2002::/16"};
	/* prebuilt: NONE INTERNAL EXTERNAL */

	int prefixlen;
	uint64_t network;
	char sNetwork[128];

	_net_count = 0;
	for (int i = 0; i < COUNTOF(_include); i++) {
		int nmatch = sscanf(_include[i], "%128[0-9.:]/%d%*s", sNetwork, &prefixlen);

		if (nmatch != 2) {
			fprintf(stderr, "match: %d %s\n", nmatch, _include[i]);
			continue;
		}

		if (prefixlen > 48) {
		    int save = prefixlen;
			int origin = prefixlen;
			prefixlen = 32;
			while (save > 1) {
				prefixlen--;
				save >>= 1;
			}
		}

		network = pton_val(sNetwork);
		includeNetwork(network, prefixlen);
	}

	for (int i = 0; i < COUNTOF(_exclude); i++) {
		int nmatch = sscanf(_exclude[i], "%128[0-9.:]/%d%*s", sNetwork, &prefixlen);

		if (nmatch != 2) {
			continue;
		}

		if (prefixlen > 48) {
		    int save = prefixlen;
			int origin = prefixlen;
			prefixlen = 32;
			while (save > 1) {
				prefixlen--;
				save >>= 1;
			}
		}

		network = pton_val(sNetwork);
		excludeNetwork(network, prefixlen);
	}

	return;
}

void initRoute(const char *tag)
{
	char * _include[] = {"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3"};
	char * _internal[] = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"};

	char *_exclude[] = {"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"};
	/* prebuilt: NONE INTERNAL EXTERNAL */

	int prefixlen;
	uint64_t network;
	char sNetwork[128];

	_net_count = 0;
	for (int i = 0; i < COUNTOF(_include); i++) {
		int nmatch = sscanf(_include[i], "%128[0-9a-f.:]/%d%*s", sNetwork, &prefixlen);

		if (nmatch != 2) {
			fprintf(stderr, "match: %d %s\n", nmatch, _include[i]);
			continue;
		}

		network = pton_val(sNetwork);
		includeNetwork(network, prefixlen);
	}

	for (int i = 0; i < COUNTOF(_exclude); i++) {
		int nmatch = sscanf(_exclude[i], "%128[0-9a-f.:]/%d%*s", sNetwork, &prefixlen);

		if (nmatch != 2) {
			continue;
		}

		network = pton_val(sNetwork);
		excludeNetwork(network, prefixlen);
	}

	return;
}

void loadRoute(const char *path, int (*callback)(uint64_t , uint8_t))
{

	int prefixlen;
	uint64_t network;
	char sNetwork[128];

	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		return;
	}

    char line[1024] = "";
    while (fgets(line, sizeof(line) -1, fp) != NULL) {
        int nmatch = sscanf(line, "%123[^/]/%d", sNetwork, &prefixlen);

		if (prefixlen > 48) {
		    int save = prefixlen;
			int origin = prefixlen;
			prefixlen = 32;
			while (save > 1) {
				prefixlen--;
				save >>= 1;
			}
		}

        if (nmatch == 2) {
            network = pton_val(sNetwork);
            (*callback)(network, prefixlen);
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
		fprintf(stdout, "{0x%08llx, 0, 0, %2d}%s", _net_list[i].network,
				_net_list[i].prefixlen, (i + 1 == _net_count? "\n": ","));
	}
	fprintf(stdout, "};\n");

	return;
}

int queryRoute(uint64_t ipv4, char *sTarget)
{
    char sNetwork[128];

    uint64_t target = (ipv4);
    subnet_t *subnet = lookupRoute(target);

	uint64_t last_network = 0;
	for (int i = 0; i < _net_count; i++) {
		// fprintf(stderr, "%08x/%d\n", _net_list[i].network, _net_list[i].prefixlen);
		assert(last_network < _net_list[i].network || last_network == 0);
		last_network = _net_list[i].network;
	}

    if (subnet != 0) {
        uint64_t network = (subnet->network);

        inet_ntop(_family, &network, sNetwork, sizeof(sNetwork));
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
                strcmp(argv[i], "-6") == 0) {
			_family = AF_INET6;
            continue;
        }

        if (i + 1 < argc &&
                strcmp(argv[i], "-4") == 0) {
			_family = AF_INET;
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
			if (_family == AF_INET) 
				initRoute(argv[i + skip]);
			else if (_family == AF_INET6) 
				initRoute6(argv[i + skip]);
            continue;
        }

        if (i + 1 < argc &&
                strcmp(argv[i], "-q") == 0) {
            skip = 1;
            if (query == 0) {
                qsort(_net_list, _net_count, sizeof(_net_list[0]), subnet_compare);
                query = 1;
            }

            queryRoute(pton_val(argv[i + 1]), argv[i + 1]);
            continue;
        }

        if (_net_count == 0) {
			if (_family == AF_INET) 
				initRoute("DEFAULT");
			else if (_family == AF_INET6) 
				initRoute6("DEFAULT");
		}

        loadRoute(argv[i], excludeNetwork);
    }

    if (query == 0)
        dumpRoute();

    return 0;
}
