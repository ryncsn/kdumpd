#include <stdint.h>
#include <bits/endian.h>
#include <arpa/inet.h>

#ifndef ntohll
#if __BYTE_ORDER == __BIG_ENDIAN
uint64_t ntohll(uint64_t a) {
	return a;
}
#else
uint64_t ntohll(uint64_t a) {
	uint32_t lo = a & 0xffffffff;
	uint32_t hi = a >> 32U;
	lo = ntohl(lo);
	hi = ntohl(hi);
	return ((uint64_t) lo) << 32U | hi;
}
#endif
#endif
