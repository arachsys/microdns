#ifndef SCAN_H
#define SCAN_H

#include <stddef.h>
#include <stdint.h>

size_t scan_uint8(const char *s, uint8_t *u);
size_t scan_xint8(const char *s, uint8_t *u);

size_t scan_uint16(const char *s, uint16_t *u);
size_t scan_xint16(const char *s, uint16_t *u);

size_t scan_uint32(const char *s, uint32_t *u);
size_t scan_xint32(const char *s, uint32_t *u);

size_t scan_uint64(const char *s, uint64_t *u);
size_t scan_xint64(const char *s, uint64_t *u);

size_t scan_ip4_prefix(const char *s, char *ip, size_t *len, size_t max);
size_t scan_ip4(const char *s, char ip[4]);
size_t scan_ip6_prefix(const char *s, char *ip, size_t *len, size_t max);
size_t scan_ip6(const char *s, char ip[16]);

#endif
