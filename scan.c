#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "scan.h"

static uint8_t xdigit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

size_t scan_uint8(const char *s, uint8_t *u) {
  uint8_t d, x;
  size_t i;

  for (i = x = 0; d = s[i] - '0', d < 10; i++) {
    if (x > UINT8_MAX / 10 || UINT8_MAX - d < 10 * x)
      return 0;
    x = x * 10 + d;
  }
  *u = x;
  return i;
}

size_t scan_xint8(const char *s, uint8_t *u) {
  uint8_t d, x;
  size_t i;

  for (i = x = 0; d = xdigit(s[i]), d < 16; i++) {
    if (x > UINT8_MAX / 16 || UINT8_MAX - d < 16 * x)
      return 0;
    x = x * 16 + d;
  }
  *u = x;
  return i;
}

size_t scan_uint16(const char *s, uint16_t *u) {
  uint16_t x;
  uint8_t d;
  size_t i;

  for (i = x = 0; d = s[i] - '0', d < 10; i++) {
    if (x > UINT16_MAX / 10 || UINT16_MAX - d < 10 * x)
      return 0;
    x = x * 10 + d;
  }
  *u = x;
  return i;
}

size_t scan_xint16(const char *s, uint16_t *u) {
  uint16_t x;
  uint8_t d;
  size_t i;

  for (i = x = 0; d = xdigit(s[i]), d < 16; i++) {
    if (x > UINT16_MAX / 16 || UINT16_MAX - d < 16 * x)
      return 0;
    x = x * 16 + d;
  }
  *u = x;
  return i;
}

size_t scan_uint32(const char *s, uint32_t *u) {
  uint32_t x;
  uint8_t d;
  size_t i;

  for (i = x = 0; d = s[i] - '0', d < 10; i++) {
    if (x > UINT32_MAX / 10 || UINT32_MAX - d < 10 * x)
      return 0;
    x = x * 10 + d;
  }
  *u = x;
  return i;
}

size_t scan_xint32(const char *s, uint32_t *u) {
  uint32_t x;
  uint8_t d;
  size_t i;

  for (i = x = 0; d = xdigit(s[i]), d < 16; i++) {
    if (x > UINT32_MAX / 16 || UINT32_MAX - d < 16 * x)
      return 0;
    x = x * 16 + d;
  }
  *u = x;
  return i;
}

size_t scan_uint64(const char *s, uint64_t *u) {
  uint64_t x;
  uint8_t d;
  size_t i;

  for (i = x = 0; d = s[i] - '0', d < 10; i++) {
    if (x > UINT64_MAX / 10 || UINT64_MAX - d < 10 * x)
      return 0;
    x = x * 10 + d;
  }
  *u = x;
  return i;
}

size_t scan_xint64(const char *s, uint64_t *u) {
  uint64_t x;
  uint8_t d;
  size_t i;

  for (i = x = 0; d = xdigit(s[i]), d < 16; i++) {
    if (x > UINT64_MAX / 16 || UINT64_MAX - d < 16 * x)
      return 0;
    x = x * 16 + d;
  }
  *u = x;
  return i;
}

size_t scan_ip4_prefix(const char *s, char *ip, size_t *len, size_t max) {
  size_t i = 0, m, n = 0;

  if (max && (n = scan_uint8(s, (uint8_t *) ip)))
    while (++i < max && s[n] == '.') {
      if (!(m = scan_uint8(s + n + 1, (uint8_t *) ip + i)))
        break;
      n += m + 1;
    }
  *len = i;
  return n;
}

size_t scan_ip4(const char *s, char ip[4]) {
  size_t i, n;

  n = scan_ip4_prefix(s, ip, &i, 4);
  return i == 4 ? n : 0;
}


size_t scan_ip6_prefix(const char *s, char *ip, size_t *len, size_t max) {
  size_t i = 0, m, n = 0;
  uint16_t u;

  if (max && (n = scan_xint16(s, &u))) {
    ip[i++] = u >> 8;
    ip[i++] = u;
    while (i < max && (s[n] == '.' || s[n] == ':')) {
      if (!(m = scan_xint16(s + n + 1, &u)))
        break;
      ip[i++] = u >> 8;
      ip[i++] = u;
      n += m + 1;
    }
  }
  *len = i;
  return n;
}

size_t scan_ip6(const char *s, char ip[16]) {
  size_t i, j, m, n;

  m = scan_ip6_prefix(s, ip, &i, 16);
  if (i == 16)
    return m;
  if (s[m] != '.' && s[m] != ':')
    return 0;
  if (s[m + 1] != '.' && s[m + 1] != ':')
    return 0;

  n = scan_ip6_prefix(s + m + 2, ip + i, &j, 16 - i);
  memmove(ip + 16 - j, ip + i, j);
  memset(ip + i, 0, 16 - i - j);
  return m + n + 2;
}
