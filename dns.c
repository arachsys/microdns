#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "pack.h"
#include "stralloc.h"

size_t dns_domain_length(const char *dn) {
  size_t len = 0;

  while (dn[len])
    len += (uint8_t) dn[len] + 1;
  return len + 1;
}

int dns_domain_copy(stralloc *out, const char *in) {
  return stralloc_copyb(out, in, dns_domain_length(in));
}

int dns_domain_equal(const char *dn1, const char *dn2) {
  size_t i, len;
  uint8_t x, y;

  len = dns_domain_length(dn1);
  if (dns_domain_length(dn2) != len)
    return 0;

  for (i = 0; i < len; i++) {
    x = dn1[i] >= 'A' && dn1[i] <= 'Z' ? dn1[i] + 'a' - 'A' : dn1[i];
    y = dn2[i] >= 'A' && dn2[i] <= 'Z' ? dn2[i] + 'a' - 'A' : dn2[i];
    if (x != y) /* safe because 63 < 'A' */
      return 0;
  }
  return 1;
}

int dns_domain_fromdot(stralloc *out, const char *in, size_t n) {
  size_t labellen = 0, namelen = 0;
  char byte, label[63], name[255];

  while (n > 0) {
    byte = *in++, n--;
    if (byte == '.') {
      if (labellen) {
        if (namelen + labellen + 1 > sizeof name)
          return  errno = EPROTO, 0;
        name[namelen++] = labellen;
        memcpy(name + namelen, label, labellen);
        namelen += labellen;
        labellen = 0;
      }
      continue;
    }

    if (byte  == '\\') {
      if (n == 0)
        break;
      byte = *in++, n--;
      if (byte >= '0' && byte <= '7') {
        byte = byte - '0';
        if (n > 0 && *in >= '0' && *in <= '7') {
          byte = (byte << 3) + *in++ - '0', n--;
          if (n > 0 && *in >= '0' && *in <= '7')
            byte = (byte << 3) + *in++ - '0', n--;
        }
      }
    }

    if (labellen >= sizeof label)
      return errno = EPROTO, 0;
    label[labellen++] = byte;
  }

  if (labellen > 0) {
    if (namelen + labellen + 1 > sizeof name)
      return errno = EPROTO, 0;
    name[namelen++] = labellen;
    memcpy(name + namelen, label, labellen);
    namelen += labellen;
    labellen = 0;
  }

  if (namelen + 1 > sizeof name)
    return errno = EPROTO, 0;
  name[namelen++] = 0;
  return stralloc_copyb(out, name, namelen);
}

int dns_name4_domain(stralloc *name, const char ip[4]) {
  if (!stralloc_ready(name, 30))
    return 0;
  stralloc_zero(name);

  for (int i = 0; i < 4; i++) {
    name->s[name->len] = 1;
    for (uint8_t x = ip[3 - i]; x > 9; x /= 10)
      name->s[name->len]++;
    for (uint8_t n = name->s[name->len], x = ip[3 - i]; n > 0; n--)
      name->s[name->len + n] = '0' + x % 10, x /= 10;
    name->len += name->s[name->len] + 1;
  }
  memcpy(name->s + name->len, "\7in-addr\4arpa\0", 14);
  name->len += 14;
  return 1;
}

int dns_name6_domain(stralloc *name, const char ip[16]) {
  const char xdigit[16] = "0123456789abcdef";

  if (!stralloc_ready(name, 74))
    return 0;
  stralloc_zero(name);

  for (int i = 0; i < 16; i++) {
    name->s[name->len++] = 1;
    name->s[name->len++] = xdigit[(uint8_t) ip[15 - i] & 15];
    name->s[name->len++] = 1;
    name->s[name->len++] = xdigit[(uint8_t) ip[15 - i] >> 4];
  }
  memcpy(name->s + name->len, "\3ip6\4arpa\0", 10);
  name->len += 10;
  return 1;
}

int dns_packet_copy(size_t *pos, char *out, size_t len,
    const char *in, size_t size) {
  if (size < *pos + len)
    return errno = EPROTO, 0;
  memcpy(out, in + *pos, len);
  *pos += len;
  return 1;
}

int dns_packet_getname(size_t *pos, stralloc *out,
    const char *in, size_t size) {
  size_t cursor = *pos, first = 0, loop = 0, namelen = 0;
  uint8_t byte, state = 0;
  char name[255];

  while (1) {
    if (cursor >= size || ++loop >= 1000)
      return errno = EPROTO, 0;
    byte = in[cursor++];

    if (state) {
      if (namelen >= sizeof name)
        return errno = EPROTO, 0;
      name[namelen++] = byte, state--;
      continue;
    }

    while (byte >= 192) {
      size_t where = (byte - 192) << 8;
      if (cursor >= size || ++loop >= 1000)
        return errno = EPROTO, 0;

      byte = in[cursor++];
      if (!first)
        first = cursor;
      cursor = where + byte;

      if (cursor >= size)
        return errno = EPROTO, 0;
      byte = in[cursor++];
    }

    if (byte >= 64 || namelen >= sizeof name)
      return errno = EPROTO, 0;
    state = name[namelen++] = byte;

    if (byte == 0)
      break;
  }

  if (!dns_domain_copy(out, name))
    return 0;
  if (first)
    *pos = first;
  else
    *pos = cursor;
  return 1;
}

int dns_packet_skipname(size_t *pos, const char *in, size_t size) {
  size_t cursor = *pos;

  while (cursor < size) {
    uint8_t byte = in[cursor++];
    if (byte >= 192) {
      *pos = cursor + 1;
      return 1;
    }
    if (byte >= 64)
      break;
    if (byte == 0) {
      *pos = cursor;
      return 1;
    }
    cursor += byte;
  }
  return errno = EPROTO, 0;
}
