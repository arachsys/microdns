#include <stdint.h>
#include <string.h>

#include "dns.h"
#include "pack.h"
#include "response.h"

static stralloc *response = &(stralloc) {
  .limit = -1
};

static struct {
  char s[128];
  uint16_t pos;
} name[128];

static size_t namec;
static size_t rdata;

int response_addbytes(const char *in, unsigned int len) {
  return stralloc_catb(response, in, len);
}

int response_addshort(uint16_t u) {
  char buffer[2];

  pack_uint16_big(buffer, u);
  return response_addbytes(buffer, 2);
}

int response_addlong(uint32_t u) {
  char buffer[4];

  pack_uint32_big(buffer, u);
  return response_addbytes(buffer, 4);
}

int response_addname(const char *d) {
  size_t dlen = dns_domain_length(d), i;

  while (*d) {
    for (i = 0; i < namec; i++)
      if (dns_domain_equal(d, name[i].s))
        return response_addshort(49152 + name[i].pos);
    if (dlen <= 128 && response->len < 16384)
      if (namec < sizeof name / sizeof *name) {
        memcpy(name[namec].s, d, dlen);
        name[namec].pos = response->len;
        namec++;
      }
    i = (uint8_t) *d + 1;
    if (!response_addbytes(d, i))
      return 0;
    d += i, dlen -= i;
  }
  return response_addbytes(d, 1);
}

size_t response_length(void) {
  return response->len;
}

int response_copy(size_t *pos, char *out, size_t len) {
  return dns_packet_copy(pos, out, len, response->s, response->len);
}

int response_getname(size_t *pos, stralloc *d) {
  return dns_packet_getname(pos, d, response->s, response->len);
}

int response_skipname(size_t *pos) {
  return dns_packet_skipname(pos, response->s, response->len);
}

int response_query(stralloc *r, stralloc *qname, char qtype[2],
    char qclass[2]) {
  size_t pos = 12;

  response = r;
  namec = rdata = 0;

  if (r->len < 12 || r->s[2] & 128) {
    r->len = 0;
    return 0; /* truncated header or QR set */
  }

  if (r->s[2] & 254) /* not a standard query */
    return response_rcode(RCODE_NOTIMPL), 0;

  if (memcmp(r->s + 4, "\0\1", 2)) /* QDCOUNT != 1 */
    return response_rcode(RCODE_FORMERR), 0;
  if (!dns_packet_getname(&pos, qname, r->s, r->len))
    return response_rcode(RCODE_FORMERR), 0;
  if (!dns_packet_copy(&pos, qtype, 2, r->s, r->len))
    return response_rcode(RCODE_FORMERR), 0;
  if (!dns_packet_copy(&pos, qclass, 2, r->s, r->len))
    return response_rcode(RCODE_FORMERR), 0;

  r->len = 12; /* inherit ID, RD and QDCOUNT */
  memset(r->s + 6, 0, 6); /* ANCOUNT, NSCOUNT, ARCOUNT */

  if (!response_addname(qname->s))
    return response_rcode(RCODE_SERVFAIL), 0;
  if (!response_addbytes(qtype, 2))
    return response_rcode(RCODE_SERVFAIL), 0;
  if (!response_addbytes(qclass, 2))
    return response_rcode(RCODE_SERVFAIL), 0;
  return 1;
}

void response_authoritative(int flag) {
  response->s[2] &= ~4;
  if (flag)
    response->s[2] |= 4;
}

void response_rcode(uint8_t rcode) {
  if (rcode == RCODE_FORMERR
        || rcode == RCODE_SERVFAIL
        || rcode == RCODE_NOTIMPL
        || rcode == RCODE_REFUSED) {
    size_t pos = 12;
    response->s[2] &= ~4; /* AA = 0 */

    if (!memcmp(response->s + 4, "\0\1", 2)
          && response_skipname(&pos)
          && response->len >= pos + 4) {
      memset(response->s + 6, 0, 6);
      response->len = pos + 4;
    } else {
      memset(response->s + 4, 0, 8);
      response->len = 12;
    }
  }
  response->s[2] |= 128; /* QR = 1 */
  response->s[3] = rcode;
}

int response_rstart(const char *d, const char type[2], uint32_t ttl) {
  if (!response_addname(d))
    return 0;
  if (!response_addbytes(type, 2))
    return 0;
  if (!response_addbytes(DNS_C_IN, 2))
    return 0;
  if (!response_addlong(ttl))
    return 0;
  if (!response_addbytes("\0\0", 2))
    return 0;
  rdata = response->len;
  return 1;
}

void response_rfinish(size_t section) {
  pack_uint16_big(response->s + rdata - 2, response->len - rdata);
  if (!++response->s[section + 1])
    response->s[section]++;
  rdata = 0;
}

void response_finish(size_t len) {
  if (len < response->len) {
    size_t pos = 12;
    if (response_skipname(&pos)) {
      memset(response->s + 6, 0, 6);
      response->len = pos + 4;
    } else {
      memset(response->s + 4, 0, 8);
      response->len = 12;
    }
    response->s[2] |= 2;
  }
  if (len < response->len)
    response->len = len;
  return;
}
