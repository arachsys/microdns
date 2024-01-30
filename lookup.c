#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cdb/cdb.h"
#include "dns.h"
#include "pack.h"
#include "response.h"

static struct cdb c;
static char cloc[2];
static uint64_t now;

static char data[65536];
static size_t dlen;
static size_t dpos;

static uint64_t ttd;
static uint32_t ttl;
static char type[2];

static int dobytes(size_t len) {
  if (dlen < dpos + len)
    return 0;
  if (!response_addbytes(data + dpos, len))
    return 0;
  dpos += len;
  return 1;
}

static int doname(stralloc *name) {
  if (!dns_packet_getname(&dpos, name, data, dlen))
    return 0;
  return response_addname(name->s);
}

static int find(char *name, int wild) {
  while (1) {
    char byte, rloc[2], ttlstr[4], ttdstr[8];
    int r = cdb_findnext(&c, name, dns_domain_length(name));

    if (r <= 0)
      return r;
    if (dlen = cdb_datalen(&c), dlen > sizeof data)
      return -1;
    if (cdb_read(&c, data, dlen, cdb_datapos(&c)) < 0)
      return -1;

    if (dpos = 0, !dns_packet_copy(&dpos, type, 2, data, dlen))
      return -1;
    if (!dns_packet_copy(&dpos, &byte, 1, data, dlen))
      return -1;

    if (byte == '=' + 1 || byte == '*' + 1) {
      if (!dns_packet_copy(&dpos, rloc, 2, data, dlen))
        return -1;
      if (memcmp(rloc, cloc, 2))
        continue;
      byte--;
    }

    if (wild != (byte == '*'))
      continue;

    if (!dns_packet_copy(&dpos, ttlstr, 4, data, dlen))
      return -1;
    if (!dns_packet_copy(&dpos, ttdstr, 8, data, dlen))
      return -1;
    ttl = unpack_uint32_big(ttlstr);
    ttd = unpack_uint64_big(ttdstr);

    if (now - ttd >= 0x8000000000000000)
      continue;
    if (now - ttd + ttl >= 0x8000000000000000)
      ttl = 0x8000000000000000 - now + ttd;
    return 1;
  }
}

static int locate(const void *ip, size_t len) {
  char key[19];
  int rc = 0;

  memset(cloc, 0, 2);
  switch (len) {
    case 4: /* IPv4 */
      memcpy(key, "\0%4", 3);
      memcpy(key + 3, ip, 4);
      for (int n = 7; n >= 3 && rc == 0; n--)
        if ((rc = cdb_find(&c, key, n)) < 0)
          return 0;
      break;
    case 16: /* IPv6 */
      memcpy(key, "\0%6", 3);
      memcpy(key + 3, ip, 16);
      for (int n = 19; n >= 3 && rc == 0; n -= 2)
        if ((rc = cdb_find(&c, key, n)) < 0)
          return 0;
      break;
  }

  if (rc > 0 && cdb_datalen(&c) == 2)
    if (cdb_read(&c, cloc, 2, cdb_datapos(&c)) < 0)
      return 0;
  return 1;
}

static void refresh(const char *filename) {
  static int fd = -1;
  static time_t refreshed = 0;

  if (fd >= 0 && now < refreshed + 10)
    return;

  cdb_free(&c);
  if (fd >= 0)
    close(fd);

  fd = open(filename, O_RDONLY);
  if (fd >= 0)
    refreshed = now;
  cdb_init(&c, fd);
}

static int want(const char *name, const char type[2]) {
  static stralloc d;
  char buffer[10];
  size_t pos = 12;

  if (!response_skipname(&pos))
    return 1;
  pos += 4;

  while (response_getname(&pos, &d)) {
    if (!response_copy(&pos, buffer, 10))
      break;
    if (dns_domain_equal(d.s, name))
      if (!memcmp(type, buffer, 2))
        return 0;
    pos += unpack_uint16_big(buffer + 8);
  }
  return 1;
}

static int respond(stralloc *qname, const char qtype[2]) {
  static stralloc name;
  size_t answer, authority, additional;
  int authoritative, nameservers, restarted = 0;
  int found, gavesoa, rc;
  char *control, *wild;

  if (!memcmp(qtype, DNS_T_AXFR, 2)) {
    response_rcode(RCODE_NOTIMPL);
    return 1;
  }

ANSWER:
  answer = response_length();
  control = qname->s;

  while (1) {
    authoritative = 0;
    nameservers = 0;
    cdb_findstart(&c);

    while ((rc = find(control, 0))) {
      if (rc < 0)
        return 0;
      if (!memcmp(type, DNS_T_SOA, 2))
        authoritative++;
      if (!memcmp(type, DNS_T_NS, 2))
        nameservers++;
    }

    if (nameservers > 0)
      break;

    if (!*control) { /* qname is not within our bailiwick */
      if (!restarted)
        response_rcode(RCODE_REFUSED);
      return 1;
    }
    control += *control + 1;
  }

  if (!authoritative) {
    if (!restarted)
      response_authoritative(0);
    goto AUTHORITY;
  }

  found = 0;
  gavesoa = 0;
  wild = qname->s;

  while (1) {
    cdb_findstart(&c);
    while ((rc = find(wild, wild != qname->s))) {
      if (rc == -1)
        return 0;
      found++;

      if (!memcmp(qtype, DNS_T_ANY, 2) && memcmp(type, DNS_T_CNAME, 2))
          continue;
      if (gavesoa && !memcmp(type, DNS_T_SOA, 2))
        continue;
      if (memcmp(type, qtype, 2) && memcmp(type, DNS_T_CNAME, 2))
        continue;

      if (!response_rstart(qname->s, type, ttl))
        return 0;
      if (!memcmp(type, DNS_T_NS, 2) || !memcmp(type, DNS_T_PTR, 2)) {
        if (!doname(&name))
          return 0;
      } else if (!memcmp(type, DNS_T_CNAME, 2)) {
        if (!doname(&name))
          return 0;
        if (memcmp(type, qtype, 2) && ++restarted < 16) {
          response_rfinish(RESPONSE_ANSWER);
          if (!dns_domain_copy(qname, name.s))
            return 0;
          goto ANSWER;
        }
      } else if (!memcmp(type, DNS_T_MX, 2)) {
        if (!dobytes(2))
          return 0;
        if (!doname(&name))
          return 0;
      } else if (!memcmp(type, DNS_T_SOA, 2)) {
        if (!doname(&name))
          return 0;
        if (!doname(&name))
          return 0;
        if (!dobytes(20))
          return 0;
        gavesoa++;
      } else if (!dobytes(dlen - dpos)) {
        return 0;
      }
      response_rfinish(RESPONSE_ANSWER);
    }

    if (found)
      break;
    if (wild == control)
      break;
    if (!*wild) /* impossible */
      break;

    if (wild != qname->s) {
      cdb_findstart(&c);
      if (find(wild, 0))
        break; /* RFC 1034 section 4.3.3 */
    }
    wild += *wild + 1;
  }

  if (found) {
    if (!memcmp(qtype, DNS_T_ANY, 2)) {
      if (!response_rstart(qname->s, DNS_T_HINFO, 86400))
        return 0;
      if (!response_addbytes("\7RFC8482\0", 9))
        return 0;
      response_rfinish(RESPONSE_ANSWER);
    }
    response_rcode(RCODE_NOERROR);
  } else {
    response_rcode(RCODE_NXDOMAIN);
  }

AUTHORITY:
  authority = response_length();

  if (authoritative && authority == answer) {
    cdb_findstart(&c);
    while ((rc = find(control, 0))) {
      if (rc == -1)
        return 0;
      if (!memcmp(type, DNS_T_SOA, 2)) {
        if (!response_rstart(control, DNS_T_SOA, ttl))
          return 0;
        if (!doname(&name))
          return 0;
        if (!doname(&name))
          return 0;
        if (!dobytes(20))
          return 0;
        response_rfinish(RESPONSE_AUTHORITY);
        break;
      }
    }
  } else if (!authoritative) { /* minimise responses */
    if (want(control, DNS_T_NS)) {
      cdb_findstart(&c);
      while ((rc = find(control, 0))) {
        if (rc == -1)
          return 0;
        if (!memcmp(type, DNS_T_NS, 2)) {
          if (!response_rstart(control, DNS_T_NS, ttl))
            return 0;
          if (!doname(&name))
            return 0;
          response_rfinish(RESPONSE_AUTHORITY);
        }
      }
    }
  }

ADDITIONAL:
  additional = response_length();

  while (answer < additional) {
    char rtype[2], rdlen[2];
    stralloc_zero(&name);

    if (!response_skipname(&answer))
      return 0;
    if (!response_copy(&answer, rtype, 2))
      return 0;
    if (answer += 6, !response_copy(&answer, rdlen, 2))
      return 0;

    if (!memcmp(rtype, DNS_T_NS, 2))
      if (!response_getname(&(size_t) { answer }, &name))
        return 0;
    if (!memcmp(rtype, DNS_T_MX, 2))
      if (!response_getname(&(size_t) { answer + 2 }, &name))
        return 0;
    if (!memcmp(rtype, DNS_T_SRV, 2))
      if (!response_getname(&(size_t) { answer + 6 }, &name))
        return 0;

    if (name.len > 0) {
      stralloc_lower(&name);
      if (want(name.s, DNS_T_A)) {
        cdb_findstart(&c);
        while ((rc = find(name.s, 0))) {
          if (rc == -1)
            return 0;
          if (!memcmp(type, DNS_T_A, 2)) {
            if (!response_rstart(name.s, DNS_T_A, ttl))
              return 0;
            if (!dobytes(4))
              return 0;
            response_rfinish(RESPONSE_ADDITIONAL);
          }
        }
      }
      if (want(name.s, DNS_T_AAAA)) {
        cdb_findstart(&c);
        while ((rc = find(name.s, 0))) {
          if (rc == -1)
            return 0;
          if (!memcmp(type, DNS_T_AAAA, 2)) {
            if (!response_rstart(name.s, DNS_T_AAAA, ttl))
              return 0;
            if (!dobytes(16))
              return 0;
            response_rfinish(RESPONSE_ADDITIONAL);
          }
        }
      }
    }
    answer += unpack_uint16_big(rdlen);
  }
  return 1;
}

void lookup(stralloc *r, size_t max, const void *ip, size_t iplen) {
  static stralloc qname;
  char qtype[2], qclass[2];

  if (!response_query(r, &qname, qtype, qclass)) {
    stralloc_zero(r);
    return;
  }

  if (!memcmp(qclass, DNS_C_IN, 2)) {
    response_authoritative(1);
  } else if (!memcmp(qclass, DNS_C_ANY, 2)) {
    response_authoritative(0);
  } else {
    response_rcode(RCODE_FORMERR);
    response_finish(max);
    return;
  }

  now = time(0);
  refresh("data.cdb");
  stralloc_lower(&qname);

  if (!locate(ip, iplen) || !respond(&qname, qtype))
    response_rcode(RCODE_SERVFAIL);
  response_finish(max);
}
