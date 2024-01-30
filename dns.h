#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include "stralloc.h"

#define DNS_C_IN "\0\1"
#define DNS_C_ANY "\0\377"

#define DNS_T_A "\0\1"
#define DNS_T_NS "\0\2"
#define DNS_T_CNAME "\0\5"
#define DNS_T_SOA "\0\6"
#define DNS_T_PTR "\0\14"
#define DNS_T_HINFO "\0\15"
#define DNS_T_MX "\0\17"
#define DNS_T_TXT "\0\20"
#define DNS_T_AAAA "\0\34"
#define DNS_T_SRV "\0\41"
#define DNS_T_DNAME "\0\47"
#define DNS_T_IXFR "\0\373"
#define DNS_T_AXFR "\0\374"
#define DNS_T_ANY "\0\377"

size_t dns_domain_length(const char *dn);
int dns_domain_copy(stralloc *out, const char *in);
int dns_domain_equal(const char *dn1, const char *dn2);
int dns_domain_fromdot(stralloc *out, const char *in, size_t n);

int dns_name4_domain(stralloc *out, const char ip[4]);
int dns_name6_domain(stralloc *out, const char ip[16]);

int dns_packet_copy(size_t *pos, char *out, size_t len,
  const char *in, size_t size);
int dns_packet_getname(size_t *pos, stralloc *out,
  const char *in, size_t size);
int dns_packet_skipname(size_t *pos, const char *in, size_t size);

#endif
