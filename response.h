#ifndef RESPONSE_H
#define RESPONSE_H

#include <stddef.h>
#include <stdint.h>
#include "stralloc.h"

#define RESPONSE_QUESTION 4
#define RESPONSE_ANSWER 6
#define RESPONSE_AUTHORITY 8
#define RESPONSE_ADDITIONAL 10

#define RCODE_NOERROR 0
#define RCODE_FORMERR 1
#define RCODE_SERVFAIL 2
#define RCODE_NXDOMAIN 3
#define RCODE_NOTIMPL 4
#define RCODE_REFUSED 5

int response_addbytes(const char *buf, unsigned int len);
int response_addshort(uint16_t u);
int response_addlong(uint32_t u);
int response_addname(const char *d);

size_t response_length(void);
int response_copy(size_t *pos, char *out, size_t len);
int response_getname(size_t *pos, stralloc *d);
int response_skipname(size_t *pos);

int response_query(stralloc *r, stralloc *qname, char qtype[2],
  char qclass[2]);
void response_authoritative(int flag);
void response_rcode(uint8_t rcode);
int response_rstart(const char *d, const char type[2], uint32_t ttl);
void response_rfinish(size_t section);
void response_finish(size_t maxlen);

#endif
