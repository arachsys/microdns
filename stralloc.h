#ifndef STRALLOC_H
#define STRALLOC_H

#include <stdlib.h>
#include <string.h>

typedef struct stralloc {
  char *s;
  size_t len;
  size_t size;
  size_t limit;
} stralloc;

static inline void stralloc_free(stralloc *sa) {
  if (sa->limit + 1) {
    free(sa->s);
    sa->s = 0;
    sa->size = 0;
  }
  sa->len = 0;
}

static inline int stralloc_ready(stralloc *sa, size_t n) {
  if (sa->limit + 1 == 0)
    return n <= sa->size;
  if (sa->limit && sa->limit < n)
    return 0;
  if (sa->size && sa->size < n)
    n += 30 + (n >> 3);
  if (sa->limit && sa->limit < n)
    n = sa->limit;
  if (sa->size < n) {
    char *new = realloc(sa->s, n);
    if (!new)
      return 0;
    sa->s = new;
    sa->size = n;
  }
  return 1;
}

static inline int stralloc_copyb(stralloc *sa, const void *s, size_t n) {
  if (!stralloc_ready(sa, n))
    return 0;
  if (n > 0)
    memcpy(sa->s, s, n);
  sa->len = n;
  return 1;
}

static inline int stralloc_copys(stralloc *sa, const char *s) {
  return stralloc_copyb(sa, s, strlen(s));
}

static inline int stralloc_catb(stralloc *sa, const void *s, size_t n) {
  if (!sa->s)
    return stralloc_copyb(sa, s, n);
  if (!stralloc_ready(sa, sa->len + n))
    return 0;
  if (n > 0)
    memcpy(sa->s + sa->len, s, n);
  sa->len += n;
  return 1;
}

static inline int stralloc_cats(stralloc *sa, const char *s) {
  return stralloc_catb(sa, s, strlen(s));
}

static inline int stralloc_guard(stralloc *sa) {
  if (!stralloc_ready(sa, sa->len + 1))
    return 0;
  sa->s[sa->len] = 0;
  return 1;
}

static inline void stralloc_lower(stralloc *sa) {
  for (size_t i = 0; i < sa->len; i++)
    if (sa->s[i] >= 'A' && sa->s[i] <= 'Z')
      sa->s[i] += 'a' - 'A';
}

static inline void stralloc_zero(stralloc *sa) {
  sa->len = 0;
}

#endif
