#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cdb.h"
#include "make.h"
#include "pack.h"

#define CDB_HPLIST 1000

int cdb_make_start(struct cdb_make *c, const char *filename) {
  c->head = 0;
  c->split = 0;
  c->hash = 0;
  c->entries = 0;
  c->pos = sizeof c->final;
  c->file = filename ? fopen(filename, "w") : tmpfile();
  return c->file ? fseek(c->file, c->pos, SEEK_SET) : -1;
}

int cdb_make_add_begin(struct cdb_make *c, size_t keylen, size_t datalen) {
  char buffer[8];

  if (keylen > 0xffffffff || datalen > 0xffffffff)
    return errno = ENOMEM, -1;
  pack_uint32(buffer, keylen);
  pack_uint32(buffer + 4, datalen);
  return fwrite(buffer, 8, 1, c->file) == 1 ? 0 : -1;
}

static int posplus(struct cdb_make *c, uint32_t len) {
  uint32_t new = c->pos + len;
  if (new < len)
    return errno = ENOMEM, -1;
  c->pos = new;
  return 0;
}

int cdb_make_add_end(struct cdb_make *c, size_t keylen, size_t datalen,
    uint32_t h) {
  struct cdb_hplist *head = c->head;

  if (!head || head->num >= CDB_HPLIST) {
    head = malloc(sizeof *head);
    if (!head)
      return -1;
    head->num = 0;
    head->next = c->head;
    c->head = head;
  }
  head->hp[head->num].h = h;
  head->hp[head->num].p = c->pos;
  head->num++;
  c->entries++;

  if (posplus(c, 8) < 0)
    return -1;
  if (posplus(c, keylen) < 0)
    return -1;
  if (posplus(c, datalen) < 0)
    return -1;
  return 0;
}

int cdb_make_add(struct cdb_make *c, const char *key, size_t keylen,
    const char *data, size_t datalen) {
  if (cdb_make_add_begin(c, keylen, datalen) < 0)
    return -1;
  if (fwrite(key, keylen, 1, c->file) != 1)
    return -1;
  if (fwrite(data, datalen, 1, c->file) != 1)
    return -1;
  return cdb_make_add_end(c, keylen, datalen, cdb_hash(key, keylen));
}

int cdb_make_finish(struct cdb_make *c) {
  uint32_t memsize, u;
  char buffer[8];

  for (int i = 0; i < 256; i++)
    c->count[i] = 0;

  for (struct cdb_hplist *x = c->head; x; x = x->next)
    for (int i = 0; i < x->num; i++)
      c->count[255 & x->hp[i].h]++;

  memsize = 1;
  for (int i = 0; i < 256; i++) {
    u = c->count[i] * 2;
    if (u > memsize)
      memsize = u;
  }

  memsize += c->entries; /* no overflow possible up to now */
  if (memsize > 0xffffffff / sizeof *c->split)
    return errno = ENOMEM, -1;

  c->split = malloc(memsize * sizeof *c->split);
  if (!c->split)
    return -1;
  c->hash = c->split + c->entries;

  for (int i = u = 0; i < 256; i++) {
    u += c->count[i]; /* bounded by entries, so no overflow */
    c->start[i] = u;
  }

  for (struct cdb_hplist *x = c->head; x; x = x->next)
    for (int i = 0; i < x->num; i++)
      c->split[--c->start[255 & x->hp[i].h]] = x->hp[i];

  for (int i = 0; i < 256; i++) {
    struct cdb_hp *hp = c->split + c->start[i];
    uint32_t count = c->count[i];
    uint32_t len = count << 1; /* no overflow possible */

    pack_uint32(c->final + 8 * i, c->pos);
    pack_uint32(c->final + 8 * i + 4, len);

    for (u = 0; u < len; u++)
      c->hash[u].h = c->hash[u].p = 0;

    for (u = 0; u < count; u++) {
      uint32_t where = (hp->h >> 8) % len;
      while (c->hash[where].p)
        if (++where == len)
          where = 0;
      c->hash[where] = *hp++;
    }

    for (u = 0; u < len; u++) {
      pack_uint32(buffer, c->hash[u].h);
      pack_uint32(buffer + 4, c->hash[u].p);
      if (fwrite(buffer, 8, 1, c->file) != 1)
        return -1;
      if (posplus(c, 8) < 0)
        return -1;
    }
  }

  if (fseek(c->file, 0, SEEK_SET) < 0)
    return -1;
  if (fwrite(c->final, sizeof c->final, 1, c->file) != 1)
    return -1;
  if (fflush(c->file) < 0 || fsync(fileno(c->file)) < 0)
    return -1;
  return fclose(c->file);
}
