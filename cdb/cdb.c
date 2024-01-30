#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cdb.h"
#include "pack.h"

void cdb_free(struct cdb *c) {
  if (c->map) {
    munmap(c->map, c->size);
    c->map = 0;
  }
}

void cdb_findstart(struct cdb *c) {
  c->loop = 0;
}

void cdb_init(struct cdb *c, int fd) {
  struct stat st;
  char *map;

  cdb_free(c);
  cdb_findstart(c);
  c->fd = fd;

  if (fstat(fd, &st) == 0 && st.st_size <= 0xffffffff) {
    map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map != MAP_FAILED) {
      c->size = st.st_size;
      c->map = map;
    }
  }
}

int cdb_read(struct cdb *c, char *out, size_t len, uint32_t pos) {
  if (c->map) {
    if (pos > c->size || c->size - pos < len)
      return errno = EPROTO, -1;
    memcpy(out, c->map + pos, len);
    return 0;
  }
  if (lseek(c->fd, pos, SEEK_SET) < 0)
    return -1;
  while (len > 0) {
    ssize_t count = read(c->fd, out, len);
    if (count < 0 && errno == EINTR)
      continue;
    if (count == 0)
      errno = EPROTO;
    if (count <= 0)
      return -1;
    out += count;
    len -= count;
  }
  return 0;
}

static int match(struct cdb *c, const char *key, size_t len, uint32_t pos) {
  char buffer[256];
  size_t n;

  while (len > 0) {
    n = sizeof buffer < len ? sizeof buffer : len;
    if (cdb_read(c, buffer, n, pos) < 0)
      return -1;
    if (memcmp(buffer, key, n))
      return 0;
    pos += n;
    key += n;
    len -= n;
  }
  return 1;
}

int cdb_findnext(struct cdb *c, const char *key, size_t len) {
  char buffer[8];
  uint32_t pos, u;

  if (!c->loop) {
    u = cdb_hash(key, len);
    if (cdb_read(c, buffer, 8, (u << 3) & 2047) < 0)
      return -1;
    c->hslots = unpack_uint32(buffer + 4);
    if (c->hslots == 0)
      return 0;
    c->hpos = unpack_uint32(buffer);
    c->khash = u;
    c->kpos = c->hpos + ((u >> 8) % c->hslots << 3);
  }

  while (c->loop < c->hslots) {
    if (cdb_read(c, buffer, 8, c->kpos) == -1)
      return -1;
    pos = unpack_uint32(buffer + 4);
    if (pos == 0)
      return 0;
    c->loop += 1;
    c->kpos += 8;
    if (c->kpos == c->hpos + (c->hslots << 3))
      c->kpos = c->hpos;
    if (unpack_uint32(buffer) == c->khash) {
      if (cdb_read(c, buffer, 8, pos) < 0)
        return -1;
      if (unpack_uint32(buffer) == len)
        switch(match(c, key, len, pos + 8)) {
          case -1:
            return -1;
          case 1:
            c->dlen = unpack_uint32(buffer + 4);
            c->dpos = pos + 8 + len;
            return 1;
        }
    }
  }

  return 0;
}

int cdb_find(struct cdb *c, const char *key, size_t len) {
  cdb_findstart(c);
  return cdb_findnext(c, key, len);
}
