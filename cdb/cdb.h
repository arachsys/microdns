#ifndef CDB_H
#define CDB_H

#include <stddef.h>
#include <stdint.h>

struct cdb {
  int fd;
  char *map; /* 0 if no map is available */
  uint32_t size; /* initialized if map is nonzero */
  uint32_t loop; /* number of hash slots searched under this key */
  uint32_t khash; /* initialized if loop is nonzero */
  uint32_t kpos; /* initialized if loop is nonzero */
  uint32_t hpos; /* initialized if loop is nonzero */
  uint32_t hslots; /* initialized if loop is nonzero */
  uint32_t dpos; /* initialized if cdb_findnext() returns 1 */
  uint32_t dlen; /* initialized if cdb_findnext() returns 1 */
};

static inline uint32_t cdb_datapos(struct cdb *c) {
  return c->dpos;
}

static inline uint32_t cdb_datalen(struct cdb *c) {
  return c->dlen;
}

static inline uint32_t cdb_hashadd(uint32_t h, uint8_t c) {
  h += h << 5;
  return h ^ c;
}

static inline uint32_t cdb_hash(const char *in, size_t len) {
  uint32_t h = 5381;
  while (len) {
    h = cdb_hashadd(h, *in++);
    len--;
  }
  return h;
}

void cdb_free(struct cdb *c);
void cdb_init(struct cdb *c, int fd);

int cdb_read(struct cdb *c, char *out, size_t len, uint32_t pos);

void cdb_findstart(struct cdb *c);
int cdb_findnext(struct cdb *c, const char *key, size_t len);
int cdb_find(struct cdb *c, const char *key, size_t len);

#endif
