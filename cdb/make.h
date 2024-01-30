#ifndef CDB_MAKE_H
#define CDB_MAKE_H

#include <stdint.h>
#include <stdio.h>

#define CDB_HPLIST 1000

struct cdb_hp {
  uint32_t h, p;
};

struct cdb_hplist {
  struct cdb_hp hp[CDB_HPLIST];
  struct cdb_hplist *next;
  int num;
};

struct cdb_make {
  char final[2048];
  uint32_t count[256];
  uint32_t start[256];
  struct cdb_hplist *head;
  struct cdb_hp *split; /* includes space for hash */
  struct cdb_hp *hash;
  uint32_t entries;
  uint32_t pos;
  FILE *file;
};

int cdb_make_start(struct cdb_make *c, const char *filename);
int cdb_make_add_begin(struct cdb_make *c, size_t keylen, size_t datalen);
int cdb_make_add_end(struct cdb_make *c, size_t keylen, size_t datalen,
  uint32_t h);
int cdb_make_add(struct cdb_make *c, const char *key, size_t keylen,
  const char *data, size_t datalen);
int cdb_make_finish(struct cdb_make *c);

#endif
