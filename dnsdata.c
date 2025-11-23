#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cdb/make.h"
#include "dns.h"
#include "pack.h"
#include "scan.h"
#include "stralloc.h"

static struct cdb_make cdb;
static stralloc f[15], key, rr;

static stralloc soa_rname;
static uint32_t soa_serial;

const uint32_t soa_refresh = 16384;
const uint32_t soa_retry = 2048;
const uint32_t soa_expire = 1048576;

static uint32_t ttl_nameserver = 259200;
static uint32_t ttl_positive = 86400;
static uint32_t ttl_negative = 2560;

static char *line;
static size_t size;
static size_t failc;
static size_t linec;

static int fail(const char *fmt, ...) {
  va_list args;

  fprintf(stderr, "%zu: ", linec);
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  fputc('\n', stderr);
  return 0;
}

static int parse_loc(char loc[2], const stralloc *in) {
  if (in->len > 2)
    return fail("Invalid location code: %s", in->s);
  loc[0] = in->len > 0 ? in->s[0] : 0;
  loc[1] = in->len > 1 ? in->s[1] : 0;
  return 1;
}

static int parse_name(stralloc *out, const stralloc *in) {
  if (dns_domain_fromdot(out, in->s, in->len))
    return 1;
  if (errno != EPROTO)
    err(1, "stralloc");
  return fail("Invalid domain name: %s", in->s);
}

static int parse_mail(stralloc *out, const stralloc *in) {
  char *at = memchr(in->s, '@', in->len);
  static stralloc domain;

  if (!at)
    return parse_name(out, in);
  if (at > in->s + 63)
    return fail("Email local part is too long: %s", in->s);

  if (!dns_domain_fromdot(&domain, at + 1, in->s + in->len - at - 1)) {
    if (errno != EPROTO)
      err(1, "stralloc");
    return fail("Invalid email domain: %s", in->s);
  }

  if (!stralloc_copyb(out, &(char) { at - in->s }, 1))
    err(1, "stralloc");
  if (!stralloc_catb(out, in->s, at - in->s))
    err(1, "stralloc");
  if (!stralloc_catb(out, domain.s, domain.len))
    err(1, "stralloc");
  return 1;
}

static void parse_text(stralloc *sa) {
  size_t i = 0, j = 0;
  uint8_t byte;

  while (i < sa->len) {
    byte = sa->s[i++];
    if (byte == '\\') {
      if (i >= sa->len)
        break;
      byte = sa->s[i++];

      if (byte >= '0' && byte <= '7') {
        byte = byte - '0';
        if (i < sa->len && sa->s[i] >= '0' && sa->s[i] <= '7') {
          byte = (byte << 3) + sa->s[i++] - '0';
          if (i < sa->len && sa->s[i] >= '0' && sa->s[i] <= '7' && byte < 32)
            byte = (byte << 3) + sa->s[i++] - '0';
        }
      }
    }
    sa->s[j++] = byte;
  }
  sa->len = j;
}

static int parse_ttl(uint32_t *ttl, const stralloc *in, uint32_t def) {
  if (in->len == 0)
    *ttl = def;
  if (in->len && scan_uint32(in->s, ttl) != in->len)
    return fail("Invalid TTL: %s", in->s);
  return 1;
}

static int parse_ttd(uint64_t *ttd, const stralloc *in) {
  if (scan_uint64(in->s, ttd) == in->len)
    return 1;
  if (in->len > 1 && scan_uint64(in->s + 1, ttd) == in->len - 1) {
    if (*in->s == '-')
      *ttd += 0x8000000000000000;
    if (*in->s == '+' || *in->s == '-')
      return 1;
  }
  return fail("Invalid TTD: %s", in->s);
}

static int parse_uint16(uint16_t *out, const stralloc *in, uint16_t def) {
  if (in->len == 0)
    *out = def;
  if (in->len && scan_uint16(in->s, out) != in->len)
    return fail("Invalid 16-bit value: %s", in->s);
  return 1;
}

static int parse_uint32(uint32_t *out, const stralloc *in, uint32_t def) {
  if (in->len == 0)
    *out = def;
  if (in->len && scan_uint32(in->s, out) != in->len)
    return fail("Invalid 32-bit value: %s", in->s);
  return 1;
}

static void rr_add(const char *data, unsigned int len) {
  if (!stralloc_catb(&rr, data, len))
    err(1, "stralloc");
}

static void rr_addname(const char *name) {
  rr_add(name, dns_domain_length(name));
}

static void rr_start(const char type[2], uint32_t ttl, uint64_t ttd,
    const char loc[2]) {
  char buffer[8];

  if (!stralloc_copyb(&rr, type, 2))
    err(1, "stralloc");
  if (!memcmp(loc, "\0\0", 2)) {
    rr_add("=", 1);
  } else {
    rr_add(">", 1);
    rr_add(loc, 2);
  }
  pack_uint32_big(buffer, ttl);
  rr_add(buffer, 4);
  pack_uint64_big(buffer, ttd);
  rr_add(buffer, 8);
}

static void rr_finish(const char *owner) {
  if (owner[0] == 1 && owner[1] == '*') {
    owner += 2;
    rr.s[2] -= 19;
  }
  if (!stralloc_copyb(&key, owner, dns_domain_length(owner)))
    err(1, "stralloc");
  stralloc_lower(&key);
  if (cdb_make_add(&cdb, key.s, key.len, rr.s, rr.len) < 0)
    err(1, "cdb");
}

static int append(void) {
  static stralloc d1, d2, d3;
  char bytes[20], loc[2];
  uint16_t u16;
  uint32_t ttl, u32;
  uint64_t ttd;
  size_t len;

  switch(*line) {
    case '%':
      if (!parse_loc(loc, &f[0]))
        return 0;
      if (f[1].len == 1 && *f[1].s == '4') {
        if (scan_ip4_prefix(f[2].s, bytes, &len, 4) == f[2].len) {
          if (!stralloc_copyb(&key, "\0%", 2))
            err(1, "stralloc");
          if (!stralloc_catb(&key, bytes, len))
            err(1, "stralloc");
          if (cdb_make_add(&cdb, key.s, key.len, loc, 2) < 0)
            err(1, "cdb");
          return 1;
        }
      }
      if (f[1].len == 1 && *f[1].s == '6') {
        if (scan_ip6_prefix(f[2].s, bytes, &len, 16) == f[2].len) {
          if (!stralloc_copyb(&key, "\0&", 2))
            err(1, "stralloc");
          if (!stralloc_catb(&key, bytes, len))
            err(1, "stralloc");
          if (cdb_make_add(&cdb, key.s, key.len, loc, 2) < 0)
            err(1, "cdb");
          return 1;
        }
      }
      return fail("Invalid address prefix: %s:%s", f[1].s, f[2].s);

    case '!':
      if (!parse_mail(&soa_rname, &f[0]))
        return 0;
      if (!parse_uint32(&ttl_nameserver, &f[1], ttl_nameserver))
        return 0;
      if (!parse_uint32(&ttl_positive, &f[2], ttl_positive))
        return 0;
      if (!parse_uint32(&ttl_negative, &f[3], ttl_negative))
        return 0;
      if (!parse_uint32(&soa_serial, &f[4], soa_serial))
        return 0;
      return 1;

    case 'Z':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_name(&d2, &f[1]))
        return 0;
      if (!parse_mail(&d3, &f[2]))
        return 0;
      if (!parse_ttl(&ttl, &f[8], ttl_negative))
        return 0;
      if (!parse_ttd(&ttd, &f[9]))
        return 0;
      if (!parse_loc(loc, &f[10]))
        return 0;

      if (!parse_uint32(&u32, &f[3], soa_serial))
        return 0;
      pack_uint32_big(bytes, u32);

      if (!parse_uint32(&u32, &f[4], soa_refresh))
        return 0;
      pack_uint32_big(bytes + 4, u32);

      if (!parse_uint32(&u32, &f[5], soa_retry))
        return 0;
      pack_uint32_big(bytes + 8, u32);

      if (!parse_uint32(&u32, &f[6], soa_expire))
        return 0;
      pack_uint32_big(bytes + 12, u32);

      if (!parse_uint32(&u32, &f[7], ttl))
        return 0;
      pack_uint32_big(bytes + 16, u32);

      rr_start(DNS_T_SOA, ttl, ttd, loc);
      rr_addname(d2.s);
      rr_addname(d3.s);
      rr_add(bytes, 20);
      rr_finish(d1.s);
      return 1;

    case '.':
    case '&':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_name(&d2, &f[1]))
        return 0;
      if (!parse_ttl(&ttl, &f[2], ttl_nameserver))
        return 0;
      if (!parse_ttd(&ttd, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;

      if (*line == '.') {
        rr_start(DNS_T_SOA, ttl ? ttl_negative : 0, ttd, loc);
        rr_addname(d2.s);
        if (soa_rname.len) {
          rr_addname(soa_rname.s);
        } else {
          rr_add("\12hostmaster", 11);
          rr_addname(d1.s);
        }
        pack_uint32_big(bytes, soa_serial);
        pack_uint32_big(bytes + 4, soa_refresh);
        pack_uint32_big(bytes + 8, soa_retry);
        pack_uint32_big(bytes + 12, soa_expire);
        pack_uint32_big(bytes + 16, ttl_negative);
        rr_add(bytes, 20);
        rr_finish(d1.s);
      }

      rr_start(DNS_T_NS, ttl, ttd, loc);
      rr_addname(d2.s);
      rr_finish(d1.s);
      return 1;

    case '+':
    case '=':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_ttl(&ttl, &f[2], ttl_positive))
        return 0;
      if (!parse_ttd(&ttd, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;

      len = scan_ip4(f[1].s, bytes);
      if (len && len == f[1].len) {
        rr_start(DNS_T_A, ttl, ttd, loc);
        rr_add(bytes, 4);
        rr_finish(d1.s);
        if (*line == '=') {
          if (!dns_name4_domain(&d2, bytes))
            err(1, "stralloc");
          rr_start(DNS_T_PTR, ttl, ttd, loc);
          rr_addname(d1.s);
          rr_finish(d2.s);
        }
        return 1;
      }

      len = scan_ip6(f[1].s, bytes);
      if (len && len == f[1].len) {
        rr_start(DNS_T_AAAA, ttl, ttd, loc);
        rr_add(bytes, 16);
        rr_finish(d1.s);
        if (*line == '=') {
          if (!dns_name6_domain(&d2, bytes))
            err(1, "stralloc");
          rr_start(DNS_T_PTR, ttl, ttd, loc);
          rr_addname(d1.s);
          rr_finish(d2.s);
        }
        return 1;
      }

      if (f[1].len)
        return fail("Invalid IP address: %s", f[1].s);
      return fail("Missing IP address");

    case '@':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_name(&d2, &f[1]))
        return 0;
      if (!parse_uint16(&u16, &f[2], 0))
        return 0;
      if (!parse_ttl(&ttl, &f[3], ttl_positive))
        return 0;
      if (!parse_ttd(&ttd, &f[4]))
        return 0;
      if (!parse_loc(loc, &f[5]))
        return 0;

      rr_start(DNS_T_MX, ttl, ttd, loc);
      pack_uint16_big(bytes, u16);
      rr_add(bytes, 2);
      rr_addname(d2.s);
      rr_finish(d1.s);
      return 1;

    case 'S':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_name(&d2, &f[1]))
        return 0;

      if (!parse_uint16(&u16, &f[3], 0))
        return 0;
      pack_uint16_big(bytes, u16);

      if (!parse_uint16(&u16, &f[4], 0))
        return 0;
      pack_uint16_big(bytes + 2, u16);

      if (!parse_uint16(&u16, &f[2], 0))
        return 0;
      pack_uint16_big(bytes + 4, u16);

      if (!parse_ttl(&ttl, &f[5], ttl_positive))
        return 0;
      if (!parse_ttd(&ttd, &f[6]))
        return 0;
      if (!parse_loc(loc, &f[7]))
        return 0;

      rr_start(DNS_T_SRV, ttl, ttd, loc);
      rr_add(bytes, 6);
      rr_addname(d2.s);
      rr_finish(d1.s);
      return 1;

    case 'C':
    case '^':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_name(&d2, &f[1]))
        return 0;
      if (!parse_ttl(&ttl, &f[2], ttl_positive))
        return 0;
      if (!parse_ttd(&ttd, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;

      if (*line == 'C')
        rr_start(DNS_T_CNAME, ttl, ttd, loc);
      else
        rr_start(DNS_T_PTR, ttl, ttd, loc);
      rr_addname(d2.s);
      rr_finish(d1.s);
      return 1;

    case '\'':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_ttl(&ttl, &f[2], ttl_positive))
        return 0;
      if (!parse_ttd(&ttd, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;

      parse_text(&f[1]);
      rr_start(DNS_T_TXT, ttl, ttd, loc);
      for (size_t i = 0, n; i < f[1].len; i += n) {
        n = f[1].len - i;
        if (n > 255)
          n = 255;
        rr_add(&(char) { n }, 1);
        rr_add(f[1].s + i, n);
      }
      rr_finish(d1.s);
      return 1;

    case ':':
      if (!parse_name(&d1, &f[0]))
        return 0;

      if (!parse_uint16(&u16, &f[1], 0))
        return 0;
      pack_uint16_big(bytes, u16);

      if (!parse_ttl(&ttl, &f[3], ttl_positive))
        return 0;
      if (!parse_ttd(&ttd, &f[4]))
        return 0;
      if (!parse_loc(loc, &f[5]))
        return 0;

      if (!memcmp(bytes, "\0\0", 2))
        return fail("Type 0 is prohibited");
      if (!memcmp(bytes, DNS_T_NS, 2))
        return fail("Type NS is prohibited");
      if (!memcmp(bytes, DNS_T_CNAME, 2))
        return fail("Type CNAME is prohibited");
      if (!memcmp(bytes, DNS_T_SOA, 2))
        return fail("Type SOA is prohibited");
      if (!memcmp(bytes, DNS_T_PTR, 2))
        return fail("Type PTR is prohibited");
      if (!memcmp(bytes, DNS_T_MX, 2))
        return fail("Type MX is prohibited");
      if (!memcmp(bytes, DNS_T_DNAME, 2))
        return fail("Type DNAME is prohibited");
      if (!memcmp(bytes, DNS_T_IXFR, 2))
        return fail("Type IXFR is prohibited");
      if (!memcmp(bytes, DNS_T_AXFR, 2))
        return fail("Type AXFR is prohibited");

      parse_text(&f[2]);
      rr_start(bytes, ttl, ttd, loc);
      rr_add(f[2].s, f[2].len);
      rr_finish(d1.s);
      return 1;

    case '-':
      if (!parse_name(&d1, &f[0]))
        return 0;
      if (!parse_ttd(&ttd, &f[1]))
        return 0;
      if (!parse_loc(loc, &f[2]))
        return 0;

      rr_start(DNS_T_ANY, 0, ttd, loc);
      rr_finish(d1.s);
      return 1;
  }
  return fail("Unrecognized leading character: %c", *line);
}

static int usage(const char *progname) {
  fprintf(stderr, "\
Usage: %s [OPTIONS] < DATAFILE\n\
Options:\n\
  -d DIR    change directory to DIR before replacing data.cdb\n\
  -f        replace data.cdb even if some lines have errors\n\
  -n        validate input lines without replacing data.cdb\n\
  -t FS     use FS instead of ':' as field separator character\n\
", progname);
  return 64;
}

int main(int argc, char **argv) {
  int dummy = 0, force = 0, option;
  char fs = ':';
  struct stat st;

  while ((option = getopt(argc, argv, ":d:fnt:")) > 0)
    switch (option) {
      case 'd':
        if (chdir(optarg) < 0)
          err(1, "chdir");
        break;
      case 'f':
        force = 1;
        break;
      case 'n':
        dummy = 1;
        break;
      case 't':
       if (strlen(optarg) != 1 || memchr("\n\\", *optarg, 2))
          errx(1, "Invalid field separator");
        fs = *optarg;
        break;
      default:
        return usage(argv[0]);
    }

  if (argc > optind)
    return usage(argv[0]);
  if (isatty(0))
    return usage(argv[0]);

  if (fstat(0, &st) >= 0 && st.st_mode & S_IFREG)
    soa_serial = st.st_mtime;
  else
    soa_serial = time(0);

  if (cdb_make_start(&cdb, dummy ? 0 : "data.tmp") < 0)
    err(1, "cdb");

  while (linec++, getline(&line, &size, stdin) >= 0) {
    for (size_t i = strlen(line); i-- > 0; line[i] = 0)
      if (line[i] != '\t' && line[i] != '\n' && line[i] != ' ')
        break;
    if (line[0] == 0 || line[0] == '#')
      continue;

    for (size_t j = 0; j < sizeof f / sizeof *f; j++)
      stralloc_zero(&f[j]);

    for (size_t i = 1, j = 0; line[i] && j < sizeof f / sizeof *f; i++) {
      if (line[i] == '\\' && line[i + 1] && line[i + 1] != '\n') {
        if (line[i + 1] == fs && !stralloc_catb(&f[j], &fs, 1))
          err(1, "stralloc");
        if (line[i + 1] != fs && !stralloc_catb(&f[j], line + i, 2))
          err(1, "stralloc");
        i += 1;
      } else {
        if (line[i] != fs && !stralloc_catb(&f[j], line + i, 1))
          err(1, "stralloc");
        j += line[i] == fs;
      }
    }

    for (size_t j = 0; j < sizeof f / sizeof *f; j++)
      if (!stralloc_guard(&f[j]))
        err(1, "stralloc");
    if (!append())
      failc++;
  }

  if (cdb_make_finish(&cdb) < 0)
    err(1, "cdb");

  if (dummy) {
    printf("Read %zu lines with %zu errors\n", linec - 1, failc);
    printf("Wrote %u entries in %u bytes\n", cdb.entries, cdb.pos);
  } else if (failc && !force) {
    if (unlink("data.tmp") < 0)
      err(1, "unlink");
  } else {
    if (rename("data.tmp", "data.cdb") < 0)
      err(1, "rename");
  }
  return failc ? 2 : 0;
}
