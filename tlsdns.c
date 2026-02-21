#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#include "pack.h"
#include "stralloc.h"

enum { streams = 256 };

static struct pollfd fd[streams + 16];
static size_t fdc = streams;

static char buffer[streams][65535 + 2];
static struct sockaddr_storage peer[streams];
static struct tls *ctx[streams], *tls;

static uint64_t born[streams];
static size_t head[streams];
static size_t tail[streams];

size_t attach(struct pollfd *fd, size_t fdlen, int type,
    const char *address, const char *port);
void lookup(stralloc *r, size_t max, const void *ip, size_t iplen);
void prepare(int fg, const char *user);

static size_t respond(size_t i) {
  stralloc r = {
    .s = buffer[i] + 2,
    .len = head[i] - 2,
    .size = sizeof *buffer - 2,
    .limit = -1
  };

  if (peer[i].ss_family == AF_INET)
    lookup(&r, -1, &((struct sockaddr_in *) (peer + i))->sin_addr, 4);
  else if (peer[i].ss_family == AF_INET6)
    lookup(&r, -1, &((struct sockaddr_in6 *) (peer + i))->sin6_addr, 16);
  else
    return 0;

  pack_uint16_big(buffer[i], r.len);
  head[i] = r.len + 2;
  return r.len;
}

static uint64_t utime(void) {
  struct timespec ts;
  uint64_t now = 0;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  now += (uint64_t) ts.tv_sec * 1000000;
  now += (uint64_t) ts.tv_nsec / 1000;
  return now;
}

static void drop(size_t i) {
  if (ctx[i]) {
    tls_close(ctx[i]);
    tls_free(ctx[i]);
    ctx[i] = NULL;
  }
  if (fd[i].fd >= 0) {
    close(fd[i].fd);
  }
  fd[i].events = 0;
  fd[i].fd = -1;
  born[i] = 0;
  head[i] = 0;
  tail[i] = 0;
}

static void new(size_t i) {
  struct sockaddr_storage sa;
  socklen_t salen = sizeof sa;
  size_t j, k;
  int client;

  if ((client = accept(fd[i].fd, (void *) &sa, &salen)) < 0)
    return;
  if (fcntl(client, F_SETFL, O_NONBLOCK) < 0) {
    close(client);
    return;
  }

  for (j = 0, k = 1; born[j] && k < streams; k++)
    if (born[k] < born[j])
      j = k;
  drop(j);

  if (tls_accept_socket(tls, &ctx[j], client) < 0) {
    close(client);
    return;
  }

  fd[j].events = POLLIN;
  fd[j].fd = client;
  born[j] = utime();
  peer[j] = sa;
}

static int stream(size_t i) {
  size_t size;
  ssize_t count;

  if (head[i] < 2) {
    count = tls_read(ctx[i], buffer[i] + head[i], 2 - head[i]);
    if (count == TLS_WANT_POLLIN)
      return POLLIN;
    if (count == TLS_WANT_POLLOUT)
      return POLLOUT;
    if (count <= 0)
      return 0;
    if (head[i] += count, head[i] < 2)
      return POLLIN;
  }

  if (!(size = unpack_uint16_big(buffer[i])))
    return 0;

  if (head[i] < size + 2) {
    count = tls_read(ctx[i], buffer[i] + head[i], size + 2 - head[i]);
    if (count == TLS_WANT_POLLIN)
      return POLLIN;
    if (count == TLS_WANT_POLLOUT)
      return POLLOUT;
    if (count <= 0)
      return 0;
    if (head[i] += count, head[i] < size + 2)
      return POLLIN;
    if (respond(i) == 0)
      return 0;
  }

  count = tls_write(ctx[i], buffer[i] + tail[i], head[i] - tail[i]);
  if (count == TLS_WANT_POLLIN)
    return POLLIN;
  if (count == TLS_WANT_POLLOUT)
    return POLLOUT;
  if (count <= 0)
    return 0;
  if (tail[i] += count, tail[i] < head[i])
    return POLLOUT;

  born[i] = utime();
  head[i] = 0;
  tail[i] = 0;
  return POLLIN;
}

static int usage(const char *progname) {
  fprintf(stderr, "\
Usage: %s [OPTIONS] CERTKEY ADDRESS...\n\
Options:\n\
  -d DIR        change directory to DIR before opening data.cdb\n\
  -f            run in the foreground instead of daemonizing\n\
  -u UID:GID    run with the specified numeric uid and gid\n\
  -u USERNAME   run with the uid and gid of user USERNAME\n\
", progname);
  return 64;
}

int main(int argc, char **argv) {
  struct tls_config *config;
  int fg = 0, option;
  char *user = 0;

  while ((option = getopt(argc, argv, ":d:fu:")) > 0)
    switch (option) {
      case 'd':
        if (chdir(optarg) < 0)
          err(1, "chdir");
        break;
      case 'f':
        fg = 1;
        break;
      case 'u':
        user = optarg;
        break;
      default:
        return usage(argv[0]);
    }

  if (argc <= optind + 1)
    return usage(argv[0]);

  if (!(config = tls_config_new()))
    err(1, "tls_config_new");
  if (tls_config_set_protocols(config, TLS_PROTOCOLS_DEFAULT) < 0)
    errx(1, "tls_config_set_protocols: %s", tls_config_error(config));
  if (tls_config_set_cert_file(config, argv[optind]) < 0)
    errx(1, "tls_config_set_cert_file: %s", tls_config_error(config));
  if (tls_config_set_key_file(config, argv[optind]) < 0)
    errx(1, "tls_config_set_key_file: %s", tls_config_error(config));
  if (!(tls = tls_server()))
    err(1, "tls_server");
  if (tls_configure(tls, config) < 0)
    errx(1, "tls_configure: %s", tls_error(tls));
  tls_config_free(config);

  for (int i = optind + 1; i < argc; i++)
    fdc = fdc + attach(fd + fdc, sizeof fd / sizeof *fd - fdc,
      SOCK_STREAM, argv[i], "853");

  prepare(fg, user);

  for (size_t i = 0; i < streams; i++)
    fd[i].fd = -1;

  signal(SIGPIPE, SIG_IGN);

  while (1) {
    if (poll(fd, fdc, -1) < 0) {
      if (errno == EINTR)
        continue;
      err(1, "poll");
    }

    for (size_t i = 0; i < streams; i++)
      if (fd[i].revents && !(fd[i].events = stream(i)))
        drop(i);

    for (size_t i = streams; i < fdc; i++)
      if (fd[i].revents)
        new(i);
  }
}
