#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "pack.h"
#include "stralloc.h"

enum { streams = 256 };

static struct pollfd fd[streams + 16];
static size_t fdc = streams;

static char buffer[streams][65535 + 2];
static struct sockaddr_storage peer[streams];

static uint64_t born[streams];
static size_t head[streams];
static size_t tail[streams];

void lookup(stralloc *r, size_t max, const void *ip, size_t iplen);

void attach(const char *address, const char *port) {
  struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *info, *list;
  int status = getaddrinfo(address, port, &hints, &list);

  if (status != 0 || list == 0)
    errx(1, "getaddrinfo %s: %s", address, gai_strerror(status));

  for (info = list; info; info = info->ai_next, fdc++) {
    if (fdc >= sizeof fd / sizeof *fd)
      errx(1, "Too many listening addresses");

    fd[fdc].fd = socket(info->ai_family, info->ai_socktype, 0);
    if (fd[fdc].fd < 0)
      err(1, "socket");
    if (fcntl(fd[fdc].fd, F_SETFL, O_NONBLOCK) < 0)
      err(1, "fcntl F_SETFL O_NONBLOCK");

    setsockopt(fd[fdc].fd, SOL_SOCKET, SO_REUSEADDR,
      &(int) { 1 }, sizeof(int));
#ifdef SO_REUSEPORT_LB
    setsockopt(fd[fdc].fd, SOL_SOCKET, SO_REUSEPORT_LB,
      &(int) { 1 }, sizeof(int));
#else
    setsockopt(fd[fdc].fd, SOL_SOCKET, SO_REUSEPORT,
      &(int) { 1 }, sizeof(int));
#endif

    if (bind(fd[fdc].fd, info->ai_addr, info->ai_addrlen) < 0)
      err(1, "bind");
    if (listen(fd[fdc].fd, SOMAXCONN) < 0)
      err(1, "listen");
    fd[fdc].events = POLLIN;
  }
  freeaddrinfo(list);
}

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
  if (fd[i].fd >= 0)
    close(fd[i].fd);
  fd[i].fd = -1;
  fd[i].events = 0;
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

  for (j = 0, k = 1; k < streams; k++)
    if (born[k] < born[j])
      j = k;
  if (fd[j].fd >= 0)
    close(fd[j].fd);

  fd[j].fd = client;
  fd[j].events = POLLIN;
  peer[j] = sa;
  born[j] = utime();
  head[j] = 0;
  tail[j] = 0;
}

static int stream(size_t i) {
  size_t size;
  ssize_t count;

  if (head[i] < 2) {
    count = read(fd[i].fd, buffer[i], 2 - head[i]);
    if (count < 0)
      if (errno == EINTR || errno == EAGAIN)
        return 1;
    if (count <= 0)
      return 0;
    head[i] += count;
  }

  if (head[i] >= 2) {
    size = unpack_uint16_big(buffer[i]);
    if (size == 0)
      return 0;

    if (head[i] < size + 2) {
      count = read(fd[i].fd, buffer[i] + head[i], size + 2 - head[i]);
      if (count < 0)
        if (errno == EINTR || errno == EAGAIN)
          return 1;
      if (count <= 0)
        return 0;
      head[i] += count;

      if (head[i] == size + 2) {
        size = respond(i);
        if (size == 0)
          return 0;
        fd[i].events = POLLOUT;
      }
    }

    if (head[i] == size + 2) {
      count = write(fd[i].fd, buffer[i] + tail[i], head[i] - tail[i]);
      if (count < 0)
        if (errno == EINTR || errno == EAGAIN)
          return 1;
      if (count <= 0)
        return 0;
      tail[i] += count;

      if (head[i] <= tail[i]) {
        fd[i].events = POLLIN;
        born[i] = utime();
        head[i] = 0;
        tail[i] = 0;
      }
    }
  }

  return 1;
}

void serve() {
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
      if (fd[i].revents && !stream(i))
        drop(i);

    for (size_t i = streams; i < fdc; i++)
      if (fd[i].revents)
        new(i);
  }
}
