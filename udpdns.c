#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <sys/socket.h>

#include "stralloc.h"

static struct pollfd fd[16];
static size_t fdc;

static char buffer[65535];
static stralloc r = {
  .s = buffer,
  .size = sizeof buffer,
  .limit = -1
};

void lookup(stralloc *r, size_t max, const void *ip, size_t iplen);

void attach(const char *address, const char *port) {
  struct addrinfo hints = { .ai_socktype = SOCK_DGRAM }, *info, *list;
  int one = 1, status = getaddrinfo(address, port, &hints, &list);

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

    setsockopt(fd[fdc].fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#if defined SO_REUSEPORT_LB
    setsockopt(fd[fdc].fd, SOL_SOCKET, SO_REUSEPORT_LB, &one, sizeof one);
#elif defined SO_REUSEPORT
    setsockopt(fd[fdc].fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif

#if defined IP_FREEBIND && defined IPV6_FREEBIND
    if (info->ai_family == AF_INET)
      setsockopt(fd[fdc].fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof one);
    if (info->ai_family == AF_INET6)
      setsockopt(fd[fdc].fd, IPPROTO_IPV6, IPV6_FREEBIND, &one, sizeof one);
#elif defined IP_BINDANY && defined IPV6_BINDANY
    if (info->ai_family == AF_INET)
      setsockopt(fd[fdc].fd, IPPROTO_IP, IP_BINDANY, &one, sizeof one);
    if (info->ai_family == AF_INET6)
      setsockopt(fd[fdc].fd, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof one);
#elif defined SO_BINDANY
    setsockopt(fd[fdc].fd, SOL_SOCKET, SO_BINDANY, &one, sizeof one);
#endif

    if (bind(fd[fdc].fd, info->ai_addr, info->ai_addrlen) < 0)
      err(1, "bind");
    fd[fdc].events = POLLIN;
  }
  freeaddrinfo(list);
}

void serve() {
  while (1) {
    if (poll(fd, fdc, -1) < 0) {
      if (errno == EINTR)
        continue;
      err(1, "poll");
    }

    for (size_t i = 0; i < fdc; i++)
      if (fd[i].revents) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof sa;
        ssize_t count;

        count = recvfrom(fd[i].fd, r.s, 512, 0, (void *) &sa, &salen);
        if (count < 0)
          continue;
        r.len = count;

        if (sa.ss_family == AF_INET)
          lookup(&r, 512, &((struct sockaddr_in *) &sa)->sin_addr, 4);
        else if (sa.ss_family == AF_INET6)
          lookup(&r, 512, &((struct sockaddr_in6 *) &sa)->sin6_addr, 16);
        else
          continue;

        if (r.len > 0)
          sendto(fd[i].fd, r.s, r.len, 0, (void *) &sa, salen);
      }
  }
}
