#include <err.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "scan.h"

size_t attach(struct pollfd *fd, size_t fdlen, int type,
    const char *address, const char *port) {
  struct addrinfo hints = { .ai_socktype = type }, *info, *list;
  int one = 1, status = getaddrinfo(address, port, &hints, &list);
  size_t i = 0;

  if (status != 0 || list == 0)
    errx(1, "getaddrinfo %s: %s", address, gai_strerror(status));

  for (info = list; info; info = info->ai_next, i++) {
    if (i >= fdlen)
      errx(1, "Too many listening addresses");

    fd[i].fd = socket(info->ai_family, info->ai_socktype, 0);
    if (fd[i].fd < 0)
      err(1, "socket");
    if (fcntl(fd[i].fd, F_SETFL, O_NONBLOCK) < 0)
      err(1, "fcntl F_SETFL O_NONBLOCK");

    setsockopt(fd[i].fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#if defined SO_REUSEPORT_LB
    setsockopt(fd[i].fd, SOL_SOCKET, SO_REUSEPORT_LB, &one, sizeof one);
#elif defined SO_REUSEPORT
    setsockopt(fd[i].fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif

#if defined IP_FREEBIND && defined IPV6_FREEBIND
    if (info->ai_family == AF_INET)
      setsockopt(fd[i].fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof one);
    if (info->ai_family == AF_INET6)
      setsockopt(fd[i].fd, IPPROTO_IPV6, IPV6_FREEBIND, &one, sizeof one);
#elif defined IP_BINDANY && defined IPV6_BINDANY
    if (info->ai_family == AF_INET)
      setsockopt(fd[i].fd, IPPROTO_IP, IP_BINDANY, &one, sizeof one);
    if (info->ai_family == AF_INET6)
      setsockopt(fd[i].fd, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof one);
#elif defined SO_BINDANY
    setsockopt(fd[i].fd, SOL_SOCKET, SO_BINDANY, &one, sizeof one);
#endif

    if (bind(fd[i].fd, info->ai_addr, info->ai_addrlen) < 0)
      err(1, "bind");
    if (type == SOCK_STREAM && listen(fd[i].fd, SOMAXCONN) < 0)
      err(1, "listen");
    fd[i].events = POLLIN;
  }

  freeaddrinfo(list);
  return i;
}

void prepare(int fg, const char *user) {
  uint32_t uid = -1, gid = -1;
  int fd = -1;

  if (!fg)
    if ((fd = open("/dev/null", O_RDWR)) < 0)
      err(1, "open /dev/null");

  if (user) {
    if (strchr(user, ':')) {
      size_t n = scan_uint32(user, &uid);
      if (n == 0 || user[n] != ':' || user[n + 1] == 0)
        errx(1, "Invalid username: %s", user);
      n += 1 + scan_uint32(user + n + 1, &gid);
      if (user[n] != 0)
        errx(1, "Invalid username: %s", user);
    } else {
      struct passwd *pw = getpwnam(user);
      if (!pw)
        errx(1, "Invalid username: %s", user);
      uid = pw->pw_uid;
      gid = pw->pw_gid;
    }
  }

  if (getuid() == 0 && chroot(".") < 0)
    err(1, "chroot");

  if (uid + 1 && gid + 1) {
    if (setgroups(0, 0) < 0)
      err(1, "setgroups");
    if (setgid(gid) < 0)
      err(1, "setgid");
    if (setuid(uid) < 0)
      err(1, "setuid");
  }

  if (!fg) {
    switch (fork()) {
      case -1:
        err(1, "fork");
      case 0:
        if (dup2(fd, 0) < 0)
          err(1, "dup2");
        if (dup2(fd, 1) < 0)
          err(1, "dup2");
        if (dup2(fd, 2) < 0)
          err(1, "dup2");
        if (fd > 2)
          close(fd);
        setsid();
        break;
      default:
        exit(0);
    }
  }
}
