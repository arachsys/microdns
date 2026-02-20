#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "stralloc.h"

static struct pollfd fd[16];
static size_t fdc;

static char buffer[65535];
static stralloc r = {
  .s = buffer,
  .size = sizeof buffer,
  .limit = -1
};

size_t attach(struct pollfd *fd, size_t fdlen, int type,
    const char *address, const char *port);
void lookup(stralloc *r, size_t max, const void *ip, size_t iplen);
void prepare(int fg, const char *user);

static int usage(const char *progname) {
  fprintf(stderr, "\
Usage: %s [OPTIONS] ADDRESS...\n\
Options:\n\
  -d DIR        change directory to DIR before opening data.cdb\n\
  -f            run in the foreground instead of daemonizing\n\
  -u UID:GID    run with the specified numeric uid and gid\n\
  -u USERNAME   run with the uid and gid of user USERNAME\n\
", progname);
  return 64;
}

int main(int argc, char **argv) {
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

  if (argc <= optind)
    return usage(argv[0]);
  for (int i = optind; i < argc; i++)
    fdc = fdc + attach(fd + fdc, sizeof fd / sizeof *fd - fdc,
      SOCK_DGRAM, argv[i], "53");

  prepare(fg, user);

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
