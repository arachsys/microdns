#include <err.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "scan.h"
#include "stralloc.h"

void attach(const char *address, const char *port);
void serve(void);

static void droproot(const char *user) {
  uint32_t uid = -1, gid = -1;

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
}

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
  int fd, foreground = 0, option;
  char *user = 0;

  while ((option = getopt(argc, argv, ":d:fu:")) > 0)
    switch (option) {
      case 'd':
        if (chdir(optarg) < 0)
          err(1, "chdir");
        break;
      case 'f':
        foreground = 1;
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
    attach(argv[i], "53");

  if (!foreground)
    if ((fd = open("/dev/null", O_RDWR)) < 0)
      err(1, "open /dev/null");
  droproot(user);

  if (!foreground) {
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

  serve();
  return 0;
}
