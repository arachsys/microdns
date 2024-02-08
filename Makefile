BINDIR := $(PREFIX)/bin
BINARIES := dnsdata tcpdns udpdns

CFLAGS := -ffunction-sections -O2 -Wall -Wno-unused-label
LDFLAGS := -Wl,--gc-sections

%:: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -I . -o $@ $(filter %.c,$^)

all: $(BINARIES)

dnsdata: cdb/cdb.h cdb/make.[ch] dns.[ch] pack.h scan.[ch] stralloc.h

tcpdns: cdb/cdb.[ch] dns.[ch] lookup.c pack.h response.[ch] scan.[ch] \
  server.c stralloc.h

udpdns: cdb/cdb.[ch] dns.[ch] lookup.c pack.h response.[ch] scan.[ch] \
  server.c stralloc.h

install: $(BINARIES)
	mkdir -p $(DESTDIR)$(BINDIR)
	install -s $(BINARIES) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(BINARIES)

.PHONY: all clean install
