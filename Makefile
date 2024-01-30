CFLAGS := -ffunction-sections -O2 -Wall -Wno-unused-label
LDFLAGS := -Wl,--gc-sections

%:: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -I . -o $@ $(filter %.c,$^)

all: dnsdata tcpdns udpdns

clean:
	rm -f dnsdata tcpdns udpdns

tcpdns: cdb/cdb.[ch] dns.[ch] lookup.c pack.h response.[ch] scan.[ch] \
  server.c stralloc.h

udpdns: cdb/cdb.[ch] dns.[ch] lookup.c pack.h response.[ch] scan.[ch] \
  server.c stralloc.h

dnsdata: cdb/cdb.h cdb/make.[ch] dns.[ch] pack.h scan.[ch] stralloc.h

.PHONY: all clean
