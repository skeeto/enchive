.POSIX:
.SUFFIXES:
CC     = cc
CFLAGS = -ansi -pedantic -Wall -Wextra -O3 -g3
PREFIX = /usr/local

sources = src/enchive.c src/chacha.c src/curve25519-donna.c src/sha256.c
objects = $(sources:.c=.o)
headers = config.h src/docs.h src/chacha.h src/sha256.h src/optparse.h

enchive: $(objects)
	$(CC) $(LDFLAGS) -o $@ $(objects) $(LDLIBS)
src/enchive.o: src/enchive.c config.h src/docs.h
src/chacha.o: src/chacha.c config.h
src/curve25519-donna.o: src/curve25519-donna.c config.h
src/sha256.o: src/sha256.c config.h

enchive-cli.c: $(sources) $(headers)
	cat $(headers) $(sources) | sed -r 's@^(#include +".+)@/* \1 */@g' > $@

amalgamation: enchive-cli.c

clean:
	rm -f enchive $(objects) enchive-cli.c

install: enchive enchive.1
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	cp -f enchive $(DESTDIR)$(PREFIX)/bin
	gzip < enchive.1 > $(DESTDIR)$(PREFIX)/share/man/man1/enchive.1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/enchive
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/enchive.1.gz

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
