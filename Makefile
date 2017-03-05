.POSIX:
.SUFFIXES:
CC     = cc
CFLAGS = -ansi -pedantic -Wall -Wextra -O3 -g3

sources = enchive.c chacha.c curve25519-donna.c sha256.c
objects = $(sources:.c=.o)
headers = config.h docs.h chacha.h sha256.h optparse.h

enchive: $(objects)
	$(CC) $(LDFLAGS) -o $@ $(objects) $(LDLIBS)
enchive.o: enchive.c docs.h
chacha.o: chacha.c
curve25519-donna.o: curve25519-donna.c
sha256.o: sha256.c

enchive-cli.c: $(sources) $(headers)
	cat $(headers) $(sources) | sed -r 's/^#include +".+//g' > $@

amalgamation: enchive-cli.c

clean:
	rm -f enchive $(objects) enchive-cli.c

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
