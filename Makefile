.POSIX:
.SUFFIXES:
CC     = cc
CFLAGS = -ansi -pedantic -Wall -Wextra -Wno-overlength-strings -O3 -g3

objects = enchive.o chacha.o curve25519-donna.o sha256.o

enchive: $(objects)
	$(CC) $(LDFLAGS) -o $@ $(objects) $(LDLIBS)
enchive.o: enchive.c docs.h
chacha.o: chacha.c
curve25519-donna.o: curve25519-donna.c
sha256.o: sha256.c

clean:
	rm -f enchive $(objects)

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
