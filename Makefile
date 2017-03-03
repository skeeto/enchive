.POSIX:
.SUFFIXES:
CC     = cc
CFLAGS = -ansi -pedantic -Wall -Wextra -O3 -g3

objects = enchive.o chacha.o curve25519-donna.o

enchive: $(objects)
	$(CC) $(LDFLAGS) -o $@ $(objects) $(LDLIBS)
enchive.o: enchive.c
chacha.o: chacha.c
curve25519-donna.o: curve25519-donna.c

clean:
	rm -f enchive $(objects)

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
