.POSIX:
.SUFFIXES:
CC     = cc
CFLAGS = -ansi -pedantic -Wall -Wextra -O3 -g3

objects =  enchive.o chacha.o

enchive: $(objects)
	$(CC) $(LDFLAGS) -o $@ $(objects) $(LDLIBS)
enchive.o: enchive.c
chacha.o: chacha.c

clean:
	rm -f enchive $(objects)

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
