CC=gcc
CFLAGS=-DLINUX=1 -O3 -Wall -I/usr/include
LDFLAGS=-L/usr/lib
LIBS=-lncurses

CFILES=ui.c gpl.c main.c 
HFILES=ui.h gpl.h data.h
OFILES=ui.o gpl.o main.o
all:	dhex

dhex:		$(OFILES) $(HFILES)
		$(CC) $(LDFLAGS) -o$@ $(OFILES) $(LIBS)

.c.o:
		$(CC) $< -c -I. $(CFLAGS) $(OPTIONS)

clean:
		rm -f dhex $(OFILES)
