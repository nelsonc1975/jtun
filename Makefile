all: jtun

CC=gcc
CFLAGS=-Wall
LDFLAGS=-lcrypto

DEPS=$(wildcard *.h)

#SRC=$(wildcard *.c)
SRC=tunnel.c

OBJ=$(patsubst %.c, %.o, $(SRC))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

jtun: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f jtun *.o
