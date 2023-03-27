all: jtun

CC := gcc
CFLAGS := $(TARGET_CFLAGS) -Wall
LDFLAGS += $(TARGET_LDFLAGS) -lcrypto

DEPS = $(wildcard *.h)

SRC = $(wildcard *.c)

OBJ = $(patsubst %.c, %.o, $(SRC))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

jtun: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f jtun *.o
