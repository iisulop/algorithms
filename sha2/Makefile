CC=gcc
CFLAGS=-Wall -O2 -c -DNDEBUG
LD=gcc

.PHONY: clean

s256: sha-cli.o sha2.o
	$(LD) $(LDFLAGS) -o $@ $^

sha-cli.o: sha-cli.c sha2.h
	$(CC) $(CFLAGS) -o $@ sha-cli.c

sha2.o: sha2.c
	$(CC) $(CFLAGS) -o $@ sha2.c

clean:
	@rm *.o s256
