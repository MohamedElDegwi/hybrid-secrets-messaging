CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2

all: ircd

ircd: server/main.c
	$(CC) $(CFLAGS) -o server/ircd server/main.c

clean:
	rm -f server/ircd