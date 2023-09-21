CC=gcc
CFLAGS=-g -Wall -Wextra

pinger: pinger.c
	${CC} ${CFLAGS} $< -o pinger