#
# Makefile for RUDP application
#
# October 2012
#

CC = gcc

LIBS = -lresolv -lnsl -lpthread -lm \
	   /home/dileep/NP/Assign-2/latest/unpv13e_solaris2.10/libunp.a \
	
FLAGS = -g -O0

CFLAGS = ${FLAGS} -I/home/dileep/NP/Assign-2/latest/unpv13e_solaris2.10/lib

all: server client

server: server.c rudp.c
	${CC} ${FLAGS} -o server server.c rudp.c ${LIBS}
server.o: server.c rudp.c
	${CC} ${CFLAGS} -c server.c rudp.c

client: client.c rudp.c
	${CC} ${FLAGS} -o client client.c rudp.c ${LIBS}
client.o: client.c rudp.c
	${CC} ${CFLAGS} -c client.c rudp.c

clean:
	rm server client

# End of File
