CC=gcc
CFLAGS=-I -Wall -O2
OBJ=lsniff.o
LIBS=-lpcap
DEPS=lsniff.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

lsniff: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o *~ lsniff


