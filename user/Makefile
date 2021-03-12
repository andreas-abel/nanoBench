CC=gcc 
CFLAGS=-Wall -fPIC
VPATH=../common/

all: nanoBench
nanoBench: nanoBench_main.o nanoBench.o
nanoBench_main.o: nanoBench_main.c ../common/nanoBench.h	
nanoBench.o: ../common/nanoBench.c ../common/nanoBench.h

clean:
	rm -f nanoBench *.o ../common/*.o
