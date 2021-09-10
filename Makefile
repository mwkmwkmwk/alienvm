all: avm

avm: avm.c alienvm.h
	gcc -O3 -Wall -pthread avm.c -o avm
