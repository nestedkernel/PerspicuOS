all: panic panic2

install: all
	cp panic panic2 /sbin/

panic: panic.c
	gcc -static -o panic panic.c

panic2: panic2.c
	gcc -static -o panic2 panic2.c

clean:
	rm panic panic2

