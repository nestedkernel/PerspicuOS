#
# Makefile
#

CFLAGS := -I../include

libsva.a: mmu_checks.o
	$(AR) -r $@ mmu_checks.o

%.o: %.c
	$(CC) $(CFLAGS) -O2 -c -o $@ $< $(LDFLAGS)

clean:
	rm -f *.a *.o

