#
# Makefile
#

CFLAGS := -I../include

libsva.a: mmu_checks.o
	$(AR) -r $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< $(LDFLAGS)

clean:
	rm -f *.a *.o

