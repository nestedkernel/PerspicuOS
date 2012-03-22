#
# Makefile
#

libsva.a: mmu_checks.o
	$(AR) -r $@ $<

%.o: %.c
	$(CC) -c -o $@ $<

clean:
	rm *.a *.o

