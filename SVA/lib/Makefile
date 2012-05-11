#
# Makefile
#

CFLAGS := -I../include
OFILES = secmem.o

libsva.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

%.o: %.c
	$(CC) $(CFLAGS) -O2 -c -o $@ $< $(LDFLAGS)

clean:
	rm -f *.a *.o

